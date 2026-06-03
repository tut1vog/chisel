package chserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	chshare "github.com/jpillora/chisel/share"
	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/settings"
	"github.com/jpillora/chisel/share/tunnel"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"
)

// handleClientHandler is the main http websocket handler for the chisel server
func (s *Server) handleClientHandler(w http.ResponseWriter, r *http.Request) {
	//websockets upgrade AND has chisel prefix
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	protocol := r.Header.Get("Sec-WebSocket-Protocol")
	if protocol == "" {
		protocol = r.Header.Get("X-Chisel-Client-Version")
	}
	if upgrade == "websocket" {
		if protocol == chshare.ProtocolVersion {
			s.handleWebsocket(w, r)
			return
		}
		//print into server logs and silently fall-through
		s.Infof("ignored client connection using protocol '%s', expected '%s'",
			protocol, chshare.ProtocolVersion)
	}
	//sse transport (handled before the reverse proxy so it also works with --backend)
	if r.URL.Path == "/sse" {
		switch r.Method {
		case http.MethodPost:
			//data frame upload; the session was already validated at handshake
			s.handleSSEPost(w, r)
		case http.MethodGet:
			if protocol != chshare.ProtocolVersion {
				s.Infof("ignored client connection using protocol '%s', expected '%s'",
					protocol, chshare.ProtocolVersion)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			s.handleSSEGet(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	//proxy target was provided
	if s.reverseProxy != nil {
		s.reverseProxy.ServeHTTP(w, r)
		return
	}
	//no proxy defined, provide access to health/version checks
	switch r.URL.Path {
	case "/health":
		w.Write([]byte("OK\n"))
		return
	case "/version":
		w.Write([]byte(chshare.BuildVersion))
		return
	}
	//missing :O
	w.WriteHeader(404)
	w.Write([]byte("Not found"))
}

// handleWebsocket is responsible for handling the websocket connection
func (s *Server) handleWebsocket(w http.ResponseWriter, req *http.Request) {
	id := atomic.AddInt32(&s.sessCount, 1)
	l := s.Fork("session#%d", id)
	wsConn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		l.Debugf("Failed to upgrade (%s)", err)
		return
	}
	conn := cnet.NewWebSocketConn(wsConn)
	// perform SSH handshake on net.Conn
	l.Debugf("Handshaking with %s...", req.RemoteAddr)
	s.buildSSHTunnel(conn, req.Context(), l)
}

// handleSSEGet is responsible for handling the sse handshake and the long-lived
// server->client stream.
func (s *Server) handleSSEGet(w http.ResponseWriter, req *http.Request) {
	id := atomic.AddInt32(&s.sessCount, 1)
	l := s.Fork("session#%d", id)
	// Generate a secure random ID
	key, err := generateSessionID()
	if err != nil {
		s.Debugf("Failed to generate session Key: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	pr, pw := io.Pipe()
	s.sseSessions.Store(key, pw)
	defer s.sseSessions.Delete(key)
	// SSE/streaming response headers so intermediary proxies/CDNs don't buffer
	// or transform the downstream channel.
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	h.Set("X-Chisel-Session-Id", key)
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	conn := cnet.NewServerSSEConn(w, pr)
	// Always unblock the SSH read side: close the conn (pipe reader) and the
	// pipe writer when this handler returns, even on a handshake failure.
	defer conn.Close()
	defer pw.Close()
	// Tie cleanup to client disconnect. Without this, a silently-vanished client
	// leaves the SSH read loop blocked on the pipe, leaking the goroutine, pipe
	// and session until (and unless) a keepalive write happens to fail.
	go func() {
		<-req.Context().Done()
		pw.Close()
		conn.Close()
	}()
	// perform SSH handshake on net.Conn
	l.Debugf("Handshaking with %s...", req.RemoteAddr)
	s.buildSSHTunnel(conn, req.Context(), l)
}

func (s *Server) handleSSEPost(w http.ResponseWriter, req *http.Request) {
	bodyBytes, err := io.ReadAll(req.Body)
	if err != nil {
		s.Debugf("Read client data failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer req.Body.Close()
	sseSid := req.Header.Get("X-Chisel-Session-Id")
	val, ok := s.sseSessions.Load(sseSid)
	if !ok {
		s.Debugf("sseSid not found, client should reconnect")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	pw, ok := val.(*io.PipeWriter)
	if !ok {
		s.Debugf("Unexpected error, type conversion failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err = pw.Write(bodyBytes)
	if err != nil {
		s.Debugf("Failed to write client data: %s", err.Error())
		//the session's read side is gone; tell the client to reconnect
		w.WriteHeader(http.StatusGone)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) buildSSHTunnel(conn net.Conn, reqCtx context.Context, l *cio.Logger) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.Debugf("Failed to handshake (%s)", err)
		return
	}
	// pull the users from the session map
	var user *settings.User
	if s.users.Len() > 0 {
		sid := string(sshConn.SessionID())
		u, ok := s.sessions.Get(sid)
		if !ok {
			panic("bug in ssh auth handler")
		}
		user = u
		s.sessions.Del(sid)
	}
	// chisel server handshake (reverse of client handshake)
	// verify configuration
	l.Debugf("Verifying configuration")
	// wait for request, with timeout
	var r *ssh.Request
	select {
	case r = <-reqs:
	case <-time.After(settings.EnvDuration("CONFIG_TIMEOUT", 10*time.Second)):
		l.Debugf("Timeout waiting for configuration")
		sshConn.Close()
		return
	}
	failed := func(err error) {
		l.Debugf("Failed: %s", err)
		r.Reply(false, []byte(err.Error()))
	}
	if r.Type != "config" {
		failed(s.Errorf("expecting config request"))
		return
	}
	c, err := settings.DecodeConfig(r.Payload)
	if err != nil {
		failed(s.Errorf("invalid config"))
		return
	}
	//print if client and server  versions dont match
	cv := strings.TrimPrefix(c.Version, "v")
	if cv == "" {
		cv = "<unknown>"
	}
	sv := strings.TrimPrefix(chshare.BuildVersion, "v")
	if cv != sv {
		l.Infof("Client version (%s) differs from server version (%s)", cv, sv)
	}
	//validate remotes
	for _, r := range c.Remotes {
		//if user is provided, ensure they have
		//access to the desired remotes
		if user != nil {
			addr := r.UserAddr()
			if !user.HasAccess(addr) {
				failed(s.Errorf("access to '%s' denied", addr))
				return
			}
		}
		//confirm reverse tunnels are allowed
		if r.Reverse && !s.config.Reverse {
			l.Debugf("Denied reverse port forwarding request, please enable --reverse")
			failed(s.Errorf("Reverse port forwaring not enabled on server"))
			return
		}
		//confirm reverse tunnel is available
		if r.Reverse && !r.CanListen() {
			failed(s.Errorf("Server cannot listen on %s", r.String()))
			return
		}
	}
	//successfuly validated config!
	r.Reply(true, nil)
	//tunnel per ssh connection
	tunnelConfig := tunnel.Config{
		Logger:    l,
		Inbound:   s.config.Reverse,
		Outbound:  true, //server always accepts outbound
		Socks:     s.config.Socks5,
		KeepAlive: s.config.KeepAlive,
	}
	//enforce ACL on every channel, not just the initial config
	if user != nil {
		tunnelConfig.ACL = user.HasAccess
	}
	tunnel := tunnel.New(tunnelConfig)
	//bind
	eg, ctx := errgroup.WithContext(reqCtx)
	eg.Go(func() error {
		//connected, handover ssh connection for tunnel to use, and block
		return tunnel.BindSSH(ctx, sshConn, reqs, chans)
	})
	eg.Go(func() error {
		//connected, setup reversed-remotes?
		serverInbound := c.Remotes.Reversed(true)
		if len(serverInbound) == 0 {
			return nil
		}
		//block
		return tunnel.BindRemotes(ctx, serverInbound)
	})
	err = eg.Wait()
	if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
		l.Debugf("Closed connection (%s)", err)
	} else {
		l.Debugf("Closed connection")
	}
}

func generateSessionID() (string, error) {
	b := make([]byte, 16) // 16 bytes = 128 bits of entropy
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
