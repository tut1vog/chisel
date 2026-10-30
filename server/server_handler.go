package chserver

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// ssePath is the sse endpoint: --path itself, or /sse when --path is unset
func (s *Server) ssePath() string {
	if s.config.Path != "" {
		return s.config.Path
	}
	return "/sse"
}

// handleClientHandler is the main http websocket handler for the chisel server
func (s *Server) handleClientHandler(w http.ResponseWriter, r *http.Request) {
	//tunnel requests carry no chisel-specific headers; they are recognised
	//by path alone (any path for websockets when --path is unset)
	upgrade := strings.ToLower(r.Header.Get("Upgrade"))
	if upgrade == "websocket" && (s.config.Path == "" || r.URL.Path == s.config.Path) {
		s.handleWebsocket(w, r)
		return
	}
	//sse transport (handled before the reverse proxy so it also works with
	//--backend); other methods on the endpoint fall through like any request
	if r.URL.Path == s.ssePath() && r.Method == http.MethodPost {
		s.handleSSE(w, r)
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
	s.buildSSHTunnel(conn, req, l)
}

// handleSSE reads a client POST and either opens a stream or delivers an
// upload to an open one, depending on its body.
func (s *Server) handleSSE(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	//a session is handed out before SSH authentication, so cap each
	//body like the websocket read limit does (pre-auth memory DoS)
	body := io.Reader(req.Body)
	if limit := cnet.ConfiguredReadLimit(); limit > 0 {
		body = http.MaxBytesReader(w, req.Body, limit)
	}
	var msg cnet.SSERequest
	if err := json.NewDecoder(body).Decode(&msg); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.Debugf("SSE request exceeds read limit (%d bytes)", maxErr.Limit)
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch {
	case msg.ID != "":
		s.handleSSEUpload(w, msg)
	case msg.Stream:
		s.handleSSEStream(w, req)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

// handleSSEStream is responsible for the sse handshake and the long-lived
// server->client stream.
func (s *Server) handleSSEStream(w http.ResponseWriter, req *http.Request) {
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
	w.WriteHeader(http.StatusOK)
	//the session id is the stream's first event
	if err := cnet.WriteSSESessionID(w, key); err != nil {
		pw.Close()
		return
	}
	conn := cnet.NewServerSSEConn(w, pr, cnet.NewPacer(s.sseRate))
	// Always unblock the SSH read side: close the conn (pipe reader) and the
	// pipe writer when this handler returns, even on a handshake failure.
	defer conn.Close()
	defer pw.Close()
	// Tie cleanup to client disconnect. Without this, a silently-vanished client
	// leaves the SSH read loop blocked on the pipe, leaking the goroutine, pipe
	// and session until (and unless) a keepalive write happens to fail.
	go func() {
		select {
		case <-req.Context().Done():
		case <-s.sseShutdown:
		}
		pw.Close()
		conn.Close()
	}()
	// perform SSH handshake on net.Conn
	l.Debugf("Handshaking with %s...", req.RemoteAddr)
	s.buildSSHTunnel(conn, req, l)
}

// handleSSEUpload delivers an upload's content to its session's stream
func (s *Server) handleSSEUpload(w http.ResponseWriter, msg cnet.SSERequest) {
	val, ok := s.sseSessions.Load(msg.ID)
	if !ok {
		s.Debugf("sse session not found, client should reconnect")
		w.WriteHeader(http.StatusNotFound)
		return
	}
	pw, ok := val.(*io.PipeWriter)
	if !ok {
		s.Debugf("Unexpected error, type conversion failed")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if _, err := pw.Write(msg.Content); err != nil {
		s.Debugf("Failed to write client data: %s", err.Error())
		//the session's read side is gone; tell the client to reconnect
		w.WriteHeader(http.StatusGone)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(cnet.SSEUploadOK))
}

func (s *Server) buildSSHTunnel(conn net.Conn, req *http.Request, l *cio.Logger) {
	if s.obfsKey != nil {
		conn = cnet.NewObfsConn(conn, s.obfsKey, false)
	}
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshConfig)
	if err != nil {
		s.logHandshakeFailure(err)
		return
	}
	// resolve the user from the authenticated username set by
	// authUser (nil permissions means auth is disabled: allow-all)
	var user *settings.User
	if sshConn.Permissions != nil {
		n := sshConn.Permissions.Extensions["user"]
		u, found := s.users.Get(n)
		if !found {
			//user was removed by an authfile reload mid-handshake
			l.Infof("User %s no longer exists", n)
			sshConn.Close()
			return
		}
		user = u
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
	if r == nil {
		//connection closed before the config request arrived; the
		//closed request channel yields nil
		l.Debugf("Connection closed before configuration")
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
	//print if client and server versions dont match,
	//skipping dev/unknown builds where the mismatch is meaningless
	cv := strings.TrimPrefix(c.Version, "v")
	sv := strings.TrimPrefix(chshare.BuildVersion, "v")
	devVersion := func(v string) bool {
		return v == "" || strings.HasPrefix(v, "0.0.0")
	}
	if cv != sv && !devVersion(cv) && !devVersion(sv) {
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
			failed(s.Errorf("Reverse port forwarding not enabled on server"))
			return
		}
		//confirm reverse tunnel is available
		if r.Reverse && !r.CanListen() {
			failed(s.Errorf("Server cannot listen on %s", r.String()))
			return
		}
	}
	//successfully validated config!
	r.Reply(true, nil)
	//log session opens at info level so operators can see connected
	//clients, their IPs and declared remotes without debug mode
	username := "-"
	if user != nil {
		username = user.Name
	}
	opened := time.Now()
	l.Infof("Open (user=%s addr=%s remotes=%s)",
		username, req.RemoteAddr, strings.Join(c.Remotes.Encode(), ","))
	//tunnel per ssh connection
	tunnelConfig := tunnel.Config{
		Logger:    l,
		Inbound:   s.config.Reverse,
		Outbound:  true, //server always accepts outbound
		Socks:     s.config.Socks5,
		KeepAlive: s.config.KeepAlive,
	}
	//enforce ACL on every channel, not just the initial config.
	//the user is re-resolved from the live index per channel, so
	//authfile reloads apply to connected clients' new tunnels
	if user != nil {
		name := user.Name
		tunnelConfig.ACL = func(addr string) bool {
			u, found := s.users.Get(name)
			return found && u.HasAccess(addr)
		}
	}
	tunnel := tunnel.New(tunnelConfig)
	//bind
	eg, ctx := errgroup.WithContext(req.Context())
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
	errmsg := ""
	if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
		errmsg = fmt.Sprintf(" (error %s)", err)
	}
	l.Infof("Close (user=%s addr=%s duration=%s)%s",
		username, req.RemoteAddr, time.Since(opened), errmsg)
}

func (s *Server) logHandshakeFailure(err error) {
	s.Debugf("Failed to handshake (%q)", err.Error())
}

func generateSessionID() (string, error) {
	b := make([]byte, 16) // 16 bytes = 128 bits of entropy
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
