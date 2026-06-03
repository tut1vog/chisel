package chclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jpillora/backoff"
	chshare "github.com/jpillora/chisel/share"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/cos"
	"github.com/jpillora/chisel/share/settings"
	"golang.org/x/crypto/ssh"
)

func (c *Client) connectionLoop(ctx context.Context) error {
	//connection loop!
	b := &backoff.Backoff{Max: c.config.MaxRetryInterval}
	for {
		connected, err := c.connectionOnce(ctx)
		//reset backoff after successful connections
		if connected {
			b.Reset()
		}
		//connection error
		attempt := int(b.Attempt())
		maxAttempt := c.config.MaxRetryCount
		//dont print closed-connection errors
		if err != nil && strings.HasSuffix(err.Error(), "use of closed network connection") {
			err = io.EOF
		}
		//show error message and attempt counts (excluding disconnects)
		if err != nil && err != io.EOF {
			msg := fmt.Sprintf("Connection error: %s", err)
			if attempt > 0 {
				maxAttemptVal := fmt.Sprint(maxAttempt)
				if maxAttempt < 0 {
					maxAttemptVal = "unlimited"
				}
				msg += fmt.Sprintf(" (Attempt: %d/%s)", attempt, maxAttemptVal)
			}
			c.Infof(msg)
		}
		//give up?
		if maxAttempt >= 0 && attempt >= maxAttempt {
			c.Infof("Give up")
			break
		}
		d := b.Duration()
		c.Infof("Retrying in %s...", d)
		select {
		case <-cos.AfterSignal(d):
			continue //retry now
		case <-ctx.Done():
			c.Infof("Cancelled")
			return nil
		}
	}
	c.Close()
	return nil
}

// connectionOnce connects to the chisel server and blocks
func (c *Client) connectionOnce(ctx context.Context) (connected bool, err error) {
	//already closed?
	select {
	case <-ctx.Done():
		return false, errors.New("Cancelled")
	default:
		//still open
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var conn net.Conn
	switch c.config.Mode {
	case "websocket":
		//prepare dialer
		d := websocket.Dialer{
			HandshakeTimeout: settings.EnvDuration("WS_TIMEOUT", 45*time.Second),
			Subprotocols:     []string{chshare.ProtocolVersion},
			TLSClientConfig:  c.tlsConfig,
			ReadBufferSize:   settings.EnvInt("WS_BUFF_SIZE", 0),
			WriteBufferSize:  settings.EnvInt("WS_BUFF_SIZE", 0),
			NetDialContext:   c.config.DialContext,
		}
		//optional proxy
		if p := c.proxyURL; p != nil {
			if err := c.setProxy(p, &d); err != nil {
				return false, err
			}
		}
		wsConn, _, err := d.DialContext(ctx, c.server, c.config.Headers)
		if err != nil {
			return false, err
		}
		conn = cnet.NewWebSocketConn(wsConn)
	case "sse":
		// Derive the SSE URL from the (ws/wss) server URL, preserving any base
		// path or trailing slash instead of naive string concatenation.
		u, err := url.Parse(c.server)
		if err != nil {
			return false, err
		}
		switch u.Scheme {
		case "ws":
			u.Scheme = "http"
		case "wss":
			u.Scheme = "https"
		}
		u.Path = path.Join("/", u.Path, "sse")
		sseURL := u.String()
		// Build one HTTP client that honors TLS, proxy and dialer config; it is
		// shared by the handshake GET and every subsequent data POST.
		transport := &http.Transport{
			TLSClientConfig: c.tlsConfig,
			DialContext:     c.config.DialContext,
		}
		if c.proxyURL != nil {
			transport.Proxy = http.ProxyURL(c.proxyURL)
		}
		httpClient := &http.Client{Transport: transport}
		// The streaming GET lives for the whole session; give it a cancelable
		// context so Close (via the SSH conn) can abort the in-flight request.
		sseCtx, sseCancel := context.WithCancel(ctx)
		req, err := http.NewRequestWithContext(sseCtx, "GET", sseURL, nil)
		if err != nil {
			sseCancel()
			return false, err
		}
		applySSEHeaders(req, c.config.Headers)
		req.Header.Set("X-Chisel-Client-Version", chshare.ProtocolVersion)
		req.Header.Set("Accept", "text/event-stream")
		resp, err := httpClient.Do(req)
		if err != nil {
			sseCancel()
			return false, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			sseCancel()
			return false, fmt.Errorf("sse handshake failed: status %d", resp.StatusCode)
		}
		sseSid := resp.Header.Get("X-Chisel-Session-Id")
		if sseSid == "" {
			resp.Body.Close()
			sseCancel()
			return false, fmt.Errorf("sse handshake failed: missing session id")
		}
		conn = cnet.NewClientSSEConn(sseCtx, sseCancel, resp, httpClient, c.config.Headers, sseURL, sseSid)
	default:
		return false, fmt.Errorf("unknown transport mode: %q", c.config.Mode)
	}

	// perform SSH handshake on net.Conn
	c.Debugf("Handshaking...")
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "", c.sshConfig)
	if err != nil {
		e := err.Error()
		if strings.Contains(e, "unable to authenticate") {
			c.Infof("Authentication failed")
			c.Debugf(e)
		} else {
			c.Infof(e)
		}
		return false, err
	}
	defer sshConn.Close()
	// chisel client handshake (reverse of server handshake)
	// send configuration
	c.Debugf("Sending config")
	t0 := time.Now()
	_, configerr, err := sshConn.SendRequest(
		"config",
		true,
		settings.EncodeConfig(c.computed),
	)
	if err != nil {
		c.Infof("Config verification failed")
		return false, err
	}
	if len(configerr) > 0 {
		return false, errors.New(string(configerr))
	}
	c.Infof("Connected (Latency %s)", time.Since(t0))
	//connected, handover ssh connection for tunnel to use, and block
	err = c.tunnel.BindSSH(ctx, sshConn, reqs, chans)
	c.Infof("Disconnected")
	connected = time.Since(t0) > 5*time.Second
	return connected, err
}

// applySSEHeaders replays the client-configured headers onto the handshake GET,
// translating Host into the request's Host field (net/http ignores a "Host"
// header key otherwise).
func applySSEHeaders(req *http.Request, headers http.Header) {
	for k, vs := range headers {
		if strings.EqualFold(k, "Host") {
			if len(vs) > 0 {
				req.Host = vs[0]
			}
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
}
