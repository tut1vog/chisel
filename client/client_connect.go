package chclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jpillora/backoff"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/cos"
	"github.com/jpillora/chisel/share/settings"
	"golang.org/x/crypto/ssh"
)

func (c *Client) connectionLoop(ctx context.Context) error {
	//connection loop!
	b := &backoff.Backoff{
		Min: c.config.MinRetryInterval,
		Max: c.config.MaxRetryInterval,
	}
	for {
		connected, err := c.connectionOnce(ctx)
		// Cancellation is a normal shutdown, even when the final connection
		// attempt also consumes the configured retry budget.
		if ctx.Err() != nil {
			c.Infof("Cancelled")
			return nil
		}
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
			c.Infof("%s", msg)
		}
		//give up?
		if maxAttempt >= 0 && attempt >= maxAttempt {
			c.Infof("Give up")
			c.Close()
			//unlike a ctx-cancelled shutdown, exhausting the
			//connection attempts is an error (non-zero exit)
			return errors.New("connection attempts exhausted")
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
}

// sseURL is the SSE endpoint: the server URL back on its http(s) scheme,
// with its path, or /sse without one
func (c *Client) sseURL() (string, error) {
	u, err := url.Parse(c.server)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/sse"
	}
	return u.String(), nil
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
		headers, err := c.tunnelHeaders()
		if err != nil {
			return false, err
		}
		wsConn, _, err := d.DialContext(ctx, c.server, headers)
		if err != nil {
			return false, err
		}
		conn = cnet.NewWebSocketConn(wsConn)
	case "sse":
		sseURL, err := c.sseURL()
		if err != nil {
			return false, err
		}
		// Build one HTTP client that honors TLS, proxy and dialer config; it is
		// shared by the stream request and every subsequent upload. Like Go's
		// default client it offers HTTP/2 over TLS, so the stream and uploads
		// share one connection when the server agrees. (http2 edits the TLS
		// config it is given, hence the clone.)
		transport := &http.Transport{
			TLSClientConfig:   c.tlsConfig.Clone(),
			DialContext:       c.config.DialContext,
			ForceAttemptHTTP2: true,
		}
		if c.proxyURL != nil {
			p, err := sseProxyURL(c.proxyURL)
			if err != nil {
				return false, err
			}
			transport.Proxy = http.ProxyURL(p)
		}
		httpClient := &http.Client{Transport: transport}
		// The stream request lives for the whole session; give it a cancelable
		// context so Close (via the SSH conn) can abort the in-flight request.
		sseCtx, sseCancel := context.WithCancel(ctx)
		headers, err := c.tunnelHeaders()
		if err != nil {
			sseCancel()
			return false, err
		}
		//opened like a browser EventSource
		req, err := http.NewRequestWithContext(sseCtx, "GET", sseURL, nil)
		if err != nil {
			sseCancel()
			return false, err
		}
		applySSEHeaders(req, headers)
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Cache-Control", "no-cache")
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
		//a refused tunnel is served as an ordinary page, possibly a 200
		//from --backend, so require the stream and its session cookie
		var sseSid string
		for _, ck := range resp.Cookies() {
			if ck.Name == cnet.SessionCookie {
				sseSid = ck.Value
			}
		}
		if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") || sseSid == "" {
			resp.Body.Close()
			sseCancel()
			return false, fmt.Errorf("sse handshake failed: not a tunnel response (wrong --obfs-key or path?)")
		}
		conn = cnet.NewClientSSEConn(sseCtx, sseCancel, resp, httpClient, c.config.Headers, sseURL, sseSid, c.sseRate)
	default:
		return false, fmt.Errorf("unknown transport mode: %q", c.config.Mode)
	}

	if c.obfsKey != nil {
		conn = cnet.NewObfsConn(conn, c.obfsKey, true)
	}
	// perform SSH handshake on net.Conn
	c.Debugf("Handshaking...")
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, "", c.sshConfig)
	if err != nil {
		e := err.Error()
		if strings.Contains(e, "unable to authenticate") {
			c.Infof("Authentication failed")
			c.Debugf("%s", e)
		} else {
			c.Infof("%s", e)
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

// tunnelHeaders returns the configured headers for a request that opens a
// tunnel, plus a fresh token cookie when --obfs-key is set.
func (c *Client) tunnelHeaders() (http.Header, error) {
	h := c.config.Headers.Clone()
	if c.obfsKey == nil {
		return h, nil
	}
	token, err := cnet.NewObfsToken(c.obfsKey)
	if err != nil {
		return nil, err
	}
	cookie := (&http.Cookie{Name: cnet.SessionCookie, Value: token}).String()
	if existing := h.Get("Cookie"); existing != "" {
		cookie = existing + "; " + cookie
	}
	h.Set("Cookie", cookie)
	return h, nil
}

// applySSEHeaders replays the client-configured headers onto the stream request,
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
