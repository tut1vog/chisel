package cnet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// maxSSEFrame bounds a single base64-encoded SSE data line. An SSH packet
// (max ~32 KiB payload) inflates ~4/3 under base64, so this leaves generous
// headroom over bufio.Scanner's 64 KiB default token limit.
const maxSSEFrame = 512 * 1024

// SSESessionCookie names the cookie that correlates the client's POSTs with
// its streaming GET, set by the server on the handshake response.
const SSESessionCookie = "sid"

// ClientSSEConn is a net.Conn over the chisel SSE transport. The server->client
// direction is the long-lived GET response body (base64 "data:" frames); the
// client->server direction is one POST per Write.
//
// Note: the SSH layer serializes writes, so every Write is one synchronous POST
// and effective upstream throughput is ~one frame per round-trip. This is
// inherent to the SSE transport and is most noticeable on high-latency links.
type ClientSSEConn struct {
	sessionID string       // included on every POST to correlate the session
	client    *http.Client // shared with the handshake GET (TLS/proxy/dialer honored)
	url       string
	headers   http.Header // client-supplied headers replayed on each POST
	ctx       context.Context
	cancel    context.CancelFunc
	body      io.ReadCloser // the streaming GET body
	scanner   *bufio.Scanner
	buff      []byte // leftover bytes from a frame larger than the Read buffer
}

// NewClientSSEConn wraps the streaming handshake response as a net.Conn. ctx
// governs the lifetime of outbound POSTs and cancel is invoked by Close to abort
// the in-flight streaming GET.
func NewClientSSEConn(ctx context.Context, cancel context.CancelFunc, resp *http.Response, client *http.Client, headers http.Header, url, id string) net.Conn {
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSEFrame)
	return &ClientSSEConn{
		sessionID: id,
		client:    client,
		url:       url,
		headers:   headers,
		ctx:       ctx,
		cancel:    cancel,
		body:      resp.Body,
		scanner:   scanner,
	}
}

func (c *ClientSSEConn) Read(dst []byte) (int, error) {
	if len(c.buff) > 0 {
		n := copy(dst, c.buff)
		// If we copied everything, clear the buffer.
		// If not, slice it to keep the remaining part.
		if n < len(c.buff) {
			c.buff = c.buff[n:]
		} else {
			c.buff = nil
		}
		return n, nil
	}
	for c.scanner.Scan() {
		line := c.scanner.Text()
		// skip newlines until we reach the next data: line
		if strings.HasPrefix(line, "data:") {
			payload := strings.TrimPrefix(line, "data:")
			data, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return 0, err
			}
			n := copy(dst, data)
			// If there is data left over, save it for the next Read.
			if n < len(data) {
				c.buff = data[n:]
			}
			return n, nil
		}
	}
	if err := c.scanner.Err(); err != nil {
		return 0, err
	}
	return 0, io.EOF
}

func (c *ClientSSEConn) Write(b []byte) (int, error) {
	req, err := http.NewRequestWithContext(c.ctx, "POST", c.url, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	applyHeaders(req, c.headers)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.AddCookie(&http.Cookie{Name: SSESessionCookie, Value: c.sessionID})
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return len(b), nil
}

func (c *ClientSSEConn) Close() error {
	if c.cancel != nil {
		c.cancel()
	}
	return c.body.Close()
}

// LocalAddr and RemoteAddr return the conn itself as a placeholder net.Addr,
// mirroring the stdio adapter (conn_rwc.go). The SSE transport spans many HTTP
// requests with no single stable socket, so there is no real address to report —
// and returning nil would panic any caller that logs RemoteAddr().String().
func (c *ClientSSEConn) LocalAddr() net.Addr {
	return c
}

func (c *ClientSSEConn) RemoteAddr() net.Addr {
	return c
}

func (c *ClientSSEConn) Network() string {
	return "tcp"
}

func (c *ClientSSEConn) String() string {
	return ""
}

// Deadlines are intentionally no-ops: chisel drives liveness with SSH keepalive
// rather than socket deadlines, the same as the stdio adapter (conn_rwc.go).
func (c *ClientSSEConn) SetDeadline(t time.Time) error {
	return nil //no-op
}

func (c *ClientSSEConn) SetReadDeadline(t time.Time) error {
	return nil //no-op
}

func (c *ClientSSEConn) SetWriteDeadline(t time.Time) error {
	return nil //no-op
}

// applyHeaders replays client-supplied headers onto an outbound request,
// translating Host into the request's Host field (net/http ignores a "Host"
// header key otherwise).
func applyHeaders(req *http.Request, headers http.Header) {
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
