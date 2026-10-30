package cnet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxSSEFrame bounds a single SSE data line. Events carry at most sseEventMax
// raw bytes, so this leaves generous headroom over bufio.Scanner's 64 KiB
// default token limit.
const maxSSEFrame = 512 * 1024

// ClientSSEConn is a net.Conn over the chisel SSE transport. The server->client
// direction is the long-lived streaming response (JSON "data:" events); the
// client->server direction is a series of JSON POSTs.
//
// Writes are buffered and uploaded by a single background sender, one request
// at a time, so bursts of SSH writes share a request instead of each costing
// a round-trip.
type ClientSSEConn struct {
	sessionID string       // included on every POST to correlate the session
	client    *http.Client // shared with the handshake request (TLS/proxy/dialer honored)
	url       string
	headers   http.Header // client-supplied headers replayed on each POST
	ctx       context.Context
	cancel    context.CancelFunc
	body      io.ReadCloser // the streaming response body
	scanner   *bufio.Scanner
	buff      []byte // leftover bytes from an event larger than the Read buffer
	pacer     *Pacer

	mu      sync.Mutex
	cond    *sync.Cond
	pending []byte // written but not yet uploaded
	err     error  // set once the sender stops; returned by later Writes
}

// NewClientSSEConn wraps the streaming handshake response as a net.Conn.
// sessionID comes from the response's session cookie. ctx governs the
// lifetime of uploads and cancel is invoked by Close to abort the streaming
// response. rate limits upload bytes per second (0 is unlimited).
func NewClientSSEConn(ctx context.Context, cancel context.CancelFunc, resp *http.Response, client *http.Client, headers http.Header, url, sessionID string, rate int64) net.Conn {
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSEFrame)
	c := &ClientSSEConn{
		sessionID: sessionID,
		client:    client,
		url:       url,
		headers:   headers,
		ctx:       ctx,
		cancel:    cancel,
		body:      resp.Body,
		scanner:   scanner,
		pacer:     NewPacer(rate),
	}
	c.cond = sync.NewCond(&c.mu)
	go c.sendLoop()
	return c
}

// nextEvent returns the next "data:" event of the stream
func (c *ClientSSEConn) nextEvent() (sseEvent, error) {
	var ev sseEvent
	for c.scanner.Scan() {
		line, ok := strings.CutPrefix(c.scanner.Text(), "data:")
		if !ok {
			continue //blank separators, comments, other fields
		}
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &ev); err != nil {
			return ev, err
		}
		return ev, nil
	}
	if err := c.scanner.Err(); err != nil {
		return ev, err
	}
	return ev, io.EOF
}

func (c *ClientSSEConn) Read(dst []byte) (int, error) {
	for len(c.buff) == 0 {
		ev, err := c.nextEvent()
		if err != nil {
			return 0, err
		}
		c.buff = ev.Content
	}
	n := copy(dst, c.buff)
	c.buff = c.buff[n:]
	return n, nil
}

// Write queues b for upload. It blocks only while too much is already queued.
func (c *ClientSSEConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.err == nil && len(c.pending) >= sseMaxPending {
		c.cond.Wait()
	}
	if c.err != nil {
		return 0, c.err
	}
	c.pending = append(c.pending, b...)
	c.cond.Broadcast()
	return len(b), nil
}

// sendLoop uploads queued bytes until the conn fails or closes
func (c *ClientSSEConn) sendLoop() {
	for {
		//no artificial delay: whatever is written while an upload is in
		//flight joins the next one, so batching grows with the load
		c.mu.Lock()
		for c.err == nil && len(c.pending) == 0 {
			c.cond.Wait()
		}
		if c.err != nil {
			c.mu.Unlock()
			return
		}
		n := min(len(c.pending), sseMaxBatch)
		batch := bytes.Clone(c.pending[:n])
		c.pending = append(c.pending[:0], c.pending[n:]...)
		c.cond.Broadcast()
		c.mu.Unlock()
		c.pacer.Wait(len(batch))
		if err := c.upload(batch); err != nil {
			c.fail(err)
			return
		}
	}
}

func (c *ClientSSEConn) upload(b []byte) error {
	body, err := json.Marshal(SSEUpload{Content: b})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(c.ctx, "POST", c.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	applyHeaders(req, c.headers)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: c.sessionID})
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	//read (and so drain, for keep-alive reuse) the acknowledgement
	ack, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	//an unknown session is served like any web request, which may well
	//be a 200 from --backend; only the acknowledgement means delivered
	if string(ack) != SSEUploadOK {
		return fmt.Errorf("upload not acknowledged")
	}
	return nil
}

// fail stops the sender and aborts the stream, so the SSH layer observes the
// error on both directions and the client reconnects.
func (c *ClientSSEConn) fail(err error) {
	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *ClientSSEConn) Close() error {
	c.fail(net.ErrClosed)
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
