package cnet

import (
	"encoding/json"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"time"
)

type ServerSSEConn struct {
	// p saves accumulated requests from client
	p *io.PipeReader
	// w is ResponseWriter of SSE request
	w     http.ResponseWriter
	pacer *Pacer
}

// NewServerSSEConn streams writes to w as JSON events, optionally paced, and
// reads the client's uploads from p.
func NewServerSSEConn(w http.ResponseWriter, p *io.PipeReader, pacer *Pacer) net.Conn {
	return &ServerSSEConn{p: p, w: w, pacer: pacer}
}

// writeSSEEvent writes one "data:" event carrying ev as JSON
func writeSSEEvent(w io.Writer, ev sseEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	buf := make([]byte, 0, len(b)+8)
	buf = append(buf, "data: "...)
	buf = append(buf, b...)
	buf = append(buf, "\n\n"...)
	_, err = w.Write(buf)
	return err
}

func (c *ServerSSEConn) Read(dst []byte) (int, error) {
	// directly read from pipe
	return c.p.Read(dst)
}

func (c *ServerSSEConn) Write(b []byte) (int, error) {
	flusher, _ := c.w.(http.Flusher)
	for rest := b; len(rest) > 0; {
		//random event sizes, so a paced stream is not a run of equal events
		n := min(len(rest), sseEventMax/4+mrand.IntN(sseEventMax*3/4+1))
		c.pacer.Wait(n)
		if err := writeSSEEvent(c.w, sseEvent{Content: rest[:n]}); err != nil {
			return 0, err
		}
		rest = rest[n:]
		//when paced, events trickle out one at a time
		if c.pacer != nil && flusher != nil {
			flusher.Flush()
		}
	}
	if c.pacer == nil && flusher != nil {
		flusher.Flush()
	}
	return len(b), nil
}

func (c *ServerSSEConn) Close() error {
	return c.p.Close()
}

// LocalAddr and RemoteAddr return the conn itself as a placeholder net.Addr,
// mirroring the stdio adapter (conn_rwc.go). The SSE transport spans many HTTP
// requests with no single stable socket, so there is no real address to report —
// and returning nil would panic any caller that logs RemoteAddr().String().
func (c *ServerSSEConn) LocalAddr() net.Addr {
	return c
}

func (c *ServerSSEConn) RemoteAddr() net.Addr {
	return c
}

func (c *ServerSSEConn) Network() string {
	return "tcp"
}

func (c *ServerSSEConn) String() string {
	return ""
}

// Deadlines are intentionally no-ops: chisel drives liveness with SSH keepalive
// rather than socket deadlines, the same as the stdio adapter (conn_rwc.go).
func (c *ServerSSEConn) SetDeadline(t time.Time) error {
	return nil //no-op
}

func (c *ServerSSEConn) SetReadDeadline(t time.Time) error {
	return nil //no-op
}

func (c *ServerSSEConn) SetWriteDeadline(t time.Time) error {
	return nil //no-op
}
