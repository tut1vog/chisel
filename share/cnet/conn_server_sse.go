package cnet

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type ServerSSEConn struct {
	// p saves accumulated requests from client
	p *io.PipeReader
	// w is ResponseWriter of SSE request
	w http.ResponseWriter
}

func NewServerSSEConn(w http.ResponseWriter, p *io.PipeReader) net.Conn {
	c := ServerSSEConn{p, w}
	return &c
}

func (c *ServerSSEConn) Read(dst []byte) (int, error) {
	// directly read from pipe
	n, err := c.p.Read(dst)
	if err != nil {
		return n, err
	}
	return n, nil
}

func (c *ServerSSEConn) Write(b []byte) (int, error) {
	n := len(b)
	_, err := fmt.Fprintf(c.w, "data:%s\n\n", base64.StdEncoding.EncodeToString(b))
	if err != nil {
		return 0, err
	}
	flusher, ok := c.w.(http.Flusher)
	if !ok {
		return n, nil // data accepted but failed to flush
	}
	flusher.Flush()
	return n, nil
}

func (c *ServerSSEConn) Close() error {
	err := c.p.Close()
	if err != nil {
		return err
	}
	return nil
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
