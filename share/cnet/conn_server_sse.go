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

func (c *ServerSSEConn) LocalAddr() net.Addr {
	return nil
}

func (c *ServerSSEConn) RemoteAddr() net.Addr {
	return nil
}

func (c *ServerSSEConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *ServerSSEConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *ServerSSEConn) SetWriteDeadline(t time.Time) error {
	return nil
}
