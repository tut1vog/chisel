package cnet

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type ClientSSEConn struct {
    sessionID string         // The ID to include in headers
    client    *http.Client   // To make requests
	url	      string
	scanner   *bufio.Scanner
    buff      []byte      	 // The "leftovers" buffer
}

func NewClientSSEConn(resp *http.Response, url, id string) net.Conn {
	c := ClientSSEConn {
		scanner: 	bufio.NewScanner(resp.Body),
		url: 		url,
		sessionID: 	id,
		client: 	&http.Client{Timeout: 10 * time.Second}, // POST Timeout
	}
	return &c
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
		// skip newline until reach next data:
        if strings.HasPrefix(line, "data:") {
            payload := strings.TrimPrefix(line, "data:")
            data, err := base64.StdEncoding.DecodeString(payload)
            if err != nil {
                return 0, err
            }
            n := copy(dst, data)
            // If there is data left over, SAVE IT to c.buff
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
	n := len(b)
	req, err := http.NewRequest("POST", c.url, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Chisel-Session-Id", c.sessionID)
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return n, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return n, nil
}

func (c *ClientSSEConn) Close() error {
	return nil
}

func (c *ClientSSEConn) LocalAddr() net.Addr {
	return nil
}

func (c *ClientSSEConn) RemoteAddr() net.Addr {
	return nil
}

func (c *ClientSSEConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *ClientSSEConn) SetReadDeadline(t time.Time) error {
	return nil
}


func (c *ClientSSEConn) SetWriteDeadline(t time.Time) error {
	return nil
}