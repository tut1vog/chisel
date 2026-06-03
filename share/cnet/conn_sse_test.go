package cnet

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"net/http"
	"strings"
	"testing"
)

// flushRecorder is a minimal http.ResponseWriter + http.Flusher that accumulates
// everything written by ServerSSEConn so a ClientSSEConn can read it back.
type flushRecorder struct {
	buf     bytes.Buffer
	header  http.Header
	flushed int
}

func (f *flushRecorder) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}
func (f *flushRecorder) Write(p []byte) (int, error) { return f.buf.Write(p) }
func (f *flushRecorder) WriteHeader(int)             {}
func (f *flushRecorder) Flush()                      { f.flushed++ }

// readConn builds a ClientSSEConn whose read side is fed from r, matching the
// scanner configuration of the production constructor.
func readConn(r io.Reader) *ClientSSEConn {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxSSEFrame)
	return &ClientSSEConn{scanner: scanner}
}

// encodeFrames writes payload(s) to the SSE wire format via ServerSSEConn.Write
// and returns the resulting stream.
func encodeFrames(t *testing.T, payloads ...[]byte) []byte {
	t.Helper()
	rec := &flushRecorder{}
	conn := NewServerSSEConn(rec, nil).(*ServerSSEConn)
	for _, p := range payloads {
		n, err := conn.Write(p)
		if err != nil {
			t.Fatalf("server write: %v", err)
		}
		if n != len(p) {
			t.Fatalf("server write: n=%d want %d", n, len(p))
		}
	}
	if rec.flushed == 0 {
		t.Fatalf("expected the server conn to flush")
	}
	return rec.buf.Bytes()
}

// readAll drains the conn until io.EOF.
func readAll(t *testing.T, conn *ClientSSEConn, chunk int) []byte {
	t.Helper()
	var out []byte
	buf := make([]byte, chunk)
	for {
		n, err := conn.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
}

func TestSSEFrameRoundTrip(t *testing.T) {
	payload := []byte("the quick brown fox\x00\x01\x02jumps")
	stream := encodeFrames(t, payload)
	got := readAll(t, readConn(bytes.NewReader(stream)), 4096)
	if !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", got, payload)
	}
}

func TestSSEReadShortBuffer(t *testing.T) {
	payload := []byte("hello world")
	stream := encodeFrames(t, payload)
	conn := readConn(bytes.NewReader(stream))
	// First read with a buffer smaller than the frame exercises the leftover path.
	dst := make([]byte, 5)
	n, err := conn.Read(dst)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if string(dst[:n]) != "hello" {
		t.Fatalf("first read got %q want %q", dst[:n], "hello")
	}
	// Remaining bytes must come from the leftover buffer.
	rest := readAll(t, conn, 64)
	if string(rest) != " world" {
		t.Fatalf("leftover got %q want %q", rest, " world")
	}
}

func TestSSELargeFrame(t *testing.T) {
	// A frame larger than bufio.Scanner's 64 KiB default token limit; without the
	// raised buffer (M3) the scanner would return bufio.ErrTooLong.
	payload := make([]byte, 100*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	stream := encodeFrames(t, payload)
	got := readAll(t, readConn(bytes.NewReader(stream)), 200*1024)
	if !bytes.Equal(got, payload) {
		t.Fatalf("large frame round trip mismatch (got %d bytes, want %d)", len(got), len(payload))
	}
}

func TestSSEReadMalformed(t *testing.T) {
	conn := readConn(strings.NewReader("data:not valid base64!!!\n\n"))
	if _, err := conn.Read(make([]byte, 64)); err == nil {
		t.Fatal("expected an error decoding a malformed data frame")
	}
}

func TestSSEReadEOF(t *testing.T) {
	// A stream with no data: lines must terminate with io.EOF, not an error.
	conn := readConn(strings.NewReader(": comment\n\n"))
	n, err := conn.Read(make([]byte, 64))
	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}
