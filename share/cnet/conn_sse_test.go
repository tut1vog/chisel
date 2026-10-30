package cnet

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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
	conn := NewServerSSEConn(rec, nil, nil).(*ServerSSEConn)
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
	conn := readConn(strings.NewReader("data: {\"content\":\"not valid base64!!!\"}\n\n"))
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

func TestSSEEventsAreJSONAndSplit(t *testing.T) {
	payload := make([]byte, 3*sseEventMax+5)
	rand.Read(payload)
	stream := encodeFrames(t, payload)
	events := 0
	for _, line := range strings.Split(string(stream), "\n") {
		if line == "" {
			continue
		}
		raw, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			t.Fatalf("unexpected line %q", line)
		}
		var ev sseEvent
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			t.Fatalf("event is not JSON: %v", err)
		}
		if len(ev.Content) > sseEventMax {
			t.Fatalf("event carries %d bytes, max %d", len(ev.Content), sseEventMax)
		}
		events++
	}
	if events < 4 || events > 13 {
		t.Fatalf("expected 4-13 events, got %d", events)
	}
}

// uploadRecorder is an SSE endpoint that records each upload's content
type uploadRecorder struct {
	mu      sync.Mutex
	uploads [][]byte
}

func (u *uploadRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var msg SSERequest
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil || msg.ID != "sid" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	u.mu.Lock()
	u.uploads = append(u.uploads, msg.Content)
	u.mu.Unlock()
	w.Write([]byte(SSEUploadOK))
}

func (u *uploadRecorder) joined() ([]byte, int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return bytes.Join(u.uploads, nil), len(u.uploads)
}

func newTestClientConn(t *testing.T, url string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	resp := &http.Response{Body: io.NopCloser(strings.NewReader("data: {\"id\":\"sid\"}\n\n"))}
	conn, err := NewClientSSEConn(ctx, cancel, resp, http.DefaultClient, http.Header{}, url, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestSSEClientBatchesWrites(t *testing.T) {
	rec := &uploadRecorder{}
	srv := httptest.NewServer(rec)
	defer srv.Close()
	conn := newTestClientConn(t, srv.URL)
	var want []byte
	for i := range 50 {
		msg := []byte(fmt.Sprintf("write-%02d;", i))
		want = append(want, msg...)
		if _, err := conn.Write(msg); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, n := rec.joined()
		if bytes.Equal(got, want) {
			if n >= 50 {
				t.Fatalf("50 writes took %d uploads; expected batching", n)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("uploads incomplete: got %q", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSSEClientWriteFailsAfterUploadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	conn := newTestClientConn(t, srv.URL)
	conn.Write([]byte("hello"))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := conn.Write([]byte("x")); err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("writes kept succeeding after the upload failed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPacer(t *testing.T) {
	var p *Pacer = NewPacer(0)
	p.Wait(1 << 30) //nil pacer never blocks
	p = NewPacer(100 * 1024)
	start := time.Now()
	for range 10 {
		p.Wait(10 * 1024) //100 KiB at 100 KiB/s, less the initial burst
	}
	if d := time.Since(start); d < 600*time.Millisecond || d > 2*time.Second {
		t.Fatalf("100KiB at 100KiB/s took %s", d)
	}
}
