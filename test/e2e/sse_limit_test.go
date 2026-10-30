package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
	"github.com/jpillora/chisel/share/cnet"
)

// startSSEServer starts a bare chisel server for raw SSE requests.
func startSSEServer(t *testing.T, seed string) (s *chserver.Server, base string) {
	t.Helper()
	s, err := chserver.NewServer(&chserver.Config{KeySeed: seed})
	if err != nil {
		t.Fatal(err)
	}
	s.Debug = debug
	port := availablePort()
	if err := s.Start("127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	return s, "http://127.0.0.1:" + port + "/sse"
}

// openSSESession performs the unauthenticated SSE handshake, returning the
// session id (the stream's first event) and the still-open event stream.
func openSSESession(t *testing.T, url string) (string, *bufio.Reader, *http.Response) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("handshake status %d", resp.StatusCode)
	}
	r := bufio.NewReader(resp.Body)
	line, err := r.ReadString('\n')
	var ev struct{ ID string }
	if err != nil || json.Unmarshal([]byte(strings.TrimPrefix(line, "data:")), &ev) != nil || ev.ID == "" {
		resp.Body.Close()
		t.Fatalf("missing session id event, got %q (%v)", line, err)
	}
	return ev.ID, r, resp
}

func postSSE(t *testing.T, url string, body []byte) int {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		//the server may reset the upload once the limit is hit
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func uploadBody(t *testing.T, sid string, content []byte) []byte {
	t.Helper()
	b, err := json.Marshal(cnet.SSERequest{ID: sid, Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSSEPostUnknownSession verifies that uploads without a valid session,
// and requests that are neither uploads nor stream opens, are rejected.
func TestSSEPostUnknownSession(t *testing.T) {
	s, url := startSSEServer(t, "sse-unknown-session")
	defer s.Close()
	if code := postSSE(t, url, uploadBody(t, "not-a-session", []byte("hello"))); code != http.StatusNotFound {
		t.Fatalf("unknown session: expected 404, got %d", code)
	}
	for _, body := range []string{`{"content":"aGVsbG8="}`, `not json`, `{}`} {
		if code := postSSE(t, url, []byte(body)); code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d", body, code)
		}
	}
}

// TestSSEPreAuthOversizedFrame is the SSE counterpart of
// TestPreAuthOversizedMessage: an unauthenticated peer's oversized upload
// must be refused before it is buffered. (The session id lives inside the
// body, so a truncated body cannot name the session to end; the client
// reconnects on the 413 instead.)
func TestSSEPreAuthOversizedFrame(t *testing.T) {
	t.Setenv("CHISEL_WS_READ_LIMIT", "")
	s, url := startSSEServer(t, "sse-limit-test")
	defer s.Close()
	sid, events, stream := openSSESession(t, url)
	defer stream.Body.Close()
	//the server's SSH identification arrives next
	line, err := events.ReadString('\n')
	for err == nil && strings.TrimSpace(line) == "" {
		line, err = events.ReadString('\n')
	}
	if err != nil || !strings.HasPrefix(line, "data:") {
		t.Fatalf("expected SSH identification event, got %q (%v)", line, err)
	}
	oversized := uploadBody(t, sid, bytes.Repeat([]byte("A"), 512*1024))
	if code := postSSE(t, url, oversized); code != http.StatusRequestEntityTooLarge && code != 0 {
		t.Fatalf("expected 413 for oversized frame, got %d", code)
	}
}

// TestSSEShutdownEndsStreams verifies that a graceful shutdown ends SSE
// sessions immediately instead of waiting out CHISEL_SHUTDOWN_GRACE.
func TestSSEShutdownEndsStreams(t *testing.T) {
	t.Setenv("CHISEL_SHUTDOWN_GRACE", "30s")
	s, err := chserver.NewServer(&chserver.Config{KeySeed: "sse-shutdown-test"})
	if err != nil {
		t.Fatal(err)
	}
	s.Debug = debug
	port := availablePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.StartContext(ctx, "127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := chclient.NewClient(&chclient.Config{
		Server:  "http://127.0.0.1:" + port,
		Remotes: []string{availablePort() + ":127.0.0.1:1"},
		Mode:    "sse",
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Debug = debug
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	if err := c.Start(cctx); err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	if !c.Ready(readyCtx) {
		t.Fatal("client not connected")
	}
	start := time.Now()
	cancel()
	waitc := make(chan error, 1)
	go func() { waitc <- s.Wait() }()
	select {
	case err := <-waitc:
		if err != nil {
			t.Fatalf("wait: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server shutdown blocked on the SSE session")
	}
	t.Logf("shutdown took %s", time.Since(start))
}
