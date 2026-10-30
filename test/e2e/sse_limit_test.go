package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
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
// session id (from its cookie) and the still-open event stream.
func openSSESession(t *testing.T, url string) (string, *bufio.Reader, *http.Response) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("handshake status %d", resp.StatusCode)
	}
	var sid string
	for _, c := range resp.Cookies() {
		if c.Name == cnet.SessionCookie {
			sid = c.Value
		}
	}
	if sid == "" {
		resp.Body.Close()
		t.Fatal("missing session cookie")
	}
	return sid, bufio.NewReader(resp.Body), resp
}

// postSSE uploads body under session sid ("" sends no cookie)
func postSSE(t *testing.T, url, sid string, body []byte) (int, string) {
	t.Helper()
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sid != "" {
		req.AddCookie(&http.Cookie{Name: cnet.SessionCookie, Value: sid})
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		//the server may reset the upload once the limit is hit
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func uploadBody(t *testing.T, content []byte) []byte {
	t.Helper()
	b, err := json.Marshal(cnet.SSEUpload{Content: content})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// waitStreamEnd drains an SSE stream and fails unless it ends within 5s.
func waitStreamEnd(t *testing.T, r io.Reader, what string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, r)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("SSE stream still open 5s after %s", what)
	}
}

// TestSSEPostUnknownSession verifies that uploads without an open session
// are served as ordinary requests (here the default 404), and malformed
// uploads to an open session are rejected.
func TestSSEPostUnknownSession(t *testing.T) {
	s, url := startSSEServer(t, "sse-unknown-session")
	defer s.Close()
	for _, sid := range []string{"", "not-a-session"} {
		code, body := postSSE(t, url, sid, uploadBody(t, []byte("hello")))
		if code != http.StatusNotFound || body != "Not found" {
			t.Fatalf("session %q: expected the ordinary 404, got %d %q", sid, code, body)
		}
	}
	sid, _, stream := openSSESession(t, url)
	defer stream.Body.Close()
	if code, _ := postSSE(t, url, sid, []byte("not json")); code != http.StatusBadRequest {
		t.Fatalf("malformed upload: expected 400, got %d", code)
	}
}

// TestSSEPreAuthOversizedFrame is the SSE counterpart of
// TestPreAuthOversizedMessage: an unauthenticated peer's oversized upload
// must be refused and must end its session.
func TestSSEPreAuthOversizedFrame(t *testing.T) {
	t.Setenv("CHISEL_WS_READ_LIMIT", "")
	s, url := startSSEServer(t, "sse-limit-test")
	defer s.Close()
	sid, events, stream := openSSESession(t, url)
	defer stream.Body.Close()
	//the server's SSH identification arrives first
	line, err := events.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "data:") {
		t.Fatalf("expected SSH identification event, got %q (%v)", line, err)
	}
	oversized := uploadBody(t, bytes.Repeat([]byte("A"), 512*1024))
	if code, _ := postSSE(t, url, sid, oversized); code != http.StatusRequestEntityTooLarge && code != 0 {
		t.Fatalf("expected 413 for oversized frame, got %d", code)
	}
	waitStreamEnd(t, events, "oversized frame")
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
