package e2e_test

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
	"github.com/jpillora/chisel/share/cnet"
)

const probePath = "/api/events"

// startProbeServer runs a server with --obfs-key, --path and optionally a
// --backend answering every request with 418.
func startProbeServer(t *testing.T, ctx context.Context, key string, backend bool) (*chserver.Server, string) {
	t.Helper()
	config := &chserver.Config{ObfsKey: key, Path: probePath}
	if backend {
		b := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		})}
		bl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go b.Serve(bl)
		t.Cleanup(func() { b.Close() })
		config.Proxy = "http://" + bl.Addr().String()
	}
	s, err := chserver.NewServer(config)
	if err != nil {
		t.Fatal(err)
	}
	s.Debug = debug
	port := availablePort()
	if err := s.StartContext(ctx, "127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	return s, "127.0.0.1:" + port
}

// probe sends one request and returns its status and content type
func probe(t *testing.T, method, url, cookie string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(`{"content":"aGVsbG8="}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: cnet.SessionCookie, Value: cookie})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Content-Type")
}

// TestProbeSeesOnlyBackend checks that with --obfs-key, requests without a
// valid token cannot tell the tunnel endpoint from the backend.
func TestProbeSeesOnlyBackend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, addr := startProbeServer(t, ctx, "s3cret", true)
	url := "http://" + addr + probePath
	wrongKey, _ := cnet.NewObfsToken(cnet.NewObfsKey("wrong"))
	for name, c := range map[string]struct{ method, cookie string }{
		"stream without token":     {"GET", ""},
		"stream with garbage":      {"GET", "abc"},
		"stream with wrong key":    {"GET", wrongKey},
		"upload without session":   {"POST", ""},
		"upload with fake session": {"POST", "0123456789abcdef0123456789abcdef"},
	} {
		if code, _ := probe(t, c.method, url, c.cookie); code != http.StatusTeapot {
			t.Errorf("%s: expected the backend's 418, got %d", name, code)
		}
	}
	//a valid token opens a stream exactly once
	token, err := cnet.NewObfsToken(cnet.NewObfsKey("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	if code, ct := probe(t, "GET", url, token); code != http.StatusOK || ct != "text/event-stream" {
		t.Fatalf("valid token: expected a stream, got %d %q", code, ct)
	}
	if code, _ := probe(t, "GET", url, token); code != http.StatusTeapot {
		t.Fatalf("replayed token: expected the backend's 418, got %d", code)
	}
	//websocket upgrades without a token go to the backend too
	_, resp, err := websocket.DefaultDialer.Dial("ws://"+addr+probePath, nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusTeapot {
		t.Fatalf("websocket without token: expected the backend's 418, got %v (%v)", resp, err)
	}
}

// TestProbeHidesVersion checks that --obfs-key hides /version and /health,
// which would otherwise name the server.
func TestProbeHidesVersion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, addr := startProbeServer(t, ctx, "s3cret", false)
	for _, p := range []string{"/version", "/health"} {
		resp, err := http.Get("http://" + addr + p)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: expected 404, got %d", p, resp.StatusCode)
		}
	}
}

// TestProbeClientConnects checks that clients holding the key still connect
// through both transports while a backend serves everything else.
func TestProbeClientConnects(t *testing.T) {
	for _, mode := range []string{"websocket", "sse"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, addr := startProbeServer(t, ctx, "s3cret", true)
			c, err := chclient.NewClient(&chclient.Config{
				Server:      "http://" + addr + probePath,
				Fingerprint: s.GetFingerprint(),
				Remotes:     []string{availablePort() + ":127.0.0.1:1"},
				Mode:        mode,
				ObfsKey:     "s3cret",
			})
			if err != nil {
				t.Fatal(err)
			}
			c.Debug = debug
			if err := c.Start(ctx); err != nil {
				t.Fatal(err)
			}
			readyCtx, readyCancel := context.WithTimeout(ctx, 10*time.Second)
			defer readyCancel()
			if !c.Ready(readyCtx) {
				t.Fatal("client with the key did not connect")
			}
		})
	}
}
