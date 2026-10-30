package e2e_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
)

// recordingForwarder relays TCP between a listener and target, keeping a copy
// of every byte seen in both directions.
type recordingForwarder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (f *recordingForwarder) Write(b []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buf.Write(b)
}

func (f *recordingForwarder) Bytes() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return bytes.Clone(f.buf.Bytes())
}

func (f *recordingForwarder) serve(l net.Listener, target string) {
	for {
		src, err := l.Accept()
		if err != nil {
			return
		}
		dst, err := net.Dial("tcp", target)
		if err != nil {
			src.Close()
			continue
		}
		go func() {
			io.Copy(dst, io.TeeReader(src, f))
			dst.Close()
		}()
		go func() {
			io.Copy(src, io.TeeReader(dst, f))
			src.Close()
		}()
	}
}

// startPathServer runs a server with --path and a --backend that answers every
// request with 418, so requests that miss the tunnel path are easy to spot.
func startPathServer(t *testing.T, ctx context.Context, tunnelPath string) (*chserver.Server, string) {
	t.Helper()
	backend := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})}
	bl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go backend.Serve(bl)
	t.Cleanup(func() { backend.Close() })
	s, err := chserver.NewServer(&chserver.Config{
		Path:  tunnelPath,
		Proxy: "http://" + bl.Addr().String(),
	})
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

// TestPathTunnelNoFingerprint drives both transports through a recording relay
// and checks that nothing on the wire names chisel.
func TestPathTunnelNoFingerprint(t *testing.T) {
	for _, mode := range []string{"websocket", "sse"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, addr := startPathServer(t, ctx, "/api/stream")
			fl, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer fl.Close()
			rec := &recordingForwarder{}
			go rec.serve(fl, addr)
			c, err := chclient.NewClient(&chclient.Config{
				Server:      "http://" + fl.Addr().String() + "/api/stream",
				Fingerprint: s.GetFingerprint(),
				Remotes:     []string{availablePort() + ":127.0.0.1:1"},
				Mode:        mode,
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
				t.Fatal("client did not connect on the tunnel path")
			}
			wire := bytes.ToLower(rec.Bytes())
			//the relay must see the plaintext handshake for this check to mean anything
			if !bytes.Contains(wire, []byte("/api/stream")) {
				t.Fatal("relay did not record the http handshake")
			}
			if bytes.Contains(wire, []byte("chisel")) {
				t.Fatalf("wire traffic mentions chisel:\n%q", wire)
			}
		})
	}
}

// TestPathOtherWebsocketsGoToBackend checks that with --path set, websocket
// upgrades elsewhere reach the backend instead of the tunnel.
func TestPathOtherWebsocketsGoToBackend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, addr := startPathServer(t, ctx, "api/stream") //normalised to /api/stream
	for _, p := range []string{"/", "/api", "/api/stream/x"} {
		_, resp, err := websocket.DefaultDialer.Dial("ws://"+addr+p, nil)
		if err == nil {
			t.Fatalf("%s: websocket was accepted as a tunnel", p)
		}
		if resp == nil || resp.StatusCode != http.StatusTeapot {
			t.Fatalf("%s: expected backend response, got %v (%v)", p, resp, err)
		}
	}
	ws, _, err := websocket.DefaultDialer.Dial("ws://"+addr+"/api/stream", nil)
	if err != nil {
		t.Fatalf("tunnel path rejected: %v", err)
	}
	ws.Close()
	//the sse endpoint lives under the tunnel path, not at /sse
	resp, err := http.Get("http://" + addr + "/sse")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("/sse: expected backend response, got %d", resp.StatusCode)
	}
}
