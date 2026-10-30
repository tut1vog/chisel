package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"testing"
	"time"

	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
)

// startObfsClient connects a client through a recording relay to a server
// using --obfs-key, and reports whether it became ready.
func startObfsClient(t *testing.T, mode, serverKey, clientKey string) (bool, []byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := chserver.NewServer(&chserver.Config{ObfsKey: serverKey})
	if err != nil {
		t.Fatal(err)
	}
	s.Debug = debug
	port := availablePort()
	if err := s.StartContext(ctx, "127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	fl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer fl.Close()
	rec := &recordingForwarder{}
	go rec.serve(fl, "127.0.0.1:"+port)
	c, err := chclient.NewClient(&chclient.Config{
		Server:        "http://" + fl.Addr().String(),
		Fingerprint:   s.GetFingerprint(),
		Remotes:       []string{availablePort() + ":127.0.0.1:1"},
		Mode:          mode,
		ObfsKey:       clientKey,
		MaxRetryCount: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Debug = debug
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	readyCtx, readyCancel := context.WithTimeout(ctx, 5*time.Second)
	defer readyCancel()
	return c.Ready(readyCtx), rec.Bytes()
}

// TestObfsKeyHidesSSH checks that with --obfs-key the SSH handshake never
// appears on the wire, while it does without one.
func TestObfsKeyHidesSSH(t *testing.T) {
	for _, mode := range []string{"websocket", "sse"} {
		t.Run(mode, func(t *testing.T) {
			//sse carries the banner base64-encoded inside JSON events
			banner := []byte("SSH-2.0")
			if mode == "sse" {
				banner = []byte(base64.StdEncoding.EncodeToString([]byte("SSH-2.0-"))[:8])
			}
			ready, wire := startObfsClient(t, mode, "", "")
			if !ready {
				t.Fatal("plain client did not connect")
			}
			if !bytes.Contains(wire, banner) {
				t.Fatalf("control: expected the ssh banner %q on the plain wire", banner)
			}
			ready, wire = startObfsClient(t, mode, "s3cret", "s3cret")
			if !ready {
				t.Fatal("obfs client did not connect")
			}
			if bytes.Contains(wire, banner) {
				t.Fatalf("wire carries %q with --obfs-key set", banner)
			}
			for _, sig := range []string{"SSH-2.0", "curve25519", "ssh-ed25519", "ecdsa-sha2"} {
				if bytes.Contains(wire, []byte(sig)) {
					t.Fatalf("wire carries %q with --obfs-key set", sig)
				}
			}
		})
	}
}

// TestObfsKeyMismatch checks that a client cannot connect with the wrong key
// or without one.
func TestObfsKeyMismatch(t *testing.T) {
	for _, keys := range [][2]string{{"s3cret", "wrong"}, {"s3cret", ""}, {"", "s3cret"}} {
		if ready, _ := startObfsClient(t, "websocket", keys[0], keys[1]); ready {
			t.Fatalf("server key %q accepted client key %q", keys[0], keys[1])
		}
	}
}

// TestObfsKeyWithAuth checks that --auth still gates tunnels under
// --obfs-key: the right credentials carry traffic, wrong ones are refused.
func TestObfsKeyWithAuth(t *testing.T) {
	for _, mode := range []string{"websocket", "sse"} {
		t.Run(mode, func(t *testing.T) {
			tmpPort := availablePort()
			teardown := simpleSetup(t,
				&chserver.Config{KeySeed: "foobar", Auth: "foo:bar", ObfsKey: "s3cret"},
				&chclient.Config{
					Remotes: []string{"0.0.0.0:" + tmpPort + ":127.0.0.1:$FILEPORT"},
					Auth:    "foo:bar",
					ObfsKey: "s3cret",
					Mode:    mode,
				})
			defer teardown()
			result, err := post("http://localhost:"+tmpPort, "foo")
			if err != nil {
				t.Fatal(err)
			}
			if result != "foo!" {
				t.Fatalf("expected exclamation mark added, got %q", result)
			}
			//wrong password, right obfs key: SSH auth must still refuse it
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s, err := chserver.NewServer(&chserver.Config{Auth: "foo:bar", ObfsKey: "s3cret"})
			if err != nil {
				t.Fatal(err)
			}
			port := availablePort()
			if err := s.StartContext(ctx, "127.0.0.1", port); err != nil {
				t.Fatal(err)
			}
			c, err := chclient.NewClient(&chclient.Config{
				Server:        "http://127.0.0.1:" + port,
				Fingerprint:   s.GetFingerprint(),
				Remotes:       []string{availablePort() + ":127.0.0.1:1"},
				Auth:          "foo:wrong",
				ObfsKey:       "s3cret",
				Mode:          mode,
				MaxRetryCount: 0,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Start(ctx); err != nil {
				t.Fatal(err)
			}
			readyCtx, readyCancel := context.WithTimeout(ctx, 3*time.Second)
			defer readyCancel()
			if c.Ready(readyCtx) {
				t.Fatal("client with the wrong password connected")
			}
		})
	}
}
