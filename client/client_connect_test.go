package chclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestSSEHandshakeNon200 is a regression test for C1: a non-200 SSE handshake
// response must surface as an error rather than (false, nil), which the
// connection loop would then dereference and panic on.
func TestSSEHandshakeNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	c, err := NewClient(&Config{
		Server:  srv.URL,
		Remotes: []string{"socks"},
		Mode:    "sse",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Must return an error and not panic.
	connected, err := c.connectionOnce(context.Background())
	if connected {
		t.Fatal("expected not connected on a non-200 handshake")
	}
	if err == nil {
		t.Fatal("expected an error on a non-200 handshake")
	}
}

// TestInvalidModeRejected confirms NewClient rejects an unknown transport mode
// rather than later passing a nil net.Conn to the SSH handshake.
func TestInvalidModeRejected(t *testing.T) {
	if _, err := NewClient(&Config{
		Server:  "http://localhost:1234",
		Remotes: []string{"socks"},
		Mode:    "bogus",
	}); err == nil {
		t.Fatal("expected NewClient to reject an unknown mode")
	}
}

// TestDefaultModeIsWebsocket confirms an unset Mode defaults to websocket (C2),
// so existing library callers that never set Mode keep working.
func TestDefaultModeIsWebsocket(t *testing.T) {
	c, err := NewClient(&Config{
		Server:  "http://localhost:1234",
		Remotes: []string{"socks"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.config.Mode != "websocket" {
		t.Fatalf("expected default mode websocket, got %q", c.config.Mode)
	}
}
