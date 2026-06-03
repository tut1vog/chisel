package e2e_test

import (
	"testing"

	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
)

// TestSSEBase mirrors TestBase but drives the tunnel over the SSE transport
// instead of WebSockets.
func TestSSEBase(t *testing.T) {
	tmpPort := availablePort()
	teardown := simpleSetup(t,
		&chserver.Config{},
		&chclient.Config{
			Remotes: []string{tmpPort + ":$FILEPORT"},
			Mode:    "sse",
		})
	defer teardown()
	result, err := post("http://localhost:"+tmpPort, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if result != "foo!" {
		t.Fatalf("expected exclamation mark added")
	}
}

// TestSSEReverse mirrors TestReverse over the SSE transport.
func TestSSEReverse(t *testing.T) {
	tmpPort := availablePort()
	teardown := simpleSetup(t,
		&chserver.Config{
			Reverse: true,
		},
		&chclient.Config{
			Remotes: []string{"R:" + tmpPort + ":$FILEPORT"},
			Mode:    "sse",
		})
	defer teardown()
	result, err := post("http://localhost:"+tmpPort, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if result != "foo!" {
		t.Fatalf("expected exclamation mark added")
	}
}

// TestSSEAuth mirrors TestAuth, confirming SSH auth/ACL runs unchanged on top of
// the SSE transport.
func TestSSEAuth(t *testing.T) {
	tmpPort1 := availablePort()
	tmpPort2 := availablePort()
	teardown := simpleSetup(t,
		&chserver.Config{
			KeySeed: "foobar",
			Auth:    "../bench/userfile",
		},
		&chclient.Config{
			Remotes: []string{
				"0.0.0.0:" + tmpPort1 + ":127.0.0.1:$FILEPORT",
				"0.0.0.0:" + tmpPort2 + ":localhost:$FILEPORT",
			},
			Auth: "foo:bar",
			Mode: "sse",
		})
	defer teardown()
	result, err := post("http://localhost:"+tmpPort1, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if result != "foo!" {
		t.Fatalf("expected exclamation mark added")
	}
	result, err = post("http://localhost:"+tmpPort2, "bar")
	if err != nil {
		t.Fatal(err)
	}
	if result != "bar!" {
		t.Fatalf("expected exclamation mark added again")
	}
}

// TestSSETLS runs the SSE transport over TLS. It proves the SSE handshake GET and
// data POSTs honor the client TLS config (CA, client cert/key) — i.e. the H3 fix;
// before it, SSE used http.DefaultClient and this would fail to verify the
// self-signed server.
func TestSSETLS(t *testing.T) {
	tlsConfig, err := newTestTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	defer tlsConfig.Close()

	tmpPort := availablePort()
	teardown := simpleSetup(t,
		&chserver.Config{
			TLS: *tlsConfig.serverTLS,
		},
		&chclient.Config{
			Remotes: []string{tmpPort + ":$FILEPORT"},
			TLS:     *tlsConfig.clientTLS,
			Server:  "https://localhost:" + tmpPort,
			Mode:    "sse",
		})
	defer teardown()
	result, err := post("http://localhost:"+tmpPort, "foo")
	if err != nil {
		t.Fatal(err)
	}
	if result != "foo!" {
		t.Fatalf("expected exclamation mark added")
	}
}
