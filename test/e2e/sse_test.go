package e2e_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
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
			Auth:    "foo:bar",
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

// TestSSEOverHTTP2 checks that a TLS server offers HTTP/2 and serves the SSE
// stream over it, as the SSE client's transport (like Go's default client)
// will use it when offered.
func TestSSEOverHTTP2(t *testing.T) {
	tlsConfig, err := newTestTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	defer tlsConfig.Close()
	s, err := chserver.NewServer(&chserver.Config{TLS: *tlsConfig.serverTLS})
	if err != nil {
		t.Fatal(err)
	}
	port := availablePort()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.StartContext(ctx, "127.0.0.1", port); err != nil {
		t.Fatal(err)
	}
	//client side of the test's mutual TLS
	cert, err := tls.LoadX509KeyPair(tlsConfig.clientTLS.Cert, tlsConfig.clientTLS.Key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(tlsConfig.clientTLS.CA)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{cert}},
		ForceAttemptHTTP2: true,
	}}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://localhost:"+port+"/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("expected HTTP/2, got %s", resp.Proto)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("expected an event stream, got %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Connection") != "" {
		t.Fatal("connection-specific header sent over HTTP/2")
	}
}
