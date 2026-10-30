package chclient

import (
	"context"
	"crypto/elliptic"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jpillora/chisel/share/ccrypto"
	"golang.org/x/crypto/ssh"
)

func TestCustomHeaders(t *testing.T) {
	//fake server, records the header for the main goroutine to
	//assert (t.Fatal must not be called from the handler goroutine)
	wg := sync.WaitGroup{}
	wg.Add(1)
	var gotFoo string
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		gotFoo = req.Header.Get("Foo")
		wg.Done()
	}))
	defer server.Close()
	//client
	headers := http.Header{}
	headers.Set("Foo", "Bar")
	config := Config{
		KeepAlive:        time.Second,
		MaxRetryInterval: time.Second,
		Server:           server.URL,
		Remotes:          []string{"9000"},
		Headers:          headers,
	}
	c, err := NewClient(&config)
	if err != nil {
		t.Fatal(err)
	}
	go c.Run()
	//wait for the fake server to receive the request
	wg.Wait()
	c.Close()
	if gotFoo != "Bar" {
		t.Fatalf("expected header Foo to be 'Bar', got %q", gotFoo)
	}
}

func TestFallbackLegacyFingerprint(t *testing.T) {
	config := Config{
		Fingerprint: "a5:32:92:c6:56:7a:9e:61:26:74:1b:81:a6:f5:1b:44",
	}
	c, err := NewClient(&config)
	if err != nil {
		t.Fatal(err)
	}
	r := ccrypto.NewDetermRand([]byte("test123"))
	priv, err := ccrypto.GenerateKeyGo119(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = c.verifyServer("", nil, pub)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyLegacyFingerprint(t *testing.T) {
	config := Config{
		Fingerprint: "a5:32:92:c6:56:7a:9e:61:26:74:1b:81:a6:f5:1b:44",
	}
	c, err := NewClient(&config)
	if err != nil {
		t.Fatal(err)
	}
	r := ccrypto.NewDetermRand([]byte("test123"))
	priv, err := ccrypto.GenerateKeyGo119(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = c.verifyLegacyFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyFingerprint(t *testing.T) {
	config := Config{
		Fingerprint: "qmrRoo8MIqePv3jC8+wv49gU6uaFgD3FASQx9V8KdmY=",
	}
	c, err := NewClient(&config)
	if err != nil {
		t.Fatal(err)
	}
	r := ccrypto.NewDetermRand([]byte("test123"))
	priv, err := ccrypto.GenerateKeyGo119(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	err = c.verifyServer("", nil, pub)
	if err != nil {
		t.Fatal(err)
	}
}

//TestSSEURL verifies the SSE endpoint keeps the server's http(s) scheme
//rather than the ws(s):// form the client stores internally
func TestSSEURL(t *testing.T) {
	for server, want := range map[string]string{
		"https://example.com/api/events": "https://example.com:443/api/events",
		"http://example.com":             "http://example.com:80/sse",
		"example.com:8080/":              "http://example.com:8080/sse",
	} {
		c, err := NewClient(&Config{Server: server, Mode: "sse", Remotes: []string{"9000"}})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := c.sseURL(); err != nil || got != want {
			t.Errorf("%s: got %q (%v), want %q", server, got, err, want)
		}
	}
}

//TestSSEHandshakeErrors verifies a 200 that is not a tunnel stream names the
//check it failed, e.g. a proxy that removed Set-Cookie
func TestSSEHandshakeErrors(t *testing.T) {
	for name, c := range map[string]struct {
		contentType, cookie, want string
	}{
		"cookie removed":       {"text/event-stream", "", `no "session" cookie`},
		"cookie renamed":       {"text/event-stream", "sid=abc", `no "session" cookie`},
		"content type changed": {"text/html", "session=abc", `Content-Type "text/html"`},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", c.contentType)
				if c.cookie != "" {
					w.Header().Set("Set-Cookie", c.cookie)
				}
			}))
			defer srv.Close()
			cl, err := NewClient(&Config{Server: srv.URL, Mode: "sse", Remotes: []string{"9000"}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = cl.connectionOnce(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got error %v, want one containing %s", err, c.want)
			}
		})
	}
}

func TestRedactSetCookie(t *testing.T) {
	for in, want := range map[string]string{
		"session=80ccb130; Path=/sse; HttpOnly": "session=<8 bytes>; Path=/sse; HttpOnly",
		"session=abc":                           "session=<3 bytes>",
		"garbage":                               "garbage",
	} {
		if got := redactSetCookie(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

//TestHostHeaderOmitsDefaultPort verifies the Host header names the default
//port nowhere, like browsers and curl, in both transports. Dials go to local
//test servers whatever the server URL, so default ports need no privileges.
func TestHostHeaderOmitsDefaultPort(t *testing.T) {
	hosts := make(chan string, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case hosts <- r.Host:
		default:
		}
		w.WriteHeader(http.StatusNotFound)
	})
	plain := httptest.NewServer(handler)
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(handler)
	defer tlsSrv.Close()
	for _, c := range []struct {
		server, hostname, want string
	}{
		{"https://example.com", "", "example.com"},
		{"https://example.com:443/api/events", "", "example.com"},
		{"http://example.com", "", "example.com"},
		{"example.com", "", "example.com"},
		{"https://example.com:8443", "", "example.com:8443"},
		{"http://example.com:443", "", "example.com:443"},
		{"https://[::1]", "", "[::1]"},
		{"https://example.com", "front.example.org", "front.example.org"},
	} {
		for _, mode := range []string{"websocket", "sse"} {
			target := plain.Listener.Addr().String()
			if strings.HasPrefix(c.server, "https") {
				target = tlsSrv.Listener.Addr().String()
			}
			config := &Config{
				Server:  c.server,
				Mode:    mode,
				Remotes: []string{"9000"},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, target)
				},
			}
			config.TLS.SkipVerify = true
			if c.hostname != "" {
				config.Headers = http.Header{"Host": {c.hostname}}
			}
			cl, err := NewClient(config)
			if err != nil {
				t.Fatal(err)
			}
			cl.connectionOnce(context.Background())
			select {
			case got := <-hosts:
				if got != c.want {
					t.Errorf("%s %s: Host %q, want %q", mode, c.server, got, c.want)
				}
			default:
				t.Errorf("%s %s: no request arrived", mode, c.server)
			}
		}
	}
}

func TestHostWithoutDefaultPort(t *testing.T) {
	for in, want := range map[string]string{
		"wss://example.com:443":    "example.com",
		"ws://example.com:80":      "example.com",
		"wss://example.com:80":     "example.com:80",
		"ws://example.com:8080":    "example.com:8080",
		"wss://[2001:db8::1]:443":  "[2001:db8::1]",
		"wss://[2001:db8::1]:8443": "[2001:db8::1]:8443",
	} {
		u, _ := url.Parse(in)
		if got := hostWithoutDefaultPort(u); got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}
