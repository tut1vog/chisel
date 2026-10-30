package chclient

import (
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestSetProxySchemes(t *testing.T) {
	//all socks variants use the same SOCKS5 dialer
	for _, scheme := range []string{"socks", "socks5", "socks5h"} {
		u, err := url.Parse(scheme + "://127.0.0.1:1080")
		if err != nil {
			t.Fatal(err)
		}
		d := &websocket.Dialer{}
		if err := (&Client{}).setProxy(u, d); err != nil {
			t.Fatalf("%s:// rejected: %v", scheme, err)
		}
		if d.NetDial == nil {
			t.Fatalf("%s:// did not install the socks dialer", scheme)
		}
	}
	//http CONNECT proxies pass through
	u, _ := url.Parse("http://127.0.0.1:8080")
	d := &websocket.Dialer{}
	if err := (&Client{}).setProxy(u, d); err != nil {
		t.Fatal(err)
	}
	if d.Proxy == nil {
		t.Fatal("http:// did not set the CONNECT proxy")
	}
	//unknown socks variants are rejected
	u, _ = url.Parse("socks4://127.0.0.1:1080")
	if err := (&Client{}).setProxy(u, &websocket.Dialer{}); err == nil {
		t.Fatal("socks4:// unexpectedly accepted")
	}
}

// TestSSEProxySchemes checks that the SSE transport speaks SOCKS5 for every
// scheme setProxy accepts. net/http would otherwise send an HTTP CONNECT to a
// socks:// proxy.
func TestSSEProxySchemes(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	firstByte := make(chan byte, 1)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			b := make([]byte, 1)
			if _, err := c.Read(b); err == nil {
				firstByte <- b[0]
			}
			c.Close()
		}
	}()
	for _, scheme := range []string{"socks", "socks5", "socks5h"} {
		u, _ := url.Parse(scheme + "://" + l.Addr().String())
		p, err := sseProxyURL(u)
		if err != nil {
			t.Fatalf("%s:// rejected: %v", scheme, err)
		}
		c := &http.Client{
			Timeout:   time.Second,
			Transport: &http.Transport{Proxy: http.ProxyURL(p)},
		}
		c.Get("http://example.invalid/sse")
		select {
		case b := <-firstByte:
			if b != 0x05 {
				t.Fatalf("%s:// sent %q, expected a SOCKS5 greeting", scheme, b)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s:// never reached the proxy", scheme)
		}
	}
	//http CONNECT proxies pass through unchanged
	u, _ := url.Parse("http://127.0.0.1:8080")
	if p, err := sseProxyURL(u); err != nil || p != u {
		t.Fatalf("http:// proxy altered: %v, %v", p, err)
	}
	//unknown socks variants are rejected
	u, _ = url.Parse("socks4://127.0.0.1:1080")
	if _, err := sseProxyURL(u); err == nil {
		t.Fatal("socks4:// unexpectedly accepted")
	}
}
