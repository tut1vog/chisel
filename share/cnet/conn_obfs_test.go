package cnet

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
)

var testObfsKey = NewObfsKey("test-key")

func TestObfsConnRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	client := NewObfsConn(a, testObfsKey, true)
	server := NewObfsConn(b, testObfsKey, false)
	defer client.Close()
	defer server.Close()
	//larger than one chunk, in both directions
	msg := make([]byte, 3*obfsMaxPayload+17)
	rand.Read(msg)
	for _, dir := range [][2]net.Conn{{client, server}, {server, client}} {
		go dir[0].Write(msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(dir[1], got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatal("payload mismatch")
		}
	}
}

func TestObfsConnHidesPlaintext(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	client := NewObfsConn(a, testObfsKey, true)
	defer client.Close()
	banner := []byte("SSH-2.0-Go\r\n")
	wire := captureWire(t, client, b, banner)
	if bytes.Contains(wire, []byte("SSH")) {
		t.Fatalf("plaintext on the wire: %q", wire)
	}
}

// captureWire writes msg through conn and returns what reached the raw peer
func captureWire(t *testing.T, conn, peer net.Conn, msg []byte) []byte {
	t.Helper()
	go func() {
		conn.Write(msg)
		conn.Close()
	}()
	wire, err := io.ReadAll(peer)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestObfsConnPadding(t *testing.T) {
	//the same small write on fresh conns should not keep the same wire size
	sizes := map[int]bool{}
	for range 10 {
		a, b := net.Pipe()
		sizes[len(captureWire(t, NewObfsConn(a, testObfsKey, true), b, []byte("hello")))] = true
		b.Close()
	}
	if len(sizes) < 2 {
		t.Fatalf("wire size did not vary: %v", sizes)
	}
}

func TestObfsConnKeyMismatch(t *testing.T) {
	a, b := net.Pipe()
	client := NewObfsConn(a, testObfsKey, true)
	server := NewObfsConn(b, NewObfsKey("other-key"), false)
	defer client.Close()
	defer server.Close()
	go client.Write([]byte("hello"))
	if _, err := server.Read(make([]byte, 16)); err != errObfsAuth {
		t.Fatalf("expected auth error, got %v", err)
	}
}

func TestObfsConnRejectsReflection(t *testing.T) {
	//a client's own stream fed back to it must not decrypt
	a, b := net.Pipe()
	wire := captureWire(t, NewObfsConn(a, testObfsKey, true), b, []byte("hello"))
	b.Close()
	c, d := net.Pipe()
	defer d.Close()
	reflected := NewObfsConn(c, testObfsKey, true)
	defer reflected.Close()
	go d.Write(wire)
	if _, err := reflected.Read(make([]byte, 16)); err != errObfsAuth {
		t.Fatalf("expected auth error, got %v", err)
	}
}
