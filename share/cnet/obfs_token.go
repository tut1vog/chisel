package cnet

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// SessionCookie names the cookie that carries the tunnel token on the
// request that opens a tunnel, and the session id on SSE uploads.
const SessionCookie = "session"

// With --obfs-key set, every request that opens a tunnel carries a token
// proving knowledge of the key, so the server can answer everything else as
// an ordinary web server would. A token is
//
//	base64url(nonce[16] | unix seconds[8] | HMAC-SHA256(key, nonce|time)[:16])
//
// and is accepted once, within obfsTokenWindow of the server's clock.
const (
	obfsTokenNonce  = 16
	obfsTokenMAC    = 16
	obfsTokenSize   = obfsTokenNonce + 8 + obfsTokenMAC
	obfsTokenWindow = 5 * time.Minute
)

func obfsTokenKey(master []byte) []byte {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, master, nil, []byte("chisel-obfs token")), key); err != nil {
		panic(err) //hkdf cannot fail for 32 bytes
	}
	return key
}

func obfsTokenSum(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)[:obfsTokenMAC]
}

// NewObfsToken returns a fresh tunnel token for a master key from NewObfsKey
func NewObfsToken(master []byte) (string, error) {
	b := make([]byte, obfsTokenSize)
	if _, err := rand.Read(b[:obfsTokenNonce]); err != nil {
		return "", err
	}
	binary.BigEndian.PutUint64(b[obfsTokenNonce:], uint64(time.Now().Unix()))
	copy(b[obfsTokenNonce+8:], obfsTokenSum(obfsTokenKey(master), b[:obfsTokenNonce+8]))
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ObfsTokenVerifier checks tunnel tokens and rejects replays
type ObfsTokenVerifier struct {
	key       []byte
	mu        sync.Mutex
	seen      map[[obfsTokenNonce]byte]time.Time
	lastSweep time.Time
}

// NewObfsTokenVerifier returns a verifier for a master key from NewObfsKey
func NewObfsTokenVerifier(master []byte) *ObfsTokenVerifier {
	return &ObfsTokenVerifier{
		key:  obfsTokenKey(master),
		seen: map[[obfsTokenNonce]byte]time.Time{},
	}
}

// Verify reports whether token is authentic, current and unused, and marks
// it used.
func (v *ObfsTokenVerifier) Verify(token string) bool {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(b) != obfsTokenSize {
		return false
	}
	if !hmac.Equal(b[obfsTokenNonce+8:], obfsTokenSum(v.key, b[:obfsTokenNonce+8])) {
		return false
	}
	now := time.Now()
	issued := time.Unix(int64(binary.BigEndian.Uint64(b[obfsTokenNonce:])), 0)
	if issued.Before(now.Add(-obfsTokenWindow)) || issued.After(now.Add(obfsTokenWindow)) {
		return false
	}
	var nonce [obfsTokenNonce]byte
	copy(nonce[:], b)
	v.mu.Lock()
	defer v.mu.Unlock()
	//forget nonces old enough that their tokens fail the time check anyway
	if now.Sub(v.lastSweep) > obfsTokenWindow {
		for n, t := range v.seen {
			if now.Sub(t) > 2*obfsTokenWindow {
				delete(v.seen, n)
			}
		}
		v.lastSweep = now
	}
	if _, used := v.seen[nonce]; used {
		return false
	}
	v.seen[nonce] = now
	return true
}
