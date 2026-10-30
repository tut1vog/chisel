package cnet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"net"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// The obfs layer seals the SSH byte stream with AES-256-GCM so the transport
// payload carries no SSH banner or packet structure. Each direction starts
// with a random salt, then a sequence of chunks:
//
//	salt[32] | seal(len[2] pad[2]) | seal(payload[len] zeros[pad]) | ...
//
// Lengths are sealed too, so the stream is indistinguishable from random
// bytes. Every chunk carries a random amount of padding so its size does not
// mirror the SSH packet inside; small chunks (handshake, keepalives,
// keystrokes) get more, since their sizes are the most recognisable.
// Per-direction keys are HKDF(master, salt, direction), and nonces are a
// per-direction counter, which is safe because every key is fresh.
const (
	obfsSaltSize   = 32
	obfsHeaderSize = 4
	obfsMaxPayload = 0x3FFF
	//padding is drawn uniformly from [0, obfsMaxPadSmall] for payloads
	//below obfsSmallPayload, and from [0, obfsMaxPad] otherwise
	obfsSmallPayload = 1024
	obfsMaxPadSmall  = 1024
	obfsMaxPad       = 255
)

// obfsPadLen picks the padding length for a chunk carrying n payload bytes
func obfsPadLen(n int) int {
	if n < obfsSmallPayload {
		return mrand.IntN(obfsMaxPadSmall + 1)
	}
	return mrand.IntN(obfsMaxPad + 1)
}

var errObfsAuth = errors.New("obfs: message authentication failed")

// NewObfsKey stretches a pre-shared passphrase into the 32 byte master key
// used by NewObfsConn. It is slow by design; derive once at startup.
func NewObfsKey(passphrase string) []byte {
	return argon2.IDKey([]byte(passphrase), []byte("chisel-obfs-v1"), 1, 64*1024, 4, 32)
}

type obfsConn struct {
	net.Conn
	master   []byte
	sendInfo []byte
	recvInfo []byte

	wmu   sync.Mutex
	wAEAD cipher.AEAD
	wNonc []byte

	rmu   sync.Mutex
	rAEAD cipher.AEAD
	rNonc []byte
	rBuf  []byte //decrypted bytes not yet returned
	rErr  error
}

// NewObfsConn wraps conn with AES-256-GCM using a master key from NewObfsKey.
// Both peers must use the same master key and opposite isClient values.
func NewObfsConn(conn net.Conn, master []byte, isClient bool) net.Conn {
	c2s, s2c := []byte("chisel-obfs c2s"), []byte("chisel-obfs s2c")
	c := &obfsConn{Conn: conn, master: master}
	if isClient {
		c.sendInfo, c.recvInfo = c2s, s2c
	} else {
		c.sendInfo, c.recvInfo = s2c, c2s
	}
	return c
}

func (c *obfsConn) newAEAD(salt, info []byte) (cipher.AEAD, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, c.master, salt, info), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// incNonce increments a little-endian counter nonce
func incNonce(n []byte) {
	for i := range n {
		n[i]++
		if n[i] != 0 {
			return
		}
	}
}

// Write seals p into as many chunks as needed and sends them in a single
// underlying write, so message-oriented transports (websocket frames, SSE
// POSTs) still see one message per SSH write.
func (c *obfsConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var out []byte
	if c.wAEAD == nil {
		salt := make([]byte, obfsSaltSize)
		if _, err := rand.Read(salt); err != nil {
			return 0, err
		}
		aead, err := c.newAEAD(salt, c.sendInfo)
		if err != nil {
			return 0, err
		}
		c.wAEAD, c.wNonc = aead, make([]byte, aead.NonceSize())
		out = append(out, salt...)
	}
	var header [obfsHeaderSize]byte
	var body []byte
	for rest := p; len(rest) > 0; {
		n := min(len(rest), obfsMaxPayload)
		pad := obfsPadLen(n)
		binary.BigEndian.PutUint16(header[0:], uint16(n))
		binary.BigEndian.PutUint16(header[2:], uint16(pad))
		out = c.wAEAD.Seal(out, c.wNonc, header[:], nil)
		incNonce(c.wNonc)
		//padding is zeros; once sealed it is indistinguishable from data
		body = append(append(body[:0], rest[:n]...), make([]byte, pad)...)
		out = c.wAEAD.Seal(out, c.wNonc, body, nil)
		incNonce(c.wNonc)
		rest = rest[n:]
	}
	if _, err := c.Conn.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *obfsConn) Read(p []byte) (int, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if len(c.rBuf) == 0 {
		if c.rErr != nil {
			return 0, c.rErr
		}
		if err := c.readChunk(); err != nil {
			//authentication failures are permanent: the stream is out of sync
			c.rErr = err
			return 0, err
		}
	}
	n := copy(p, c.rBuf)
	c.rBuf = c.rBuf[n:]
	return n, nil
}

func (c *obfsConn) readChunk() error {
	if c.rAEAD == nil {
		salt := make([]byte, obfsSaltSize)
		if _, err := io.ReadFull(c.Conn, salt); err != nil {
			return err
		}
		aead, err := c.newAEAD(salt, c.recvInfo)
		if err != nil {
			return err
		}
		c.rAEAD, c.rNonc = aead, make([]byte, aead.NonceSize())
	}
	overhead := c.rAEAD.Overhead()
	buf := make([]byte, obfsHeaderSize+overhead)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return err
	}
	header, err := c.rAEAD.Open(buf[:0], c.rNonc, buf, nil)
	if err != nil {
		return errObfsAuth
	}
	incNonce(c.rNonc)
	n := int(binary.BigEndian.Uint16(header[0:]))
	pad := int(binary.BigEndian.Uint16(header[2:]))
	if n == 0 || n > obfsMaxPayload || pad > max(obfsMaxPadSmall, obfsMaxPad) {
		return errObfsAuth
	}
	buf = make([]byte, n+pad+overhead)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return noEOF(err)
	}
	body, err := c.rAEAD.Open(buf[:0], c.rNonc, buf, nil)
	if err != nil {
		return errObfsAuth
	}
	incNonce(c.rNonc)
	c.rBuf = body[:n]
	return nil
}

// noEOF reports a stream cut mid-chunk as truncated rather than a clean close
func noEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
