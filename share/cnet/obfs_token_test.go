package cnet

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"
)

func TestObfsToken(t *testing.T) {
	v := NewObfsTokenVerifier(testObfsKey)
	token, err := NewObfsToken(testObfsKey)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Verify(token) {
		t.Fatal("valid token rejected")
	}
	if v.Verify(token) {
		t.Fatal("replayed token accepted")
	}
	other, _ := NewObfsToken(NewObfsKey("other-key"))
	for name, bad := range map[string]string{
		"wrong key": other,
		"empty":     "",
		"garbage":   "not-a-token",
		"stale":     tokenAt(t, time.Now().Add(-2*obfsTokenWindow)),
		"future":    tokenAt(t, time.Now().Add(2*obfsTokenWindow)),
	} {
		if v.Verify(bad) {
			t.Fatalf("%s token accepted", name)
		}
	}
	if !v.Verify(tokenAt(t, time.Now().Add(-obfsTokenWindow/2))) {
		t.Fatal("token within the clock-skew window rejected")
	}
}

// tokenAt forges a correctly signed token issued at ts
func tokenAt(t *testing.T, ts time.Time) string {
	t.Helper()
	b := make([]byte, obfsTokenSize)
	b[0] = byte(ts.UnixNano()) //distinct nonce
	binary.BigEndian.PutUint64(b[obfsTokenNonce:], uint64(ts.Unix()))
	copy(b[obfsTokenNonce+8:], obfsTokenSum(obfsTokenKey(testObfsKey), b[:obfsTokenNonce+8]))
	return base64.RawURLEncoding.EncodeToString(b)
}
