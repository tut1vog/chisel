package cnet

import (
	"time"
)

// The SSE transport is shaped like a streaming JSON API rather than a raw
// byte pipe:
//
//	open:     POST <endpoint> {"stream":true}
//	          -> 200 text/event-stream, first event data: {"id":"<session>"}
//	down:     data: {"content":"<base64>"}            (one event per <=2 KiB)
//	up:       POST <endpoint> {"id":"<session>","content":"<base64>"}
//	          -> 200 {"status":"ok"}
//
// Client writes are batched: one upload is in flight at a time and whatever
// accumulates meanwhile goes in the next request.

// SSERequest is the JSON body of every client POST. Content is []byte, so
// encoding/json carries it as standard base64.
type SSERequest struct {
	ID      string `json:"id,omitempty"`
	Stream  bool   `json:"stream,omitempty"`
	Content []byte `json:"content,omitempty"`
}

// sseEvent is the JSON payload of each server-sent "data:" line
type sseEvent struct {
	ID      string `json:"id,omitempty"`
	Content []byte `json:"content,omitempty"`
}

const (
	// sseEventMax is the most raw bytes carried by one downstream event
	sseEventMax = 2 * 1024
	// sseMaxBatch is the most raw bytes carried by one upload; its JSON
	// body (~4/3 larger) stays well under the server's pre-auth read limit
	sseMaxBatch = 64 * 1024
	// sseMaxPending bounds buffered upload bytes before Write blocks
	sseMaxPending = 1024 * 1024
	// SSEUploadOK is the body of a successful upload response
	SSEUploadOK = `{"status":"ok"}`
)

// Pacer limits a stream to a fixed number of bytes per second, allowing a
// short burst after idle periods. A nil Pacer does not limit.
type Pacer struct {
	rate float64 //bytes per second
	next time.Time
}

const pacerBurst = 250 * time.Millisecond

// NewPacer returns a Pacer for rate bytes per second, or nil when rate <= 0
func NewPacer(rate int64) *Pacer {
	if rate <= 0 {
		return nil
	}
	return &Pacer{rate: float64(rate)}
}

// Wait blocks until n more bytes may be sent. Not safe for concurrent use.
func (p *Pacer) Wait(n int) {
	if p == nil {
		return
	}
	now := time.Now()
	if earliest := now.Add(-pacerBurst); p.next.Before(earliest) {
		p.next = earliest
	}
	p.next = p.next.Add(time.Duration(float64(n) / p.rate * float64(time.Second)))
	if d := p.next.Sub(now); d > 0 {
		time.Sleep(d)
	}
}
