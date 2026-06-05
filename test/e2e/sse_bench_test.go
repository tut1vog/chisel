package e2e_test

import (
	"fmt"
	"strings"
	"testing"

	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
)

// BenchmarkTransport compares request throughput over the WebSocket (default)
// and SSE transports through a real loopback tunnel. The SSE transport sends one
// HTTP POST per upstream frame, so its cost scales with payload size (more frames
// means more round-trips). This benchmark makes that tradeoff measurable.
//
// It only runs under -bench, so it does not affect the normal `go test ./...` CI:
//
//	go test ./test/e2e/ -run '^$' -bench Transport -benchmem
func BenchmarkTransport(b *testing.B) {
	// Per-channel debug logging would dominate the measurement; silence it for
	// the duration of the benchmark (restored on exit).
	prev := debug
	debug = false
	defer func() { debug = prev }()

	sizes := []int{1 << 10, 64 << 10, 1 << 20} // 1 KiB, 64 KiB, 1 MiB
	for _, mode := range []string{"websocket", "sse"} {
		for _, size := range sizes {
			b.Run(fmt.Sprintf("%s/%dKiB", mode, size>>10), func(b *testing.B) {
				tmpPort := availablePort()
				teardown := simpleSetup(b,
					&chserver.Config{},
					&chclient.Config{
						Remotes: []string{tmpPort + ":$FILEPORT"},
						Mode:    mode,
					})
				defer teardown()
				url := "http://localhost:" + tmpPort
				payload := strings.Repeat("x", size)
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := post(url, payload); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}
