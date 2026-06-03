# SSE Transport — Code Review & Bug Report

**Branch:** `sse` (commits `fd33248`, `86bcd6d`) rebased onto upstream `b9d1219`
**Reviewer:** code review, 2026-06-03
**Scope:** the `--sse` client transport and `/sse` server endpoint.

## Files reviewed
- `client/client.go` — `Config.Mode`
- `client/client_connect.go` — SSE handshake/dial path
- `share/cnet/conn_client_sse.go` — client `net.Conn` over SSE+POST
- `share/cnet/conn_server_sse.go` — server `net.Conn` over SSE+pipe
- `server/server.go` — `sseSessions sync.Map`
- `server/server_handler.go` — routing, `handleSSEGet`, `handleSSEPost`, `buildSSHTunnel`
- `main.go` — `--sse` flag

## Design summary
The client `--sse` flag swaps the WebSocket transport for two HTTP channels:
- **server → client:** a long-lived `GET /sse` response streaming base64 SSH frames as `data:` lines.
- **client → server:** one `POST /sse` per SSH write, correlated by a 128-bit random `X-Chisel-Session-Id`, joined into the server-side SSH read via an `io.Pipe`.

SSH (and therefore chisel auth/ACL) runs unchanged on top. The server-side extraction of `buildSSHTunnel()` from `handleWebsocket` is clean, and routing both transports through it means upstream's per-channel ACL fix (`44310b6`) now covers SSE automatically. The transport concept is sound; the issues below are correctness, resource-lifecycle, and config-fidelity defects.

---

## Critical

### C1 — Client panics on any non-200 SSE handshake response
**Where:** `client/client_connect.go:122-124` returns `(false, nil)`; `client/client_connect.go:35` then calls `err.Error()`.
**Root cause:** On a non-200 GET response the SSE path returns `connected=false, err=nil`. `connectionLoop` unconditionally dereferences `err`:
```go
if strings.HasSuffix(err.Error(), "use of closed network connection") { // err == nil → panic
```
The WebSocket path never returns a nil error, so this guard was always safe before SSE.
**Impact:** A wrong protocol version, a busy/erroring server, or any non-200 crashes the whole client process. Easily triggered remotely.
**Fix:** Return a real error (e.g. `fmt.Errorf("sse handshake failed: status %d", resp.StatusCode)`) and/or nil-guard `err` in `connectionLoop`. Close `resp.Body` before returning.

### C2 — Nil `net.Conn` panic when `Mode` is unset (breaks library use + entire test suite)
**Where:** `client/client_connect.go:81-130` then `:134`.
**Root cause:** `conn` is only assigned when `Mode == "websocket"` or `"sse"`. With an empty/unknown `Mode`, `conn` stays `nil` and is passed to `ssh.NewClientConn(nil, ...)`.
**Impact:** Any consumer of `chclient.Config` that does not set `Mode` panics. This currently breaks **all** `client` and `test/e2e` tests (including upstream's new `acl_channel_test.go`) — confirmed via `go test ./...`:
```
panic: invalid memory address... ssh.NewClientConn({0x0,0x0}...) client_connect.go:134
```
**Fix:** Treat empty `Mode` as `"websocket"` (default in `NewClient` or in `connectionOnce`), and return an explicit error for unknown modes instead of falling through with a nil conn.

### C3 — `ClientSSEConn.Close()` is a no-op; response body is never closable
**Where:** `share/cnet/conn_client_sse.go:23-31` (resp not retained), `:87-89` (`Close` returns nil).
**Root cause:** `NewClientSSEConn` keeps only `resp.Body`'s scanner, not `resp`/`resp.Body`. `Close()` does nothing, so the long-lived GET body is never closed.
**Impact:** Every reconnect leaks the GET connection + its reader goroutine on the client, and leaves the server-side session/stream alive. Leaks accumulate across the retry loop.
**Fix:** Store `resp.Body` (or a cancel func / `*http.Response`) and close it in `Close()`; cancel the request context.

---

## High

### H1 — Nil-pointer in `handleSSEPost` (missing `return`)
**Where:** `server/server_handler.go:126-130`.
```go
pw, ok := val.(*io.PipeWriter)
if !ok {
    s.Debugf("Unexpected error, type conversion failed")
    w.WriteHeader(http.StatusInternalServerError)
}            // <-- no return
_, err = pw.Write(bodyBytes)   // pw == nil → panic
```
**Impact:** Latent crash. Unreachable today (stored value is always `*io.PipeWriter`), but one refactor away from a remote panic.
**Fix:** Add `return` in the `!ok` branch.

### H2 — Server pipe/session leak on client disconnect
**Where:** `server/server_handler.go:89-109`.
**Root cause:** `handleSSEGet` stores `pw`, `defer`s only `sseSessions.Delete(key)`, then blocks in `buildSSHTunnel` reading from the pipe. Nothing closes `pw`/`pr` when the client silently vanishes. The read unblocks only if the SSH layer tries to write and the GET write fails — i.e. it relies on keepalive traffic.
**Impact:** With `--keepalive 0` (or before the first keepalive), a dropped client leaks a goroutine + pipe + session indefinitely. Unauthenticated clients can open many `GET /sse` to amplify.
**Fix:** Tie cleanup to `req.Context().Done()` (close the pipe writer/reader on disconnect) and `defer conn.Close()` so the SSH read always unblocks.

### H3 — SSE bypasses all client transport configuration (TLS, proxy, dialer, headers)
**Where:** `client/client_connect.go:113-129` (`http.DefaultClient`), `share/cnet/conn_client_sse.go:28,70-76` (fresh `http.Client`).
**Root cause:** Both the handshake GET and every data POST use default HTTP clients, ignoring `c.tlsConfig`, `c.proxyURL`, `c.config.DialContext`, and `c.config.Headers`.
**Impact:**
- `wss://` / TLS is effectively broken: `--tls-ca`, `--tls-skip-verify`, mTLS cert/key, and `--sni` are all ignored; self-signed or pinned servers fail.
- `--proxy` and custom `--header` / hostname overrides are dropped.
- No dial timeout on the handshake.
**Fix:** Build a single `*http.Client` with a `Transport` carrying `c.tlsConfig`, proxy, and `DialContext`; reuse it for GET and POST; apply `c.config.Headers`.

### H4 — Missing SSE/streaming response headers defeat proxy traversal
**Where:** `server/server_handler.go:102-104` (server), client GET lacks `Accept`.
**Root cause:** The GET response sets only `X-Chisel-Session-Id` + `200`. No `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`, or `X-Accel-Buffering: no`.
**Impact:** Intermediary proxies/CDNs (the entire reason to use SSE) may buffer or transform the response, stalling the downstream channel. The transport works only on direct connections.
**Fix:** Set the standard event-stream headers server-side and `Accept: text/event-stream` client-side.

---

## Medium

### M1 — `/sse` unreachable when server runs a backend reverse proxy
**Where:** `server/server_handler.go:40-58`. The `s.reverseProxy != nil` block returns before the `/sse` check, whereas the WebSocket upgrade is handled *before* the proxy. With `--backend` set, WebSocket works but SSE is dead.
**Fix:** Move the `/sse` routing above the reverse-proxy block, mirroring the WebSocket upgrade handling.

### M2 — Request context not propagated; no handshake dial timeout
**Where:** `client/client_connect.go:113` and `share/cnet/conn_client_sse.go:70`. GET/POST use `http.NewRequest` (no ctx). Cancellation / client shutdown cannot interrupt in-flight SSE I/O, and the handshake GET (via `http.DefaultClient`) has no timeout.
**Fix:** Use `http.NewRequestWithContext(ctx, ...)`; set a connect timeout distinct from the stream lifetime.

### M3 — `bufio.Scanner` 64 KB token limit on the read path
**Where:** `share/cnet/conn_client_sse.go:25`. A base64-encoded SSH frame inflates ~4/3×. Typical channel packets (~32 KB) → ~43 KB, under the 64 KB `MaxScanTokenSize` but with thin margin; a larger packet yields `bufio.ErrTooLong` and kills the connection.
**Fix:** `scanner.Buffer(make([]byte, 0, 64*1024), maxFrame)` sized to the SSH max packet, or frame without a line scanner.

### M4 — Response bodies leaked on early-return handshake paths
**Where:** `client/client_connect.go:122-124` (non-200) and `:126-128` (missing session id) return without `resp.Body.Close()`.
**Fix:** `defer resp.Body.Close()` immediately after a successful `Do`, before the status checks.

### M5 — Per-packet POST round-trip: throughput + spurious-disconnect risk
**Where:** `share/cnet/conn_client_sse.go:28,68-85`. Each SSH write is one synchronous `POST` (SSH serializes writes), and the client has a fixed `Timeout: 10s`.
**Impact:** Effective upstream throughput ≈ packet/RTT (one round-trip per frame); on higher-latency links this collapses. A POST exceeding 10 s (slow link or slow server-side pipe drain) errors and tears down the tunnel.
**Fix:** Document the design limit; consider a write timeout proportional to payload, and batching if feasible.

### M6 — Handshake-failure paths in `handleSSEGet` skip `conn.Close()`
**Where:** `server/server_handler.go:89-109` + `buildSSHTunnel:139-144`. If `ssh.NewServerConn` fails (or the handler returns early), the pipe is abandoned, not closed; a concurrent `handleSSEPost` `pw.Write` can block until the client's 10 s timeout.
**Fix:** `defer conn.Close()` in the GET handler / `buildSSHTunnel`.

---

## Low / quality

- **L1** Unchecked `w.(http.Flusher)` assertion at `server/server_handler.go:104` can panic with a non-flushing `ResponseWriter`; guard with the comma-ok form (as `ServerSSEConn.Write` already does).
- **L2** `url += "/sse"` (`client/client_connect.go:111`) breaks with any base path or trailing slash; the server matches only exact `r.URL.Path == "/sse"` (`:45`).
- **L3** `io.Writer` contract violation: `ClientSSEConn.Write` returns `(len(b), err)` on non-200 (`conn_client_sse.go:81-83`); should return `n < len(b)` with the error.
- **L4** gofmt failures (mixed tabs/spaces) and missing trailing newlines in `conn_client_sse.go`, `conn_server_sse.go`, `server_handler.go`; CI `gofmt -l` will flag these.
- **L5** `--sse` has an empty help string (`main.go:442`) and is undocumented in `clientHelp` / README.
- **L6** Convoluted method/protocol gate in `handleClientHandler` (`:45-58`); `strings.ToLower(r.Method)` is non-idiomatic (HTTP methods are case-sensitive). A `switch r.Method` reads cleaner.
- **L7** Comment typo "handelSSE" (`server_handler.go:88`); no tests cover the SSE path.

---

## Suggested fix ordering
1. **C2** (unblocks the whole test suite + restores library API), then **C1**, **C3** — crashes & core leaks.
2. **H1–H4** — remaining panic, server leak, config fidelity, proxy traversal.
3. **M1–M6** — robustness & routing.
4. **L1–L7** — polish, formatting, docs; add SSE integration tests.

## Verification status
`go build ./...` and `go vet ./...` pass on the rebased branch. `go test ./...` currently fails (`client`, `test/e2e`) due to **C2** — fixing it should restore the suite, after which the e2e harness can be extended with an SSE variant.
