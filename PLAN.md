# SSE Remediation & Test Plan

Tracks the fixes for the 20 issues in [`SSE_BUG_REPORT.md`](./SSE_BUG_REPORT.md) plus
test coverage for the SSE transport.

**Branch:** `sse` · **Workflow:** one commit per phase, force-push with lease.
**Status legend:** `[ ]` todo · `[~]` in progress · `[x]` done

## Scope (ratified)
- Fix **all 20** issues (Critical → Low, incl. gofmt/newlines and `--sse` docs).
- **M5**: document the per-packet round-trip design limit + replace the fixed 10 s POST
  timeout with a context/proportional one. **No transport redesign.**
- Tests follow **existing project convention**: integration tests in `test/e2e`
  (`package e2e_test`, reuse `testLayout`/`simpleSetup`/`post`); pure-logic unit tests
  in-package (precedent: `share/tunnel/wg_test.go`).

## Verification gate (run before every commit)
- `gofmt -l .` → no SSE-touched file listed (all SSE files are gofmt-clean).
  Some pre-existing upstream files — e.g. `share/cnet/conn_rwc.go`,
  `conn_ws.go`, `connstats.go`, `http_server.go`, `meter.go` — are flagged by
  the go1.26 gofmt independently of this work and are intentionally left
  untouched to keep the SSE diff focused.
- `go vet ./...` → clean
- `go build ./...` → ok
- `go test ./...` → pass

---

## Phase 0 — Planning artifacts
- [x] Write `SSE_BUG_REPORT.md`
- [x] Write `PLAN.md`
- [x] Commit both (`docs: add SSE review and remediation plan`)

## Phase 1 — Client crash fixes
*Commit: `fix(client): prevent SSE handshake panics`*
- [x] **C2** — default empty/unknown `Mode` to `"websocket"`; return an explicit error for
  an unknown mode instead of passing a nil `conn` to `ssh.NewClientConn`.
  `client/client_connect.go:81-130`, optionally normalize in `NewClient`
  (`client/client.go`).
- [x] **C1** — on non-200 SSE handshake, return a real error (`fmt.Errorf("sse handshake
  failed: status %d", …)`) and close `resp.Body`; add a nil-guard before `err.Error()` in
  `connectionLoop`. `client/client_connect.go:35,122-124`.
- [x] *Acceptance:* existing `client` + `test/e2e` suites stop panicking and pass again
  (this alone fixes the currently-failing suite, incl. upstream `acl_channel_test.go`).

## Phase 2 — Client transport fidelity & conn lifecycle
*Commit: `fix(client): honor TLS/proxy/dialer in SSE and fix conn lifecycle`*
- [x] **H3** — build one shared `*http.Client` whose `Transport` carries `c.tlsConfig`,
  `c.proxyURL`, and `c.config.DialContext`; apply `c.config.Headers`. Use it for the
  handshake GET and reuse it inside `ClientSSEConn` for POSTs.
  `client/client_connect.go:113-129`, `share/cnet/conn_client_sse.go:28,70-76`.
- [x] **C3** — retain `resp.Body` (and a request `context.CancelFunc`) in `ClientSSEConn`;
  `Close()` cancels the GET context and closes the body.
  `share/cnet/conn_client_sse.go:23-31,87-89`.
- [x] **M2** — use `http.NewRequestWithContext` for GET and POST; thread the connection ctx.
- [x] **M3** — raise the read buffer: `scanner.Buffer(make([]byte,0,64*1024), maxFrame)`
  sized to the SSH max packet (base64-inflated). `share/cnet/conn_client_sse.go:25`.
- [x] **M4** — `defer resp.Body.Close()` immediately after a successful `Do`, before status
  checks. `client/client_connect.go:122-128`.
- [x] **M5** — replace the fixed `10*time.Second` POST timeout with a context-derived one;
  add a code comment documenting the one-round-trip-per-frame throughput limit.
  `share/cnet/conn_client_sse.go:28`.
- [x] **H4 (client half)** — set `Accept: text/event-stream` on the GET.
- [x] **L2** — derive the `/sse` URL with `net/url` join so a base path / trailing slash
  doesn't produce `//sse`. `client/client_connect.go:111`.
- [x] **L3** — `ClientSSEConn.Write` returns `n < len(b)` on error (io.Writer contract).
  `share/cnet/conn_client_sse.go:81-83`.

## Phase 3 — Server lifecycle, routing & headers
*Commit: `fix(server): SSE session lifecycle, routing, and stream headers`*
- [x] **H2** — tie session cleanup to `req.Context().Done()`; close the pipe writer/reader
  on disconnect so the SSH read always unblocks. `server/server_handler.go:89-109`.
- [x] **M6** — `defer conn.Close()` in the GET handler / `buildSSHTunnel` so handshake
  failures don't abandon the pipe. `server/server_handler.go:89-109,139-144`.
- [x] **H1** — add the missing `return` after the failed type assertion in `handleSSEPost`.
  `server/server_handler.go:126-130`.
- [x] **H4 (server half)** — set `Content-Type: text/event-stream`, `Cache-Control:
  no-cache`, `Connection: keep-alive`, `X-Accel-Buffering: no` on the GET response.
  `server/server_handler.go:102-104`.
- [x] **M1** — move the `/sse` routing above the `reverseProxy` block so `/sse` works with
  `--backend`. `server/server_handler.go:40-58`.
- [x] **L1** — guard `w.(http.Flusher)` with comma-ok in `handleSSEGet`.
  `server/server_handler.go:104`.
- [x] **L6** — simplify the method/protocol gate (`switch r.Method`).
  `server/server_handler.go:45-58`.
- [x] **L7 (typo)** — fix "handelSSE" comment. `server/server_handler.go:88`.

## Phase 4 — Tests (project convention)
*Commit: `test: cover SSE transport`*
- [x] **E2E** `test/e2e/sse_test.go` (`package e2e_test`): SSE variants mirroring
  `base_test.go` / reverse / auth via `simpleSetup` + `client.Config{Mode:"sse"}`:
  `TestSSEBase`, `TestSSEReverse`, `TestSSEAuth`.
- [x] **E2E-TLS** SSE-over-TLS test reusing `cert_utils_test.go` / `tls_test.go` patterns —
  proves **H3** (TLS config honored). Gated on Phase 2.
- [x] **Unit** `share/cnet/conn_sse_test.go` (`package cnet`): base64 frame round-trip via a
  pipe pair; short-`Read` `buff` leftover path; large frame > 64 KB (**M3** regression);
  malformed `data:` line; clean-EOF → `io.EOF`.
- [x] **Regression** client non-200 handshake (**C1**) against an `httptest.Server` returning
  a non-200 on `/sse` → asserts a returned error and **no panic**. (**C2** is covered by the
  existing e2e suite, which sets no `Mode`.)
- [x] *Acceptance:* `go test ./...` green, including the new SSE cases.

## Phase 5 — Docs & formatting
*Commit: `docs: document --sse flag; gofmt`*
- [x] **L5** — add `--sse` to `clientHelp` in `main.go` and a short note in `README.md`.
- [x] **L4** — `gofmt -w` the SSE files (mixed tabs/spaces, trailing newlines).

---

## Bug → phase coverage map
| Phase | Bugs |
|------|------|
| 1 | C1, C2 |
| 2 | C3, H3, H4(client), M2, M3, M4, M5, L2, L3 |
| 3 | H1, H2, H4(server), M1, M6, L1, L6, L7 |
| 4 | tests (validates all) |
| 5 | L4, L5 |
