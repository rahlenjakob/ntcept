# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`ntcept` is a network debugger that intercepts, inspects, and modifies the network traffic of a
supervised process tree — no code changes, no SDK, no proxy config, whatever language the program
is written in. It is built to be driven by coding agents: every command emits JSON. It is a single
Go binary (`cmd/ntcept`, module `github.com/rahlenjakob/ntcept`). Proprietary, not open source.

## Commands

```bash
go build -o ntcept ./cmd/ntcept          # build; untagged builds identify by commit sha
go build -ldflags "-X main.Version=v0.1.0" -o ntcept ./cmd/ntcept   # stamp a release version

go test -race ./...                       # everything, including the interception engine
go test -short ./...                      # skips e2e tests (which build the binary)
go test -race ./internal/capture/         # one package
go test -race -run TestName ./internal/capture/   # one test
go test ./internal/proxy ./internal/tunnel ./internal/redact -run '^$' -bench . -benchmem   # benchmarks

gofmt -l .                                # CI fails on unformatted files (examples/ excluded)
go vet ./...
go mod tidy                               # CI fails if go.mod/go.sum aren't tidy
```

CI (`.github/workflows/ci.yml`) runs vet+gofmt, `go test -race` on ubuntu and macos, dedicated
**tunnel-linux** and **tunnel-macos** jobs that exercise the real attach path (these are where
platform bugs surface), cross-builds for linux/darwin × amd64/arm64, and non-gating benchmarks.

The tunnel jobs assert availability via `ntcept doctor --json` — a rule that is merely *set up* is
not one that *routes*, so doctor measures rather than assumes. Preserve that when touching attach code.

macOS work: `sudo ntcept install` is a one-time privileged setup (root-owned helper + scoped
sudoers grant); `sudo ntcept uninstall` reverses it. Linux needs no privileges where unprivileged
user namespaces are enabled.

## Architecture

**One interception engine, two platform attaches.** The design principle throughout: intercept
*below the socket API* of one process tree so routing works for any language/HTTP client, and there
is **one attach with no silent fallback** — a machine that can't tunnel is refused, never downgraded
to a proxy that would miss traffic.

Request flow, bottom to top:

- **Attach (platform-specific, get packets into the engine):**
  - `internal/netns` — Linux: runs the child in its own network namespace whose only route is a
    TUN device ntcept holds. Not a container; same filesystem/libraries/env. `*_linux.go` /
    `*_other.go` build tags.
  - `internal/pftun` — macOS: creates a utun device and tells `pf` to route one process *group*'s
    outbound traffic into it. Scoping is by process group id. `*_darwin.go` build tags. Supporting:
    `internal/pfnat` (asks pf the original destination of a redirected connection, so one rule
    covers every port), `internal/procs` (which process owns a loopback connection, so unwatched
    traffic is passed through untouched).
- **`internal/tunnel`** — the shared engine: a userspace TCP/IP stack (gVisor netstack) that
  *terminates* every connection the supervised process opens and re-originates it from ntcept's own
  side. Both platforms behave identically above the device; a bare `socket.connect()` is intercepted
  exactly like `fetch`.
- **`internal/proxy`** — the interception plane above the stack: accepts CONNECT/SOCKS5/transparent
  TLS-by-SNI/plain HTTP, then decodes HTTP/1.1, HTTP/2, WebSocket, or relays raw TCP with decoders
  attached.
- **`internal/ca`** — the scoped CA used to read TLS. Generated once, kept in `~/.ntcept`, **never**
  added to the system trust store; the child is pointed at it via trust env vars scoped to that one
  run (`internal/attach` sets these). A runtime that pins its own roots stays an opaque passthrough.
- **`internal/decode`** — stateful protocol decoders detected **by content, not port**: Postgres
  (incl. bound parameters + typed errors), MySQL, Redis (RESP2/RESP3), MongoDB (OP_MSG), plus DNS
  and a raw fallback. `sniff.go` does content detection. Each decoder is built on a byte-stateless
  `parseOne`, which backs both `Feed` (display) and the `Framer` interface (`Frame` returns exact
  message byte-spans so the relay can hold/drop/edit/answer one message at a time; `ok=false` means
  the stream stopped being decodable, e.g. a Postgres TLS upgrade). Postgres also has response
  synthesis (`SynthError` → `ErrorResponse`+`ReadyForQuery`) for local `respond`.
- **`internal/redact`** — masks credential headers and secret-looking fields **on the way into**
  the capture buffer only; the forwarding path sees real bytes and retains nothing. Masked values
  become a stable fingerprint (`«name/fingerprint»`) so "same token?" stays answerable.
- **`internal/capture`** — a bounded, redacted, in-memory ring of flows (`store.go`), plus the
  hold/verdict queue (`hold.go`) for intercept mode (`Held`/`Verdict` cover both HTTP exchanges and
  message-level database/TCP frames). Written by one goroutine per connection, read by the control
  plane — hence `-race` in CI. The HTTP hold path lives in `proxy/http.go`; the framed TCP hold path
  (frame → park → forward/drop/edit/respond, with a coalesced writer) lives in `proxy/raw.go`.
- **`internal/control`** — the local HTTP API the CLI and web UI both call. **Loopback-only**
  (`loopbackOnly` middleware) because the capture buffer holds credentials for every service. SSE
  at `/events` for live streaming.
- **`internal/ui`** — the inspector web UI, embedded in the binary.
- **`internal/probe`** — answers "will this runtime's TLS be readable here?" by *trying* it; backs
  `ntcept doctor`.

**Sessions & the CLI↔engine split.** `ntcept run` starts an engine + control server; every other
command (`ls`, `show`, `intercept`, `forward`, …) is a thin CLI client that talks to a running
session's loopback control API. Sessions are discovered via one JSON file per running session under
`~/.ntcept/sessions/` (`internal/attach/session.go`: `SessionsDir`, `ListSessions`, `ResolveSession`
prunes dead ones). `cmd/ntcept/*.go` is one file per subcommand; `register.go` is the command table
and `main.go` dispatches (including two hidden privileged helper re-entry points via `HelperArg`).

## Conventions

- Platform code uses build-tag file suffixes: `_linux.go`, `_darwin.go`, `_other.go`. Keep the
  `_other.go` stub in sync so cross-builds for all four targets keep compiling.
- Every CLI command supports `--json`; `takePositionals` in `main.go` lets flags and positionals
  appear in either order.
- `examples/` is excluded from gofmt checks — it's a standalone Next.js demo app (`examples/nextjs`,
  its own `package.json`), not part of the Go module.
