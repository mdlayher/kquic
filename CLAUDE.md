# CLAUDE.md

Guidance for AI agents working in this repository.

## Verification

Run these on every Go change, alongside `go build` and `go test`:

- `gofumpt -l .` (CI enforces gofumpt; keep stderr visible so a bad path
  can't look like a clean run)
- `go vet ./...`
- `staticcheck ./...` (CI enforces it; if the system binary is too old for
  the toolchain, use `go run honnef.co/go/tools/cmd/staticcheck@latest ./...`)
- `gopls check -severity=hint <changed files>` (catches unusedfunc,
  modernize, typeargs, and other hint-level findings vet and staticcheck
  miss)
- `GOOS=darwin go build ./...` and `GOOS=windows go build ./...` (the
  package is Linux-only at runtime, but the kquic_others.go stubs must keep
  it compiling everywhere; CI enforces both)

The development machine has no kernel QUIC module, so the TestIntegration*
tests skip locally. To exercise them, build a test binary and run it on the
quicdev machine: `go test -c`, `scp` the binary to `quicdev:tmp/`, then run
it over `ssh quicdev` (no sudo is available there). Both the loopback and the
Cloudflare dial test must pass as an unprivileged user.

## Code style

Blank lines:

- Leave an empty line after a closing brace and after a `var (` / `const (`
  block when another statement or declaration follows at the same indent
  level. Keep `}`, `)`, `case`, `default:`, and `else` continuations tight
  against what precedes them.
- Break dense bodies, especially tests, with blank lines at logical seams:
  between multi-line handler fields in a config struct literal, between one
  actor's cluster of steps and the next, before non-blocking assertion
  checks and final verdict assertions, and between constructing a fixture
  and the next setup statement.
- A single multi-line struct literal is one logical unit: never split it
  mid-literal.

Declaration layout:

- A type and all of its methods stay contiguous. Supporting enums and codes
  go before the type that uses them. Encoder/decoder pairs sit together
  (e.g. `streamInfoCmsg` beside `parseStreamInfo`).
- Paired values described by one doc comment share one declaration
  (`local, remote netip.AddrPort`). A doc comment attaches to the
  declaration, so separate lines leave every name after the first
  undocumented in go doc and IDE hover.
- Exception: files deliberately organized by theme or flow keep that layout
  (e.g. `handshake_linux.go` in handshake flow order, and
  `internal/quicsys/uapi_linux.go` mirroring the kernel UAPI header).
- Keep groups of one-line method stubs compact and aligned, with no blank
  lines between them.

Exported doc comments:

- State the contract directly, self-contained: no references to design
  documents that live outside this repository. When a comment needs a
  decision's rationale, carry the one-sentence version inline.
- Plain prose: short sentences, no em dashes. Prefer separate sentences, a
  colon, or "such as X or Y" over parenthetical asides. Internal comments
  are exempt.

Markdown documents:

- Wrap prose at 80 columns for terminal splits. Table rows and badge lines
  are exempt: they cannot wrap.

## Tests

- Never sleep in tests. Every awaited condition must be signaled; poll
  loops with sleep intervals count as sleeping.
- Independent scenarios are individual top-level Test functions. `t.Run`
  is for a table's cases and for subtests sharing a fixture built by the
  parent, such as one Test with per-case setup on a shared listener.
- Test scenarios, not coverage. Cover paths a plausible real-world scenario
  hits, framed on behavior; 100% coverage is not a goal.
- Test helpers, rig types, and shared fixtures go at the end of test files,
  after every Test/Fuzz/Benchmark/Example function. Shared consts may stay
  at the top.
- Integration tests that need kernel QUIC support call `probe(t)` first so
  they skip cleanly on machines without the module. Network-dependent tests
  also skip under `testing.Short()` and on DNS or connectivity failure.
