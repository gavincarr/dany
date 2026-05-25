# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository layout

Two CLI binaries share one library:

- `dany.go` (repo root) — package `dany`, the shared DNS query engine. Exposes `RunQuery` (typed-ANY aggregation) and `RunNXQuery` (NXDOMAIN probing), plus the `Query`, `Resolvers`, `Result` types and the `DefaultRRTypes` / `SupportedRRTypes` / `NXTypes` / `SupportedUSDs` constants. Imported by the CLIs as `github.com/gavincarr/dany`.
- `cmd/dany/main.go` — the `dany` CLI: simulates DNS `ANY` queries by firing the configured RR types (default `SOA,NS,A,AAAA,MX,TXT`) concurrently and aggregating tab-separated results.
- `cmd/dnx/main.go` — the `dnx` CLI: takes hostnames (args or stdin) and reports those that return NXDOMAIN. For safety it runs all `NXTypes` (`MX,NS,SOA`) concurrently per hostname and only reports a host as NX if *every* type returns NXDOMAIN (`RunNXQuery` returns `len(NXTypes) - nxcount`).

Module path: `github.com/gavincarr/dany` (Go 1.13, only deps are `miekg/dns` and `jessevdk/go-flags`).

## Build / test commands

```bash
# Build both binaries (run from each cmd/ dir)
cd cmd/dany && go build
cd cmd/dnx  && go build

# Run all (offline) tests
go test ./...

# Also run the live-DNS smoke tests (requires network + 8.8.8.8 reachable)
go test -tags integration ./...

# Run one test
go test -run TestRunQuery_Basic ./...
```

## Test layout

Default `go test ./...` is **fully offline**. The library's `RunQuery` and `RunNXQuery` are exercised against `internal/testdns`, an in-process `dns.Server` that returns canned RRs you `Add()` per (name, type). Real-world DNS drift can never break the default suite.

The two `cmd/*/integration_test.go` files are gated behind `//go:build integration` and hit real DNS (8.8.8.8) for a stable RFC 2606 reserved domain. They're a wire-format smoke check, not regression coverage — keep them small.

## Architecture notes worth knowing before editing `dany.go`

- **TCP by default.** `RunQuery` sets `client.Net = "tcp"` unless `Query.Udp` is true, because TXT/DNSKEY responses are often too big for UDP. Don't flip this default casually.
- **Concurrency model.** `RunQuery` fans out one goroutine per RR type into a buffered `resultStream`; the main loop drains exactly `count` results or bails at a 10s wall-clock timeout (`timeoutSeconds`). Per-client dial/read/write timeout is `timeoutSeconds/2`. Same shape in `RunNXQuery` over `NXTypes`.
- **Adding a new RR type** requires three coordinated edits in `dany.go`: add to `SupportedRRTypes`, add a `case "X":` in `lookup()`, and add a `formatX()` helper. Then add a golden-file test case.
- **CNAME handling** is implicit: `dnsLookup` transparently re-queries the CNAME target for any non-CNAME request type, so `formatX` helpers never see CNAME answers.
- **PTR enrichment** (`-p/--ptr`) runs *after* A/AAAA results return, via `ptrLookupAll` → goroutine-per-IP `ptrLookupOne`, and is appended to A/AAAA lines (not emitted as separate PTR records).
- **Resolvers** rotate round-robin via `Resolvers.Next()`. With multiple resolvers, `dany` re-picks per hostname; `dnx` re-picks per goroutine. `dnx`'s overall concurrency cap is `opts.Concurrency * resolvers.Length`.

## CLI quirks (intentional, don't "fix")

`cmd/dany` still accepts two **deprecated** positional-arg forms and prints a deprecation warning at runtime:

- `@<ip>` — server, replaced by `-s/--server`
- bare `<RR>[,<RR>,...]` — types list, replaced by `-t/--types`

The detection logic in `parseArgs` (regex on `@` prefix, `.`, and `,`, plus a typeMap lookup) is what enables this. The `testMode` bool on `parseOpts`/`parseArgs` exists solely to suppress the warning text during tests — keep that plumbing if you refactor.
