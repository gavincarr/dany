# Design: surface USD empty-non-terminal existence (DKIM signal)

**Date:** 2026-07-08
**Status:** Approved (design), pending implementation plan

## Motivation

DKIM keys always live at `<selector>._domainkey.<domain>`; there is no valid
record at the bare `_domainkey.<domain>` node, and selectors are not
enumerable via DNS. So dany's existing `_domainkey` USD probe (a plain TXT
lookup) almost never returns a record and today renders nothing.

But a bare `_domainkey.<domain>` query still carries signal in its **response
code**, not its contents:

- **NXDOMAIN** — the name (and everything below it, per RFC 8020) does not
  exist. The domain publishes no DKIM at all.
- **NOERROR + empty answer (NODATA)** — the name exists as a node in the tree
  but has no records of the queried type. This is an *empty non-terminal*: the
  node exists only because at least one name below it exists — i.e. one or more
  `<selector>._domainkey.<domain>` records. **DKIM is deployed.**

An empirical sample (~150 domains) showed ~20% returning the NODATA case. dany
currently collapses NODATA and NXDOMAIN to identical empty output — for USD
probes it sets `IgnoreErrors = true` and only renders record-bearing answers —
so this "DKIM is configured" signal is discarded before any renderer sees it.

This design surfaces the NODATA / empty-non-terminal case as a first-class
answer, without reporting the NXDOMAIN (absent) case (which would be noise in a
tool whose job is showing what exists).

## Scope

- **In:** USD probes only (`--usd`: `_dmarc`, `_domainkey`, `_mta-sts`). Any of
  them returning NODATA emits a new "present; no records" answer. In practice
  `_domainkey` is the near-exclusive beneficiary; `_dmarc`/`_mta-sts` almost
  always carry a real TXT record.
- **Out (omitted, unchanged):** NXDOMAIN / SERVFAIL / other non-success rcodes
  on any query → render nothing, exactly as today.
- **Out (unchanged):** every non-USD query. A normal `-t A`/`-t TXT`/etc. query
  that hits NODATA behaves byte-for-byte as it does today (renders nothing).
- **Not in this change:** querying a user-supplied DKIM selector (a future
  `--dkim <selector>` flag) and dictionary-probing common selectors. The
  existence probe is the cheap first layer; selector querying can layer on top
  later.

## Three-way verdict

| Rcode / answer                     | Meaning                       | Rendered?                    |
|------------------------------------|-------------------------------|------------------------------|
| NXDOMAIN (and other error rcodes)  | absent                        | no (omitted, as today)       |
| NOERROR + records                  | present, with record          | yes, as today (record shown) |
| NOERROR + empty (NODATA)           | present; no records (new)     | **yes (new synthetic answer)** |

Only the third row is new output.

## Detection

`dnsLookup` already separates the cases at exactly the point we need, even with
`IgnoreErrors = true`:

- NXDOMAIN/SERVFAIL under `ignoreErrors` → returns `(nil, nil)` (dany.go:192).
  In `lookup`, `resp == nil` → no answer emitted. Omitted, as desired.
- NODATA is `RcodeSuccess` with an empty answer section, so it never hits the
  rcode branch — it returns `(resp, nil)` with non-nil `resp` (dany.go:226) and
  `len(resp.Answer) == 0`. This is the detectable hook.

No change to `dnsLookup` is required.

`lookup` gains a `usd bool` parameter (unexported function — no public API
change). The three call sites in `RunQuery` pass: types → `false`, USD fan-out
(dany.go:625) → `true`, www → `false`. After the existing `resp == nil` guard,
when the record loop produced no answers:

```go
if usd && len(resp.Answer) == 0 {
	answers = append(answers, Answer{Type: rrtype, Hostname: hostname, Empty: true})
}
```

Because `resp` is non-nil only for `RcodeSuccess`, this fires exactly on
NODATA and never on NXDOMAIN/SERVFAIL. Scope stays confined to `--usd`.

## Data model

Add one field to the internal `Answer` struct (dany.go:113):

```go
type Answer struct {
	Type     string
	Hostname string
	RR       dns.RR
	Empty    bool // present-empty (NODATA); RR is nil when true
}
```

`Empty == true` means "name exists, no records of the queried type." `RR` is
`nil`, so every consumer must check `Empty` before dereferencing `RR`.

## Text rendering

`formatAnswer` (dany.go:540) gets a guard at the top, before the `RR.(type)`
switch (which would nil-panic on a nil `RR`):

```go
if a.Empty {
	return fmt.Sprintf("%s\t\t%s [present; no records]\n", a.Type, dns.Fqdn(a.Hostname))
}
```

Non-tagged output:

```
TXT		_domainkey.example.com. [present; no records]
```

The owner name is included in the line because non-tag text mode does not
otherwise show it, and unlike a real `_dmarc` record there is no rdata value to
identify the name. In `--tag` mode the hostname prefix is added by `Render` as
usual, so the name appears twice — acceptable, and consistent with how other
answers behave under `--tag`.

The line flows through `Render`'s existing dedup + natural sort unchanged (it
is just another string line).

## JSON / YAML rendering

Add one optional field to `OutputAnswer` (render_json.go:46):

```go
PresentEmpty bool `json:"present_empty,omitempty" yaml:"present_empty,omitempty"`
```

`buildAnswer` (render_json.go:235) intercepts `Empty` before `marshalData`
(which would drop a nil-RR answer via its `ok == false` path):

```go
if a.Empty {
	return OutputAnswer{Type: a.Type, Name: dns.Fqdn(a.Hostname), PresentEmpty: true}, true
}
```

Output:

```json
{"type":"TXT","name":"_domainkey.example.com.","present_empty":true}
```

Decisions:

- **`type` stays `"TXT"`** (the queried type), consistent with how CNAME chain
  hops keep the queried type. `present_empty` is the discriminator; no synthetic
  RR type is invented.
- `ttl`/`class`/`rdata` are zero/empty and `data` is null — there is no RR.
  Consumers key on `present_empty` and ignore those fields for such answers.
- **`omitempty`** means existing record-bearing answers are completely
  unchanged — no `present_empty` key appears on them. The change is purely
  additive, so **`SchemaVersion` stays at 1**.
- Sort order (BuildOutput sorts by Type, then Rdata, Name, TTL) is stable: an
  empty answer has `Type "TXT"`, `Rdata ""`, so it sorts first among TXT
  answers deterministically.

## Testing

- **Offline `internal/testdns`:** add a zone where `sel._domainkey.<host>` has a
  TXT record but `_domainkey.<host>` itself has none, so a TXT query at
  `_domainkey.<host>` returns NOERROR/NODATA (empty non-terminal). Confirm the
  in-process server returns `RcodeSuccess` with an empty answer for the parent.
  - If `testdns` cannot naturally model an empty non-terminal, add an explicit
    NODATA canned response for the parent name (RcodeSuccess, no answer). Verify
    during implementation.
- **Text golden test:** `--usd` run yields the `[present; no records]` line for
  the empty-non-terminal name, and no line for an NXDOMAIN USD name.
- **Structured test:** extend the `TestBuildOutput_*` coverage with an `Empty`
  answer, asserting the `present_empty: true` OutputAnswer shape (covers JSON
  and, transitively, YAML — shared envelope).
- **Negative test:** a non-USD query that hits NODATA emits no answer
  (guards the USD-only scope).

## Docs

- Update `CLAUDE.md`: note the empty-non-terminal behavior in the USD section
  and the new `Empty` discriminator (parallel to the CNAME chain-hop note).
- Update `--usd` help text in `cmd/dany/main.go` to mention that USD probes now
  report a name that exists without records (e.g. `_domainkey` when DKIM
  selectors are present).

## Out of scope / future

- `--dkim <selector>` (repeatable) to query user-supplied selectors and return
  the DKIM public keys.
- Optional dictionary-probe mode over common vendor selectors (`google`,
  `selector1`/`selector2`, `k1`/`k2`, `s1`/`s2`, ...).
- Reconsidering whether `_dmarc`/`_mta-sts` should surface an empty-non-terminal
  verdict at all (they normally carry records; low value, but the mechanism
  applies uniformly and costs nothing extra).
