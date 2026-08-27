# Known issues

Long-lived issues and deferred design decisions that aren't bugs with an
obvious fix. Each entry records the symptom, what dany does today, and why
it hasn't been changed — so the next person to hit it doesn't re-derive it.

## Resolver-side blind spots look like domain-side failures

**Status:** open, not currently handled. Deliberate for now — see the
trade-off below.

### Symptom

Some recursive resolvers systematically refuse or mangle particular RR
types, independently of the domain being queried. The instance that
surfaced this: `systemd-resolved` (the `127.0.0.53` stub) returns SERVFAIL
for every `DNSKEY` query, for any domain, signed or not:

```
$ dig +noall +comments DNSKEY cloudflare.com @127.0.0.53 | sed -n 2p
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 37968

$ dig +noall +comments DNSKEY cloudflare.com @8.8.8.8 | sed -n 2p
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49528   (2 answers)
```

dany reports this faithfully, per record type:

```
$ dany -t A,DNSKEY -s 127.0.0.53 cloudflare.com
A		104.16.132.229
A		104.16.133.229
Error on DNSKEY lookup for "cloudflare.com": SERVFAIL
```

### Why that's a problem

The rcode is surfaced; the *attribution* is not. A resolver-limitation
SERVFAIL is byte-identical to a zone-side SERVFAIL, so a consumer reading
dany's output cannot tell "this zone is broken" from "this resolver won't
answer this type". Four gaps, worst first:

1. **No attribution.** Structured output records `query.server`, so a JSON/YAML
   consumer can at least correlate errors with the resolver that produced
   them. Text output can't: the `resolver selected` line is `slog.Info`,
   suppressed by the default `Warn` handler, and skipped entirely when
   `-s/--server` is given.
2. **NODATA is invisible.** A resolver that strips DNSSEC by answering
   NOERROR with an empty answer section (rather than SERVFAIL) produces
   *no output at all* — no answer, no error — which is indistinguishable
   from a genuinely unsigned zone. See "Error handling" below.
3. **Multi-resolver runs scatter it.** `Resolvers.Next()` round-robins, so
   one blind resolver in a pool of N silently degrades ~1/N of queries,
   looking exactly like ordinary transient noise.
4. **Exit status is always 0.** DNS-level errors never reach the `os.Exit(1)`
   path in `cmd/dany/main.go`; a script must parse the output to notice.

### Error handling today, for reference

All rcode handling lives in `dnsLookup` (`dany.go`):

| Wire outcome | dany behaviour |
| --- | --- |
| Transport failure (timeout, refused, reset) | `QueryError{Code:"EXCHANGE_ERROR"}` |
| Any rcode != NOERROR | `QueryError{Code: <rcode name>}`, e.g. `SERVFAIL`, `REFUSED`; `RCODE_<n>` if unnamed |
| NOERROR + answers | `[]Answer` |
| NOERROR + zero answers (NODATA) | nothing — no answer, no error (except `--usd` probes, which emit `Answer{Empty:true}`) |
| Unknown type name | `UNSUPPORTED_TYPE`, never hits the wire |
| IDNA-invalid name | `INVALID_NAME`, fatal for the whole query |
| 10s wall-clock timeout | in-flight results dropped silently — neither answer nor error |

Only NXDOMAIN and SERVFAIL wrap a sentinel (`ErrNXDomain` / `ErrServFail`)
for `errors.Is`; other rcodes carry the code string alone.

### Possible fix: a pre-flight resolver check

Probe each resolver at startup against a known-good, richly-provisioned
domain, and report **one resolver-level error alongside the results**
instead of a scatter of per-RR SERVFAILs. Key design points, learned from
implementing exactly this check in a downstream batch consumer of the dany
library:

- **Demand records, not responsiveness.** The bar must be "returned an RR",
  because the NODATA-stripping failure mode passes any check that only
  looks for a non-error response.
- **Probe every resolver in the pool,** not just the first — see gap 3.
- **Two probe domains, either one passing.** Otherwise the tool breaks when
  a third party has a bad day. `cloudflare.com` and `iana.org` work well:
  both are DNSSEC-signed and publish a full spread of record types, so
  every probed type can be demanded of both.
- **An escape hatch** (e.g. `--no-preflight`) for air-gapped or
  deliberately odd setups.

### Why dany doesn't do this today

Cost/benefit differs sharply by usage mode. dany is overwhelmingly used for
**one-off interactive queries**, where a pre-flight adds a full extra
multi-type round trip (8-ish types x up to 2 probe domains) to every
invocation — a large relative slowdown, to guard against a condition the
user can usually diagnose from the error line in front of them.

For **batch processing** the trade-off inverts: the probe amortizes to
nothing across thousands of queries, and the failure mode it catches
(silently wrong results across the whole run) is exactly the one that's
hard to notice at scale. That's why the check belongs in the batch
consumer rather than in the library.

If this is revisited for dany, the natural shape is opt-in rather than
default — a `--preflight` flag, or automatic only when reading hostnames
from stdin / a file (i.e. when the query count makes it cheap).
