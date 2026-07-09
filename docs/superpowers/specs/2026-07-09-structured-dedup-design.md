# Design: dedup structured (JSON/YAML) output on RRset identity

**Date:** 2026-07-09
**Status:** Approved (design), pending implementation plan

## Motivation

dany's text renderer (`Render`) deduplicates output: a `seen` map keyed on the
fully-formatted line drops any repeat (dany.go:449-455). The structured
renderers do not — `BuildOutput` emits exactly one `OutputAnswer` per `Answer`
with no dedup anywhere in `render_json.go`.

The divergence originates in `lookup` (dany.go:266-268), which builds one
`Answer` per RR in `resp.Answer`. When an authoritative response's answer
section carries the same resource record twice — a genuine wire duplicate,
which occurs in the wild (e.g. a domain owner adding the "same" TXT record
twice via a control panel) — dany produces two identical `Answer`s. Text folds
them; JSON/YAML keep both.

Per RFC 2181 §5, an RRset is a *set*: duplicate RRs within it carry no
additional meaning and receivers may discard them. Structured consumers that
count or join records should not have to defend against phantom duplicates, and
dany already aims for "clean, deterministic, byte-comparable" structured
output.

## Scope

- **In:** `BuildOutput` deduplicates its assembled `[]OutputAnswer` on RRset
  identity, keeping the lowest-TTL copy. Covers JSON and YAML (shared
  envelope).
- **Out (unchanged):** the text renderer (already dedups); the query engine
  (`lookup`/`RunQuery` still emit one `Answer` per wire RR — dedup is a
  render-time concern); `Output.Errors` (not part of this change).
- **Not in this change:** any `--raw` / `--no-dedup` escape hatch (YAGNI —
  `dig` is the tool for inspecting raw wire, including duplicates).

## Dedup key

`(Type, Name, Class, Rdata)` — full RRset identity, TTL excluded.

- Collapses only records that are identical DNS RRs.
- **Keeps name-distinct records:** `--www` `www.<host>` vs apex (different
  `Name`), multiple PTRs per IP (different `Rdata`), CNAME hops (different
  `Name`/`Rdata`) all survive. This preserves the higher fidelity that makes
  structured output more useful than text — structured dedup must NOT mimic
  text's line-key, which would fold www/apex.
- **`present_empty` answers:** `Rdata == ""`, so an empty-marker and a real TXT
  for the same name differ by rdata and both survive; two empty markers for one
  name cannot occur (one probe per USD label).
- **TTL:** within a valid RRset all TTLs are equal (RFC 2181 §5.2); if a buggy
  server sends differing TTLs for otherwise-identical RRs, dedup keeps the
  lowest, matching §5.2's "treat as the minimum TTL."

## Mechanism

Dedup runs **after** the existing sort in `BuildOutput`, not before:

- The sort orders answers by `(Type, Rdata, Name, TTL)` (render_json.go:194-206,
  unchanged). Among records sharing the dedup key `(Type, Name, Class, Rdata)`,
  the first in sorted order therefore has the lowest TTL.
- Walk the sorted slice with a `seen map[string]bool` keyed on
  `Type + "\x00" + Name + "\x00" + Class + "\x00" + Rdata` (NUL separators to
  avoid field-boundary collisions), appending an answer only the first time its
  key is seen. First-seen ⇒ min TTL, deterministically, every run.

Dedup **before** the sort would keep whichever duplicate the concurrent fan-out
delivered first — a nondeterministic TTL. After-sort first-seen is
deterministic.

Rationale for a `seen` map (vs adjacent-pair comparison): robust regardless of
sort-order subtleties (the sort key omits `Class`, so records identical except
for `Class` are not guaranteed adjacent; a `seen` map is correct either way,
and `Class` is effectively always `IN` in practice).

## Data model

No struct changes. `OutputAnswer` and `Output` are untouched. **`SchemaVersion`
stays `1`** — the envelope shape is identical; consumers simply receive no
phantom duplicate elements. This is a data-quality fix, not a
backwards-incompatible schema change. The changelog stanza records the
behavior change.

## Testing

- **Unit (render_json_test.go):**
  - Two identical `Answer`s (same Name/Type/Class/Rdata) with differing TTLs →
    exactly one `OutputAnswer`, at the **minimum** TTL.
  - Same Rdata, different Name (simulating www/apex) → **both** kept.
  - Same Name/Type, different Rdata (e.g. two distinct TXT strings) → **both**
    kept.
  - YAML is covered transitively via the shared `BuildOutput` envelope; add a
    confirming YAML assertion only if cheap.
- **End-to-end (dany_test.go):** `testdns.Add` the same RR twice (`Add`
  appends without dedup, so the canned response carries it twice) → `RunQuery`
  → assert the structured output (`BuildOutput`/`RenderJSON`) has **one** entry,
  and `Render` text still has one. Confirms the wire→render path collapses a
  real duplicate.
- **Determinism:** existing `TestBuildOutput_DeterministicOrder` /
  `TestBuildOutput_NaturalNumericOrder` must stay green (dedup preserves sort
  order).

## Docs

- Update `CLAUDE.md`: the "Data vs. rendering" / structured-determinism notes
  gain a line that `BuildOutput` dedups its answers on RRset identity
  `(Type, Name, Class, Rdata)`, keeping the lowest TTL — parallel to the text
  renderer's line-level dedup.
- Changelog stanza for the release (minor bump, `1.5.0`).

## Out of scope / future

- Deduping `Output.Errors` (no evidence of duplicate errors mattering).
- Any user-facing flag to disable dedup or emit raw wire.
