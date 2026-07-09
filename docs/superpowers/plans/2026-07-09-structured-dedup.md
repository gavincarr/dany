# Structured-Output RRset Dedup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deduplicate structured (JSON/YAML) output on RRset identity so genuine wire-duplicate RRs collapse to one entry, matching the text renderer and RFC 2181 §5.

**Architecture:** A single dedup pass in `BuildOutput` (render_json.go), applied after the existing answer sort, using a `seen` map keyed on `(Type, Name, Class, Rdata)`. First-seen-wins over the sorted slice keeps the lowest-TTL copy deterministically. No struct or schema changes.

**Tech Stack:** Go 1.25, `github.com/miekg/dns`, `gopkg.in/yaml.v3`; in-process `internal/testdns` for offline tests.

**Spec:** `docs/superpowers/specs/2026-07-09-structured-dedup-design.md`

## Global Constraints

- Default `go test ./...` must stay fully offline (`internal/testdns`, never real DNS).
- **`SchemaVersion` stays `1`** (render_json.go:16) — the envelope shape is unchanged; dedup only removes phantom duplicate elements. Do NOT bump it.
- Dedup key is exactly `(Type, Name, Class, Rdata)` — TTL excluded. Keep the lowest-TTL copy.
- Dedup must NOT collapse name-distinct records: `--www` www/apex (different `Name`), PTRs-per-IP (different `Rdata`), CNAME hops (different `Name`/`Rdata`) all survive.
- Text renderer (`Render`) is unchanged (it already dedups).
- No user-facing flag to disable dedup (YAGNI).
- Conventional Commits for every commit. Do NOT `git push`.
- TDD: failing tests first, watch them fail, implement minimally, watch them pass.

---

### Task 1: Dedup answers in BuildOutput (+ unit and end-to-end tests)

Adds the dedup pass and all tests: three unit tests over `BuildOutput` (identical-RR collapse with min-TTL, name-distinct kept, rdata-distinct kept) and one end-to-end test driving a duplicated wire RR through `RunQuery` → both renderers.

**Files:**
- Modify: `render_json.go` — `BuildOutput`, insert dedup after the answer `sort.Slice` (immediately after render_json.go:207, before the error `sort.Slice`)
- Test: `render_json_test.go` — three new `TestBuildOutput_Dedup*` tests
- Test: `dany_test.go` — new `TestRunQuery_StructuredDedupsWireDuplicate`

**Interfaces:**
- Consumes: `BuildOutput(answers []Answer, q *Query, errs []error) *Output`, `OutputAnswer{Type, Name, TTL, Class, Rdata, Data, PresentEmpty}`, `Render(answers []Answer, tagHostname bool) string`, `RunQuery(q *Query) ([]Answer, []error)`, `testdns.New`, `testdns.MustRR`, `Answer{Type, Hostname, RR}`.
- Produces: no new exported symbols; `BuildOutput`'s `out.Answers` is deduplicated on `(Type, Name, Class, Rdata)`.

- [ ] **Step 1: Write the failing unit tests**

In `render_json_test.go`, add:

```go
func TestBuildOutput_DedupsIdenticalRRsKeepsMinTTL(t *testing.T) {
	// Two identical RRs differing only in TTL (a wire duplicate) collapse to
	// one answer, keeping the lowest TTL.
	q := &Query{Hostname: "example.com", Types: []string{"A"}}
	a1 := Answer{Type: "A", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN A 1.2.3.4")}
	a2 := Answer{Type: "A", Hostname: "example.com", RR: testdns.MustRR("example.com. 600 IN A 1.2.3.4")}

	out := BuildOutput([]Answer{a2, a1}, q, nil) // higher TTL passed first
	if len(out.Answers) != 1 {
		t.Fatalf("Answers len = %d, want 1 (deduped): %+v", len(out.Answers), out.Answers)
	}
	if out.Answers[0].TTL != 300 {
		t.Errorf("TTL = %d, want 300 (lowest of the duplicate)", out.Answers[0].TTL)
	}
}

func TestBuildOutput_DedupKeepsNameDistinct(t *testing.T) {
	// Same rdata, different owner names (apex vs www) are NOT duplicates.
	q := &Query{Hostname: "example.com", Types: []string{"A"}}
	apex := Answer{Type: "A", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN A 1.2.3.4")}
	www := Answer{Type: "A", Hostname: "www.example.com", RR: testdns.MustRR("www.example.com. 300 IN A 1.2.3.4")}

	out := BuildOutput([]Answer{apex, www}, q, nil)
	if len(out.Answers) != 2 {
		t.Fatalf("Answers len = %d, want 2 (distinct names kept): %+v", len(out.Answers), out.Answers)
	}
}

func TestBuildOutput_DedupKeepsRdataDistinct(t *testing.T) {
	// Same name/type, different rdata (two TXT strings) are NOT duplicates.
	q := &Query{Hostname: "example.com", Types: []string{"TXT"}}
	t1 := Answer{Type: "TXT", Hostname: "example.com", RR: testdns.MustRR(`example.com. 300 IN TXT "a"`)}
	t2 := Answer{Type: "TXT", Hostname: "example.com", RR: testdns.MustRR(`example.com. 300 IN TXT "b"`)}

	out := BuildOutput([]Answer{t1, t2}, q, nil)
	if len(out.Answers) != 2 {
		t.Fatalf("Answers len = %d, want 2 (distinct rdata kept): %+v", len(out.Answers), out.Answers)
	}
}
```

- [ ] **Step 2: Write the failing end-to-end test**

In `dany_test.go`, add:

```go
func TestRunQuery_StructuredDedupsWireDuplicate(t *testing.T) {
	srv := testdns.New(t)
	// Register the same TXT twice → testdns.Add appends, so the canned
	// response carries the record twice (a wire duplicate).
	srv.Add(testdns.MustRR(`example.com. 300 IN TXT "v=spf1 -all"`))
	srv.Add(testdns.MustRR(`example.com. 300 IN TXT "v=spf1 -all"`))

	q := &Query{Hostname: "example.com", Types: []string{"TXT"}, Server: srv.Addr}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}

	// Text already dedups.
	if got := Render(answers, false); got != "TXT\t\tv=spf1 -all\n" {
		t.Errorf("text render = %q, want single deduped line", got)
	}

	// Structured must now also dedup.
	out := BuildOutput(answers, q, nil)
	txt := 0
	for _, a := range out.Answers {
		if a.Type == "TXT" {
			txt++
		}
	}
	if txt != 1 {
		t.Errorf("structured TXT answers = %d, want 1 (deduped): %+v", txt, out.Answers)
	}
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test -run 'TestBuildOutput_Dedup|TestRunQuery_StructuredDedupsWireDuplicate' ./...`
Expected: FAIL — `TestBuildOutput_DedupsIdenticalRRsKeepsMinTTL` reports `Answers len = 2, want 1` and `TestRunQuery_StructuredDedupsWireDuplicate` reports `structured TXT answers = 2, want 1`. (The two "distinct kept" tests already pass — they assert nothing gets collapsed.)

- [ ] **Step 4: Implement the dedup pass**

In `render_json.go`, insert immediately after the answer `sort.Slice(out.Answers, ...)` block (after its closing `})` at ~line 207) and before the error `sort.Slice`:

```go
	// Dedup on RRset identity (Type, Name, Class, Rdata). An RRset is a set,
	// so duplicate wire RRs carry no meaning (RFC 2181 §5). Runs after the
	// sort above, so the first occurrence of each key is the lowest-TTL copy
	// (TTL is the sort's final tiebreaker) — matching RFC 2181 §5.2's "treat
	// as the minimum TTL". Name-distinct records (www/apex, per-IP PTRs,
	// CNAME hops) differ in Name or Rdata and are preserved.
	if len(out.Answers) > 1 {
		seen := make(map[string]bool, len(out.Answers))
		deduped := out.Answers[:0]
		for _, a := range out.Answers {
			key := a.Type + "\x00" + a.Name + "\x00" + a.Class + "\x00" + a.Rdata
			if seen[key] {
				continue
			}
			seen[key] = true
			deduped = append(deduped, a)
		}
		out.Answers = deduped
	}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -run 'TestBuildOutput_Dedup|TestRunQuery_StructuredDedupsWireDuplicate' ./...`
Expected: PASS (all four).

- [ ] **Step 6: Run the full offline suite (determinism regression)**

Run: `go test ./...`
Expected: PASS — including `TestBuildOutput_DeterministicOrder` and `TestBuildOutput_NaturalNumericOrder` (dedup runs after the sort and preserves order).

- [ ] **Step 7: Commit**

```bash
git add render_json.go render_json_test.go dany_test.go
git commit -m "feat: dedup structured output on RRset identity

BuildOutput now drops duplicate answers keyed on (Type, Name, Class,
Rdata) after the existing sort, so genuine wire-duplicate RRs collapse
to one entry (RFC 2181 §5), keeping the lowest TTL. Brings JSON/YAML in
line with the text renderer; name-distinct records (www/apex, PTRs,
CNAME hops) are preserved. Envelope shape unchanged (SchemaVersion 1).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Document structured dedup in CLAUDE.md

Records the new render-time behavior for future maintainers, parallel to the existing text-dedup and determinism notes.

**Files:**
- Modify: `CLAUDE.md` — the "Data vs. rendering" architecture note

- [ ] **Step 1: Update the CLAUDE.md architecture note**

In `CLAUDE.md`, find the **"Data vs. rendering."** bullet in the "Architecture notes worth knowing before editing `dany.go`" list. Append this sentence to the end of that bullet (before the bullet's closing period/newline):

```
BuildOutput deduplicates its assembled answers on RRset identity (Type, Name, Class, Rdata), keeping the lowest TTL — the structured parallel to the text renderer's line-level `seen`-map dedup — so genuine wire-duplicate RRs collapse to one entry (RFC 2181 §5) while name-distinct records (www/apex, per-IP PTRs, CNAME hops) are preserved.
```

(If the sentence reads more cleanly as its own trailing sentence in the bullet, that is fine — keep it in the same bullet, do not add a new list item.)

- [ ] **Step 2: Verify the build and suite are unaffected**

Run: `go build ./... && go test ./...`
Expected: build succeeds; all tests PASS (a docs-only change).

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: note structured-output RRset dedup in CLAUDE.md

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Notes for the implementer

- **Why dedup runs after the sort:** the sort orders by `(Type, Rdata, Name, TTL)`, so records sharing the dedup key are grouped and the first has the lowest TTL. Deduping before the sort would keep whichever duplicate the concurrent fan-out delivered first — a nondeterministic TTL.
- **Why a `seen` map, not adjacent-pair comparison:** the sort key omits `Class`, so records identical except for `Class` are not guaranteed adjacent. A `seen` map is correct regardless (and `Class` is effectively always `IN`).
- **`out.Answers[:0]` in-place filter** is safe: the loop reads each element before the write position could overtake it (kept count ≤ read index).
- **`present_empty` answers** have `Rdata == ""`; they never collide with record-bearing answers (which have non-empty rdata) and cannot duplicate each other (one probe per USD label), so dedup leaves them untouched.
- **`BuildOutput` is the single chokepoint** for both JSON (`RenderJSON`) and YAML (`RenderYAML`) — deduping there covers both formats.
- After both tasks land, this is a minor release (`1.5.0`): add a `debian/changelog` stanza and run `scripts/release.sh 1.5.0` (separate from this plan).
