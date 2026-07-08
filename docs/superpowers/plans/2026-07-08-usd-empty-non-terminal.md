# USD Empty-Non-Terminal (DKIM Signal) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Surface the NODATA / empty-non-terminal case on `--usd` probes as a first-class "present; no records" answer, so `_domainkey.<domain>` returning NOERROR-but-empty is reported as "DKIM is deployed" instead of being silently discarded.

**Architecture:** Detection happens once in the query engine (`lookup` emits a record-less `Answer{Empty: true}` when a USD probe returns NODATA). Both renderers learn one new case: the text renderer prints a marker line (tag-aware); the structured renderer emits an `OutputAnswer` with an additive `present_empty` discriminator. NXDOMAIN stays omitted; non-USD queries are byte-for-byte unchanged.

**Tech Stack:** Go 1.25, `github.com/miekg/dns`, `gopkg.in/yaml.v3`; in-process `internal/testdns` for offline tests.

**Spec:** `docs/superpowers/specs/2026-07-08-usd-empty-non-terminal-design.md`

## Global Constraints

- Default `go test ./...` must stay fully offline (use `internal/testdns`, never real DNS).
- The change is **additive**: `SchemaVersion` stays at `1` (render_json.go:16). No existing JSON/YAML/text output for record-bearing answers may change.
- Only `--usd` probes may emit an `Empty` answer. Every non-USD query path is unchanged.
- Conventional Commits for every commit. Do **not** `git push`.
- TDD: write the failing test first, watch it fail, implement minimally, watch it pass, commit.

---

### Task 1: Query engine — detect and emit the empty-non-terminal answer

Adds the `Empty` field to `Answer`, threads a `usd bool` into `lookup`, emits a record-less `Answer` on USD NODATA, and adds the `testdns.AddEmpty` fixture helper (scaffolding this task's test needs).

**Files:**
- Modify: `dany.go` — `Answer` struct (113-117), `lookup` signature + body (244-275), `RunQuery` call sites (619-633)
- Modify: `internal/testdns/testdns.go` — new `AddEmpty` method
- Test: `dany_test.go` — new `TestRunQuery_USDEmptyNonTerminal`

**Interfaces:**
- Produces: `Answer.Empty bool` (true ⇒ `RR == nil`, name exists with no records of the queried type). `Answer.Type` is the queried type (`"TXT"` for USD), `Answer.Hostname` is the probed name (e.g. `_domainkey.example.com`).
- Produces: `func (s *Server) AddEmpty(name string)` in `internal/testdns` — registers a name that exists but has no records (NODATA for every qtype).

- [ ] **Step 1: Add the `AddEmpty` helper to testdns**

In `internal/testdns/testdns.go`, add after the `Add` method:

```go
// AddEmpty registers name as existing with no records, so every qtype returns
// NoError + no answer (NoData) — modeling a DNS empty non-terminal (a node
// that exists only because names below it do, e.g. _domainkey.<domain> when
// <selector>._domainkey.<domain> records exist).
func (s *Server) AddEmpty(name string) {
	name = strings.ToLower(dns.Fqdn(name))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.names[name] == nil {
		s.names[name] = make(map[uint16][]dns.RR)
	}
}
```

- [ ] **Step 2: Add the `Empty` field to `Answer`**

In `dany.go`, modify the `Answer` struct (113-117):

```go
type Answer struct {
	Type     string
	Hostname string
	RR       dns.RR
	Empty    bool // present-empty (NODATA); RR is nil when true
}
```

- [ ] **Step 3: Write the failing test**

In `dany_test.go`, add:

```go
func TestRunQuery_USDEmptyNonTerminal(t *testing.T) {
	srv := testdns.New(t)
	// _domainkey exists as an empty non-terminal (selectors live below it) —
	// the bare name returns NODATA. _dmarc carries a real TXT. _mta-sts is
	// absent (NXDOMAIN, omitted under the USD IgnoreErrors path).
	srv.AddEmpty("_domainkey.example.com")
	srv.Add(testdns.MustRR(`_dmarc.example.com. 300 IN TXT "v=DMARC1; p=reject"`))
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))
	// AAAA is a non-USD type and unregistered → it returns NODATA too, but
	// must NOT produce an Empty answer (USD-only scope). Only _domainkey does.

	q := &Query{Hostname: "example.com", Types: []string{"A", "AAAA"}, Server: srv.Addr, Usd: true}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}

	var empties []Answer
	for _, a := range answers {
		if a.Empty {
			empties = append(empties, a)
		}
	}
	if len(empties) != 1 {
		t.Fatalf("Empty answers = %d, want 1 (_domainkey only, not the AAAA NODATA): %+v", len(empties), answers)
	}
	e := empties[0]
	if e.Hostname != "_domainkey.example.com" {
		t.Errorf("Empty hostname = %q, want _domainkey.example.com", e.Hostname)
	}
	if e.Type != "TXT" {
		t.Errorf("Empty type = %q, want TXT", e.Type)
	}
	if e.RR != nil {
		t.Errorf("Empty RR = %v, want nil", e.RR)
	}
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `go test -run TestRunQuery_USDEmptyNonTerminal ./...`
Expected: FAIL — no `Empty` answer is produced yet (`Empty answers = 0, want 1`).

- [ ] **Step 5: Thread `usd` into `lookup` and emit the empty answer**

In `dany.go`, change the `lookup` signature (244):

```go
func lookup(stream chan<- result, client *dns.Client, rrtype, hostname string, q *Query, usd bool) {
```

Then, in the body, after the PTR block and before `stream <- result{Answers: answers}` (currently ~272-275):

```go
	if q.Ptr && (rrtype == "A" || rrtype == "AAAA") {
		answers = append(answers, ptrLookupAll(client, q.Server, resp.Answer)...)
	}

	// USD probes: a name that exists but returns no records (NODATA / empty
	// non-terminal) is a positive existence signal — surface it as a
	// record-less Answer. NXDOMAIN returns resp==nil above and is omitted.
	if usd && len(resp.Answer) == 0 {
		answers = append(answers, Answer{Type: rrtype, Hostname: hostname, Empty: true})
	}

	stream <- result{Answers: answers}
```

- [ ] **Step 6: Update the three `lookup` call sites in `RunQuery`**

In `dany.go` (619-633), pass the `usd` flag: `false` for the type fan-out, `true` for the USD fan-out, `false` for www:

```go
	for _, t := range q.Types {
		go lookup(stream, client, strings.ToUpper(t), q.Hostname, q, false)
	}
	if q.Usd {
		q.IgnoreErrors = true
		for _, usd := range SupportedUSDs {
			go lookup(stream, client, "TXT", usd+"."+q.Hostname, q, true)
		}
	}
	if q.Www {
		// www probes are best-effort: a missing www.<host> shouldn't
		// surface as an error alongside successful apex answers.
		q.IgnoreErrors = true
		for _, t := range wwwTypes(q) {
			go lookup(stream, client, strings.ToUpper(t), "www."+q.Hostname, q, false)
		}
	}
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `go test -run TestRunQuery_USDEmptyNonTerminal ./...`
Expected: PASS.

- [ ] **Step 8: Run the full offline suite (guard against regressions)**

Run: `go test ./...`
Expected: PASS. (Empty answers are currently dropped by both renderers — no existing golden output changes yet.)

- [ ] **Step 9: Commit**

```bash
git add dany.go internal/testdns/testdns.go dany_test.go
git commit -m "feat: detect USD empty-non-terminal (NODATA) answers

USD probes now emit a record-less Answer{Empty:true} when a name exists
but returns no records (NODATA), the empty-non-terminal case that signals
DKIM is deployed at _domainkey.<domain>. NXDOMAIN stays omitted; non-USD
queries are unchanged. Adds testdns.AddEmpty to model empty non-terminals.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Text rendering — tag-aware marker line

Makes `formatAnswer` tag-aware and renders the empty answer as `[present; no records]`, with the owner name shown exactly once (in the value when untagged, in the tag column under `--tag`).

**Files:**
- Modify: `dany.go` — `formatAnswer` signature + guard (540-547), `Render` call site (443)
- Test: `dany_test.go` — new `TestRender_USDEmpty_Untagged`, `TestRender_USDEmpty_Tagged`

**Interfaces:**
- Consumes: `Answer.Empty` (Task 1).
- Produces: text lines — untagged `"TXT\t\t_domainkey.example.com. [present; no records]\n"`; tagged `"_domainkey.example.com\tTXT\t\t[present; no records]\n"`.

- [ ] **Step 1: Write the failing tests**

In `dany_test.go`, add:

```go
func TestRender_USDEmpty_Untagged(t *testing.T) {
	answers := []Answer{{Type: "TXT", Hostname: "_domainkey.example.com", Empty: true}}
	got := Render(answers, false)
	want := "TXT\t\t_domainkey.example.com. [present; no records]\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRender_USDEmpty_Tagged(t *testing.T) {
	answers := []Answer{{Type: "TXT", Hostname: "_domainkey.example.com", Empty: true}}
	got := Render(answers, true)
	want := "_domainkey.example.com\tTXT\t\t[present; no records]\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test -run 'TestRender_USDEmpty' ./...`
Expected: FAIL — `formatAnswer` returns `""` for a nil-`RR` answer, so `Render` produces an empty string.

- [ ] **Step 3: Make `formatAnswer` tag-aware and handle the empty case**

In `dany.go`, change the `formatAnswer` signature (540) and add the guard at the very top of the body, before the CNAME guard:

```go
func formatAnswer(a Answer, ptrMap map[string]string, tagHostname bool) string {
	// An empty non-terminal (name exists, no records of the queried type) has
	// no RR. Show the owner name exactly once: in the value when untagged,
	// or via the tag column Render prepends under --tag.
	if a.Empty {
		if tagHostname {
			return fmt.Sprintf("%s\t\t[present; no records]\n", a.Type)
		}
		return fmt.Sprintf("%s\t\t%s [present; no records]\n", a.Type, dns.Fqdn(a.Hostname))
	}
	// A CNAME surfaced under a non-CNAME query type is a chain hop captured
```

(Leave the rest of `formatAnswer` unchanged.)

- [ ] **Step 4: Pass `tagHostname` through from `Render`**

In `dany.go`, update the `Render` call site (443):

```go
		line := formatAnswer(a, ptrMap, tagHostname)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test -run 'TestRender_USDEmpty' ./...`
Expected: PASS (both).

- [ ] **Step 6: Run the full offline suite**

Run: `go test ./...`
Expected: PASS — the `formatAnswer` signature change touches only `Render`, and record-bearing output is unchanged.

- [ ] **Step 7: Commit**

```bash
git add dany.go dany_test.go
git commit -m "feat: render USD empty-non-terminal as tag-aware text marker

formatAnswer gains a tagHostname bool and renders Empty answers as
'[present; no records]', with the owner name shown once — in the value
when untagged, in the tag column under --tag.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Structured rendering — `present_empty` discriminator

Adds the additive `present_empty` field to `OutputAnswer` and emits it from `buildAnswer` for empty answers, covering both JSON and YAML (shared envelope).

**Files:**
- Modify: `render_json.go` — `OutputAnswer` struct (46-53), `buildAnswer` (235-249)
- Test: `render_json_test.go` — new `TestBuildOutput_USDEmptyNonTerminal`
- Test: `render_yaml_test.go` — new `TestRenderYAML_USDEmptyNonTerminal`

**Interfaces:**
- Consumes: `Answer.Empty` (Task 1).
- Produces: `OutputAnswer.PresentEmpty bool` (`json:"present_empty,omitempty"` / `yaml:"present_empty,omitempty"`). For empty answers: `Type` = queried type (`"TXT"`), `Name` = FQDN of the probed host, `PresentEmpty = true`, and `TTL`/`Class`/`Rdata`/`Data` left zero/empty/nil.

- [ ] **Step 1: Write the failing JSON test**

In `render_json_test.go`, add:

```go
func TestBuildOutput_USDEmptyNonTerminal(t *testing.T) {
	answers := []Answer{{Type: "TXT", Hostname: "_domainkey.example.com", Empty: true}}
	q := &Query{Hostname: "example.com", Types: []string{"A"}, Usd: true}

	out := BuildOutput(answers, q, nil)
	if len(out.Answers) != 1 {
		t.Fatalf("Answers len = %d, want 1: %+v", len(out.Answers), out.Answers)
	}
	a := out.Answers[0]
	if !a.PresentEmpty {
		t.Errorf("PresentEmpty = false, want true")
	}
	if a.Type != "TXT" {
		t.Errorf("Type = %q, want TXT", a.Type)
	}
	if a.Name != "_domainkey.example.com." {
		t.Errorf("Name = %q, want _domainkey.example.com.", a.Name)
	}
	if a.Rdata != "" {
		t.Errorf("Rdata = %q, want empty", a.Rdata)
	}

	// Serialized form carries the discriminator...
	js := RenderJSON(answers, q, nil)
	if !strings.Contains(js, `"present_empty":true`) {
		t.Errorf("JSON missing present_empty:true: %s", js)
	}
	// ...but omitempty keeps it off normal record-bearing answers.
	rec := RenderJSON([]Answer{{
		Type: "A", Hostname: "example.com",
		RR: testdns.MustRR("example.com. 300 IN A 1.2.3.4"),
	}}, q, nil)
	if strings.Contains(rec, "present_empty") {
		t.Errorf("normal answer leaked present_empty key: %s", rec)
	}
}
```

- [ ] **Step 2: Run the JSON test to verify it fails**

Run: `go test -run TestBuildOutput_USDEmptyNonTerminal ./...`
Expected: FAIL — `OutputAnswer` has no `PresentEmpty` field (compile error), and `buildAnswer` currently drops nil-`RR` answers.

- [ ] **Step 3: Add the `PresentEmpty` field to `OutputAnswer`**

In `render_json.go`, add the field to `OutputAnswer` (after `Data`, 46-53):

```go
type OutputAnswer struct {
	Type         string      `json:"type"          yaml:"type"`
	Name         string      `json:"name"          yaml:"name"`
	TTL          uint32      `json:"ttl"           yaml:"ttl"`
	Class        string      `json:"class"         yaml:"class"`
	Rdata        string      `json:"rdata"         yaml:"rdata"`
	Data         interface{} `json:"data"          yaml:"data"`
	PresentEmpty bool        `json:"present_empty,omitempty" yaml:"present_empty,omitempty"`
}
```

- [ ] **Step 4: Intercept `Empty` in `buildAnswer`**

In `render_json.go`, add the guard at the top of `buildAnswer` (235), before `marshalData` (which returns `ok == false` for a nil `RR` and would drop the answer):

```go
func buildAnswer(a Answer) (OutputAnswer, bool) {
	if a.Empty {
		return OutputAnswer{
			Type:         a.Type,
			Name:         dns.Fqdn(a.Hostname),
			PresentEmpty: true,
		}, true
	}
	data, ok := marshalData(a)
```

(Leave the rest of `buildAnswer` unchanged.)

- [ ] **Step 5: Run the JSON test to verify it passes**

Run: `go test -run TestBuildOutput_USDEmptyNonTerminal ./...`
Expected: PASS.

- [ ] **Step 6: Write the failing YAML test**

In `render_yaml_test.go`, add:

```go
func TestRenderYAML_USDEmptyNonTerminal(t *testing.T) {
	answers := []Answer{{Type: "TXT", Hostname: "_domainkey.example.com", Empty: true}}
	q := &Query{Hostname: "example.com", Types: []string{"A"}, Usd: true}

	out := decodeYAML(t, answers, q, nil)
	if len(out.Answers) != 1 {
		t.Fatalf("Answers len = %d, want 1", len(out.Answers))
	}
	if !out.Answers[0].PresentEmpty {
		t.Errorf("PresentEmpty = false, want true")
	}
	if out.Answers[0].Name != "_domainkey.example.com." {
		t.Errorf("Name = %q, want _domainkey.example.com.", out.Answers[0].Name)
	}
}
```

- [ ] **Step 7: Run the YAML test to verify it passes**

Run: `go test -run TestRenderYAML_USDEmptyNonTerminal ./...`
Expected: PASS — the shared `OutputAnswer` change (Step 3) already covers YAML; this test just confirms it.

- [ ] **Step 8: Run the full offline suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add render_json.go render_json_test.go render_yaml_test.go
git commit -m "feat: emit present_empty for USD empty-non-terminal in JSON/YAML

OutputAnswer gains an omitempty present_empty discriminator; buildAnswer
emits it (type=queried, name=FQDN) for Empty answers, before marshalData
would drop the nil-RR answer. Additive — SchemaVersion stays at 1.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Docs — `--usd` help text and CLAUDE.md

Documents the new behavior for users (`--usd` help footer) and future maintainers (CLAUDE.md USD/rendering notes). No test cycle; verified by build + full suite.

**Files:**
- Modify: `cmd/dany/main.go` — `--usd` help string (41) and/or `writeTypesFooter` (57-62)
- Modify: `CLAUDE.md` — USD behavior note

- [ ] **Step 1: Update the `--usd` help footer**

In `cmd/dany/main.go`, append a clarifying line to `writeTypesFooter` (after the existing USD line, ~61):

```go
	fmt.Fprintf(w, "Supported underscore-subdomains with --usd: %s\n", strings.Join(dany.SupportedUSDs, ","))
	fmt.Fprintf(w, "  (a name that exists without records — e.g. _domainkey when DKIM selectors are present — is reported as \"[present; no records]\")\n")
```

- [ ] **Step 2: Verify the build and help output**

Run: `cd cmd/dany && go build && ./dany --help 2>&1 | grep -A1 'underscore-subdomains'`
Expected: build succeeds; help shows the USD line followed by the new `[present; no records]` note.

- [ ] **Step 3: Update CLAUDE.md**

In `CLAUDE.md`, add a bullet to the "Architecture notes worth knowing before editing `dany.go`" list (near the CNAME/PTR notes), documenting the new behavior:

```markdown
- **USD empty-non-terminal.** `--usd` probes TXT at fixed underscore labels (`_dmarc`/`_domainkey`/`_mta-sts`). A probe that returns NODATA (NOERROR + no records — a name that exists only because names below it do, e.g. `_domainkey.<domain>` when `<selector>._domainkey.<domain>` DKIM keys exist) is surfaced as a record-less `Answer{Empty: true}` (queried Type, `RR == nil`). NXDOMAIN stays omitted. Text renders it as `[present; no records]` (tag-aware: owner name in the value untagged, in the tag column under `--tag`); the structured renderers emit an `OutputAnswer` with an additive `present_empty: true` discriminator (no `SchemaVersion` bump). Only `--usd` probes can produce an `Empty` answer — ordinary NODATA on other queries is unchanged (renders nothing).
```

- [ ] **Step 4: Run the full offline suite**

Run: `go test ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/dany/main.go CLAUDE.md
git commit -m "docs: document USD empty-non-terminal (present; no records) behavior

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Notes for the implementer

- **Why `resp == nil` distinguishes NXDOMAIN from NODATA:** under `IgnoreErrors` (set for USD), `dnsLookup` returns `(nil, nil)` for any non-success rcode (dany.go:192-193), so NXDOMAIN reaches `lookup` as `resp == nil` and is omitted at the existing guard. NODATA is `RcodeSuccess` with an empty answer section, so `dnsLookup` returns a non-nil `resp` (dany.go:226) with `len(resp.Answer) == 0` — the detection hook. No `dnsLookup` change is needed.
- **`lookup` is unexported** and called only from the three `RunQuery` sites — the signature change has no other callers (including tests).
- **`formatAnswer` is unexported** and called only from `Render` — likewise no other callers.
- **Determinism:** an empty answer sorts as `Type "TXT"`, `Rdata ""` in `BuildOutput` (render_json.go:194-206) and as a plain string line in `Render` (natural sort) — both stable, no special handling required.
