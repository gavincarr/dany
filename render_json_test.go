package dany

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/gavincarr/dany/internal/testdns"
)

// decodeJSON renders + parses, returning the Output struct. Driving the
// assertions through unmarshal (instead of byte-comparing the raw JSON)
// avoids brittleness around json field ordering and whitespace.
func decodeJSON(t *testing.T, answers []Answer, q *Query, errs []error) Output {
	t.Helper()
	s := RenderJSON(answers, q, errs)
	if !strings.HasSuffix(s, "\n") {
		t.Fatalf("RenderJSON output not newline-terminated (needed for NDJSON), got: %q", s)
	}
	var out Output
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("unmarshal RenderJSON output: %v\noutput was: %s", err, s)
	}
	return out
}

func TestRenderJSON_Envelope(t *testing.T) {
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))

	q := &Query{
		Hostname: "example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
		Www:      true,
		Ptr:      false,
	}
	answers, errs := RunQuery(q)
	out := decodeJSON(t, answers, q, errs)

	if out.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", out.SchemaVersion, SchemaVersion)
	}
	if out.Query.Hostname != "example.com" {
		t.Errorf("Query.Hostname = %q, want example.com", out.Query.Hostname)
	}
	if len(out.Query.Types) != 1 || out.Query.Types[0] != "A" {
		t.Errorf("Query.Types = %v, want [A]", out.Query.Types)
	}
	if !out.Query.Options.Www {
		t.Errorf("Query.Options.Www = false, want true")
	}
	if out.Query.Options.Ptr {
		t.Errorf("Query.Options.Ptr = true, want false")
	}
	// Errors field is always present (never nil) so consumers can iterate it
	// without nil-checking; should be empty in this happy-path case.
	if out.Errors == nil {
		t.Errorf("Errors is nil, want empty slice")
	}
}

func TestBuildOutput_RRTypeDataShapes(t *testing.T) {
	// Drive a canned Answer for each RR type through BuildOutput and assert
	// the typed Data payload matches what the per-type *Data struct
	// promises. Catches accidental field renames / type drift.
	tests := []struct {
		name  string
		zone  string
		rType string
		check func(t *testing.T, oa OutputAnswer)
	}{
		{
			name:  "A",
			zone:  "example.com. 300 IN A 1.2.3.4",
			rType: "A",
			check: func(t *testing.T, oa OutputAnswer) {
				d, ok := oa.Data.(map[string]interface{})
				if !ok {
					t.Fatalf("Data not an object: %T", oa.Data)
				}
				if d["address"] != "1.2.3.4" {
					t.Errorf("address = %v, want 1.2.3.4", d["address"])
				}
				if oa.Rdata != "1.2.3.4" {
					t.Errorf("Rdata = %q, want 1.2.3.4", oa.Rdata)
				}
			},
		},
		{
			name:  "AAAA",
			zone:  "example.com. 300 IN AAAA 2001:db8::1",
			rType: "AAAA",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(map[string]interface{})
				if d["address"] != "2001:db8::1" {
					t.Errorf("address = %v, want 2001:db8::1", d["address"])
				}
			},
		},
		{
			name:  "MX",
			zone:  "example.com. 300 IN MX 10 mx1.example.com.",
			rType: "MX",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(map[string]interface{})
				if d["preference"].(float64) != 10 {
					t.Errorf("preference = %v, want 10", d["preference"])
				}
				if d["exchange"] != "mx1.example.com." {
					t.Errorf("exchange = %v, want mx1.example.com.", d["exchange"])
				}
			},
		},
		{
			name:  "SOA",
			zone:  "example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 12345 7200 3600 1209600 300",
			rType: "SOA",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(map[string]interface{})
				if d["mname"] != "ns.example.com." {
					t.Errorf("mname = %v", d["mname"])
				}
				if d["rname"] != "hostmaster.example.com." {
					t.Errorf("rname = %v", d["rname"])
				}
				if d["serial"].(float64) != 12345 {
					t.Errorf("serial = %v, want 12345", d["serial"])
				}
				if d["minimum"].(float64) != 300 {
					t.Errorf("minimum = %v, want 300", d["minimum"])
				}
			},
		},
		{
			name:  "TXT multi-string",
			zone:  `example.com. 60 IN TXT "v=spf1" "include:_spf.google.com" "~all"`,
			rType: "TXT",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(map[string]interface{})
				strs := d["strings"].([]interface{})
				want := []string{"v=spf1", "include:_spf.google.com", "~all"}
				if len(strs) != len(want) {
					t.Fatalf("strings len = %d, want %d (%v)", len(strs), len(want), strs)
				}
				for i, w := range want {
					if strs[i] != w {
						t.Errorf("strings[%d] = %v, want %q", i, strs[i], w)
					}
				}
			},
		},
		{
			name:  "NS",
			zone:  "example.com. 86400 IN NS ns1.example.com.",
			rType: "NS",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(map[string]interface{})
				if d["target"] != "ns1.example.com." {
					t.Errorf("target = %v", d["target"])
				}
			},
		},
		{
			name:  "CNAME",
			zone:  "alias.example.com. 300 IN CNAME target.example.com.",
			rType: "CNAME",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(map[string]interface{})
				if d["target"] != "target.example.com." {
					t.Errorf("target = %v", d["target"])
				}
			},
		},
		{
			name:  "CAA",
			zone:  `example.com. 300 IN CAA 0 issue "letsencrypt.org"`,
			rType: "CAA",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(map[string]interface{})
				if d["flag"].(float64) != 0 {
					t.Errorf("flag = %v", d["flag"])
				}
				if d["tag"] != "issue" {
					t.Errorf("tag = %v", d["tag"])
				}
				if d["value"] != "letsencrypt.org" {
					t.Errorf("value = %v", d["value"])
				}
			},
		},
		{
			name:  "SRV",
			zone:  "_sip._tcp.example.com. 300 IN SRV 10 60 5060 sipserver.example.com.",
			rType: "SRV",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(map[string]interface{})
				if d["priority"].(float64) != 10 {
					t.Errorf("priority = %v", d["priority"])
				}
				if d["weight"].(float64) != 60 {
					t.Errorf("weight = %v", d["weight"])
				}
				if d["port"].(float64) != 5060 {
					t.Errorf("port = %v", d["port"])
				}
				if d["target"] != "sipserver.example.com." {
					t.Errorf("target = %v", d["target"])
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := testdns.MustRR(tc.zone)
			a := Answer{Type: tc.rType, Hostname: "example.com", RR: rr}
			q := &Query{Hostname: "example.com"}
			out := BuildOutput([]Answer{a}, q, nil)
			if len(out.Answers) != 1 {
				t.Fatalf("Answers len = %d, want 1", len(out.Answers))
			}
			oa := out.Answers[0]
			if oa.Type != tc.rType {
				t.Errorf("Type = %q, want %q", oa.Type, tc.rType)
			}
			if oa.Class != "IN" {
				t.Errorf("Class = %q, want IN", oa.Class)
			}
			if oa.Rdata == "" {
				t.Errorf("Rdata empty, want non-empty (presentation form)")
			}
			// Round-trip through JSON so map[string]interface{} assertions
			// in tc.check work as if the consumer parsed the wire form.
			b, err := json.Marshal(oa)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var roundtripped OutputAnswer
			if err := json.Unmarshal(b, &roundtripped); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			tc.check(t, roundtripped)
		})
	}
}

func TestBuildOutput_PTRStandalone(t *testing.T) {
	// PTR Answers carry the original IP in Hostname; verify it surfaces as
	// data.ip and the record stays standalone (not folded into A/AAAA the
	// way text rendering does).
	ptrRR := testdns.MustRR("4.3.2.1.in-addr.arpa. 3600 IN PTR host.example.com.")
	aRR := testdns.MustRR("example.com. 300 IN A 1.2.3.4")
	answers := []Answer{
		{Type: "A", Hostname: "example.com", RR: aRR},
		{Type: "PTR", Hostname: "1.2.3.4", RR: ptrRR},
	}
	q := &Query{Hostname: "example.com", Ptr: true}
	out := decodeJSON(t, answers, q, nil)

	if len(out.Answers) != 2 {
		t.Fatalf("Answers len = %d, want 2 (A + PTR as standalone)", len(out.Answers))
	}
	var ptr *OutputAnswer
	for i := range out.Answers {
		if out.Answers[i].Type == "PTR" {
			ptr = &out.Answers[i]
		}
	}
	if ptr == nil {
		t.Fatal("no PTR record in output")
	}
	d := ptr.Data.(map[string]interface{})
	if d["target"] != "host.example.com." {
		t.Errorf("PTR target = %v, want host.example.com.", d["target"])
	}
	if d["ip"] != "1.2.3.4" {
		t.Errorf("PTR ip = %v, want 1.2.3.4 (from Answer.Hostname)", d["ip"])
	}
}

func TestBuildOutput_DeterministicOrder(t *testing.T) {
	// RunQuery returns Answers/Errors in nondeterministic goroutine-arrival
	// order; BuildOutput must sort them into a stable total order so
	// consecutive runs render identically. Feed the same records in two
	// different input orders and assert the built envelope is identical.
	rrs := []Answer{
		{Type: "A", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN A 10.0.0.2")},
		{Type: "A", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN A 10.0.0.1")},
		{Type: "MX", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN MX 10 mx.example.com.")},
		{Type: "NS", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN NS ns1.example.com.")},
		{Type: "AAAA", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN AAAA 2001:db8::1")},
	}
	reversed := make([]Answer, len(rrs))
	for i, a := range rrs {
		reversed[len(rrs)-1-i] = a
	}
	q := &Query{Hostname: "example.com"}

	got := RenderJSON(rrs, q, nil)
	gotReversed := RenderJSON(reversed, q, nil)
	if got != gotReversed {
		t.Fatalf("output not order-independent:\n forward: %s\nreversed: %s", got, gotReversed)
	}

	// Verify the actual order: Type first, then Rdata. Lexically "A" < "AAAA"
	// (prefix) < "MX" < "NS"; the two A records sort by rdata (10.0.0.1 <
	// 10.0.0.2).
	out := decodeJSON(t, rrs, q, nil)
	wantOrder := []struct{ typ, rdata string }{
		{"A", "10.0.0.1"},
		{"A", "10.0.0.2"},
		{"AAAA", "2001:db8::1"},
		{"MX", "10 mx.example.com."},
		{"NS", "ns1.example.com."},
	}
	if len(out.Answers) != len(wantOrder) {
		t.Fatalf("Answers len = %d, want %d", len(out.Answers), len(wantOrder))
	}
	for i, w := range wantOrder {
		if out.Answers[i].Type != w.typ || out.Answers[i].Rdata != w.rdata {
			t.Errorf("Answers[%d] = (%s, %q), want (%s, %q)",
				i, out.Answers[i].Type, out.Answers[i].Rdata, w.typ, w.rdata)
		}
	}
}

func TestBuildOutput_NaturalNumericOrder(t *testing.T) {
	// Numeric rdata fields must sort by value, not lexically: MX preference
	// 9 < 10 < 20 < 100 (lexical order would put "100" and "10" before "20"),
	// and A records sort so 10.0.0.2 < 10.0.0.10.
	rrs := []Answer{
		{Type: "MX", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN MX 100 d.example.com.")},
		{Type: "MX", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN MX 20 c.example.com.")},
		{Type: "MX", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN MX 9 b.example.com.")},
		{Type: "MX", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN MX 10 a.example.com.")},
		{Type: "A", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN A 10.0.0.10")},
		{Type: "A", Hostname: "example.com", RR: testdns.MustRR("example.com. 300 IN A 10.0.0.2")},
	}
	q := &Query{Hostname: "example.com"}
	out := decodeJSON(t, rrs, q, nil)

	wantRdata := []string{
		"10.0.0.2",
		"10.0.0.10",
		"9 b.example.com.",
		"10 a.example.com.",
		"20 c.example.com.",
		"100 d.example.com.",
	}
	if len(out.Answers) != len(wantRdata) {
		t.Fatalf("Answers len = %d, want %d", len(out.Answers), len(wantRdata))
	}
	for i, w := range wantRdata {
		if out.Answers[i].Rdata != w {
			t.Errorf("Answers[%d].Rdata = %q, want %q", i, out.Answers[i].Rdata, w)
		}
	}
}

func TestBuildOutput_DeterministicErrorOrder(t *testing.T) {
	// Errors also arrive concurrently; BuildOutput must order them stably.
	errsFwd := []error{
		&QueryError{Type: "MX", Hostname: "example.com", Code: "NXDOMAIN", Err: ErrNXDomain},
		&QueryError{Type: "A", Hostname: "example.com", Code: "SERVFAIL", Err: ErrServFail},
		&QueryError{Type: "NS", Hostname: "example.com", Code: "NXDOMAIN", Err: ErrNXDomain},
	}
	errsRev := []error{errsFwd[2], errsFwd[1], errsFwd[0]}
	q := &Query{Hostname: "example.com"}

	if RenderJSON(nil, q, errsFwd) != RenderJSON(nil, q, errsRev) {
		t.Fatal("error output not order-independent")
	}
	out := decodeJSON(t, nil, q, errsFwd)
	wantTypes := []string{"A", "MX", "NS"} // sorted by Type
	if len(out.Errors) != len(wantTypes) {
		t.Fatalf("Errors len = %d, want %d", len(out.Errors), len(wantTypes))
	}
	for i, wt := range wantTypes {
		if out.Errors[i].Type != wt {
			t.Errorf("Errors[%d].Type = %q, want %q", i, out.Errors[i].Type, wt)
		}
	}
}

func TestBuildOutput_CNAMEChainCaptured(t *testing.T) {
	// Querying A for a name that is a CNAME must capture the CNAME hop as its
	// own answer (with the owner name and target) alongside the resolved A —
	// structured output is archival, so the mapping is preserved rather than
	// silently requeried away.
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("www.example.com. 300 IN CNAME example.com."))
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))
	q := &Query{Hostname: "www.example.com", Types: []string{"A"}, Server: srv.Addr}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	out := decodeJSON(t, answers, q, errs)

	if len(out.Answers) != 2 {
		t.Fatalf("Answers len = %d, want 2 (CNAME hop + resolved A): %+v", len(out.Answers), out.Answers)
	}
	var cname, a *OutputAnswer
	for i := range out.Answers {
		switch out.Answers[i].Type {
		case "CNAME":
			cname = &out.Answers[i]
		case "A":
			a = &out.Answers[i]
		}
	}
	if cname == nil {
		t.Fatal("no CNAME hop captured in structured output")
	}
	if cname.Name != "www.example.com." {
		t.Errorf("CNAME name = %q, want www.example.com. (the queried owner)", cname.Name)
	}
	if cname.Rdata != "example.com." {
		t.Errorf("CNAME rdata = %q, want example.com.", cname.Rdata)
	}
	if d := cname.Data.(map[string]interface{}); d["target"] != "example.com." {
		t.Errorf("CNAME data.target = %v, want example.com.", d["target"])
	}
	if a == nil {
		t.Fatal("no resolved A record in output")
	}
	if a.Name != "example.com." || a.Rdata != "1.2.3.4" {
		t.Errorf("A = (name %q, rdata %q), want (example.com., 1.2.3.4)", a.Name, a.Rdata)
	}
}

func TestBuildOutput_CNAMEMultiHopCaptured(t *testing.T) {
	// A multi-hop chain a -> b -> A must capture both CNAME hops.
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("a.example.com. 300 IN CNAME b.example.com."))
	srv.Add(testdns.MustRR("b.example.com. 300 IN CNAME c.example.com."))
	srv.Add(testdns.MustRR("c.example.com. 300 IN A 1.2.3.4"))
	q := &Query{Hostname: "a.example.com", Types: []string{"A"}, Server: srv.Addr}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	out := decodeJSON(t, answers, q, errs)

	// Reconstruct the chain by name -> target and walk it from the query name.
	hop := make(map[string]string)
	for _, oa := range out.Answers {
		if oa.Type == "CNAME" {
			hop[oa.Name] = oa.Rdata
		}
	}
	want := map[string]string{
		"a.example.com.": "b.example.com.",
		"b.example.com.": "c.example.com.",
	}
	if len(hop) != len(want) {
		t.Fatalf("captured %d CNAME hops, want %d: %+v", len(hop), len(want), out.Answers)
	}
	for name, target := range want {
		if hop[name] != target {
			t.Errorf("hop %q -> %q, want %q", name, hop[name], target)
		}
	}
}

func TestBuildOutput_NXDOMAINError(t *testing.T) {
	srv := testdns.New(t)
	q := &Query{
		Hostname: "missing.example.com",
		Types:    []string{"A", "MX"},
		Server:   srv.Addr,
	}
	answers, errs := RunQuery(q)
	out := decodeJSON(t, answers, q, errs)

	if len(out.Answers) != 0 {
		t.Errorf("Answers len = %d, want 0", len(out.Answers))
	}
	if len(out.Errors) == 0 {
		t.Fatal("expected NXDOMAIN errors, got none")
	}
	for _, oe := range out.Errors {
		if oe.Code != "NXDOMAIN" {
			t.Errorf("error Code = %q, want NXDOMAIN", oe.Code)
		}
		if oe.Hostname != "missing.example.com" {
			t.Errorf("error Hostname = %q, want missing.example.com", oe.Hostname)
		}
		if oe.Type != "A" && oe.Type != "MX" {
			t.Errorf("error Type = %q, want A or MX", oe.Type)
		}
		if !strings.Contains(oe.Message, "NXDOMAIN") {
			t.Errorf("error Message = %q, want it to contain NXDOMAIN", oe.Message)
		}
	}
}

func TestRenderJSON_NDJSONShape(t *testing.T) {
	// Two RenderJSON outputs concatenated must be valid NDJSON: exactly one
	// '\n' separator and each chunk parseable independently.
	q1 := &Query{Hostname: "a.example.com"}
	q2 := &Query{Hostname: "b.example.com"}
	combined := RenderJSON(nil, q1, nil) + RenderJSON(nil, q2, nil)
	lines := strings.Split(strings.TrimSuffix(combined, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d NDJSON lines, want 2: %q", len(lines), combined)
	}
	for i, line := range lines {
		var out Output
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			t.Errorf("line %d not valid JSON: %v (%q)", i, err, line)
		}
	}
}

func TestQueryError_PreservesErrorsIs(t *testing.T) {
	// The refactor wraps NXDOMAIN/SERVFAIL inside *QueryError. Ensure
	// errors.Is still finds the sentinels — RunNXQuery and any external
	// consumer of dany rely on this.
	srv := testdns.New(t)
	q := &Query{
		Hostname: "totally-missing.example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
	}
	_, errs := RunQuery(q)
	if len(errs) == 0 {
		t.Fatal("expected an error, got none")
	}
	if !errors.Is(errs[0], ErrNXDomain) {
		t.Errorf("errors.Is(err, ErrNXDomain) = false, want true; err = %v", errs[0])
	}
	// And the structured type is reachable via errors.As.
	var qe *QueryError
	if !errors.As(errs[0], &qe) {
		t.Fatalf("errors.As(err, *QueryError) = false; err = %v", errs[0])
	}
	if qe.Code != "NXDOMAIN" {
		t.Errorf("QueryError.Code = %q, want NXDOMAIN", qe.Code)
	}
	if qe.Type != "A" {
		t.Errorf("QueryError.Type = %q, want A", qe.Type)
	}
}
