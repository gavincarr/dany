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
	// promises. Catches accidental field renames / type drift. The Data
	// values are the concrete *Data structs (marshalData's output); the
	// custom unmarshalers restore the same shapes on the way back in, which
	// TestOutputAnswer_RoundTrip verifies separately.
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
				d, ok := oa.Data.(AData)
				if !ok {
					t.Fatalf("Data not AData: %T", oa.Data)
				}
				if d.Address != "1.2.3.4" {
					t.Errorf("address = %v, want 1.2.3.4", d.Address)
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
				d := oa.Data.(AAAAData)
				if d.Address != "2001:db8::1" {
					t.Errorf("address = %v, want 2001:db8::1", d.Address)
				}
			},
		},
		{
			name:  "MX",
			zone:  "example.com. 300 IN MX 10 mx1.example.com.",
			rType: "MX",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(MXData)
				if d.Preference != 10 {
					t.Errorf("preference = %v, want 10", d.Preference)
				}
				if d.Exchange != "mx1.example.com." {
					t.Errorf("exchange = %v, want mx1.example.com.", d.Exchange)
				}
			},
		},
		{
			name:  "SOA",
			zone:  "example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 12345 7200 3600 1209600 300",
			rType: "SOA",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(SOAData)
				if d.MName != "ns.example.com." {
					t.Errorf("mname = %v", d.MName)
				}
				if d.RName != "hostmaster.example.com." {
					t.Errorf("rname = %v", d.RName)
				}
				if d.Serial != 12345 {
					t.Errorf("serial = %v, want 12345", d.Serial)
				}
				if d.Minimum != 300 {
					t.Errorf("minimum = %v, want 300", d.Minimum)
				}
			},
		},
		{
			name:  "TXT multi-string",
			zone:  `example.com. 60 IN TXT "v=spf1" "include:_spf.google.com" "~all"`,
			rType: "TXT",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(TXTData)
				want := []string{"v=spf1", "include:_spf.google.com", "~all"}
				if len(d.Strings) != len(want) {
					t.Fatalf("strings len = %d, want %d (%v)", len(d.Strings), len(want), d.Strings)
				}
				for i, w := range want {
					if d.Strings[i] != w {
						t.Errorf("strings[%d] = %v, want %q", i, d.Strings[i], w)
					}
				}
			},
		},
		{
			name:  "NS",
			zone:  "example.com. 86400 IN NS ns1.example.com.",
			rType: "NS",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(NSData)
				if d.Target != "ns1.example.com." {
					t.Errorf("target = %v", d.Target)
				}
			},
		},
		{
			name:  "CNAME",
			zone:  "alias.example.com. 300 IN CNAME target.example.com.",
			rType: "CNAME",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(CNAMEData)
				if d.Target != "target.example.com." {
					t.Errorf("target = %v", d.Target)
				}
			},
		},
		{
			name:  "CAA",
			zone:  `example.com. 300 IN CAA 0 issue "letsencrypt.org"`,
			rType: "CAA",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(CAAData)
				if d.Flag != 0 {
					t.Errorf("flag = %v", d.Flag)
				}
				if d.Tag != "issue" {
					t.Errorf("tag = %v", d.Tag)
				}
				if d.Value != "letsencrypt.org" {
					t.Errorf("value = %v", d.Value)
				}
			},
		},
		{
			name:  "SRV",
			zone:  "_sip._tcp.example.com. 300 IN SRV 10 60 5060 sipserver.example.com.",
			rType: "SRV",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(SRVData)
				if d.Priority != 10 {
					t.Errorf("priority = %v", d.Priority)
				}
				if d.Weight != 60 {
					t.Errorf("weight = %v", d.Weight)
				}
				if d.Port != 5060 {
					t.Errorf("port = %v", d.Port)
				}
				if d.Target != "sipserver.example.com." {
					t.Errorf("target = %v", d.Target)
				}
			},
		},
		{
			name:  "HTTPS",
			zone:  `example.com. 300 IN HTTPS 1 . alpn="h2,h3" ipv4hint=1.2.3.4`,
			rType: "HTTPS",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(SVCBData)
				if d.Priority != 1 {
					t.Errorf("priority = %v, want 1", d.Priority)
				}
				if d.Target != "." {
					t.Errorf("target = %v, want .", d.Target)
				}
				if len(d.Params) != 2 {
					t.Fatalf("params len = %d, want 2 (%v)", len(d.Params), d.Params)
				}
				got := map[string]string{}
				for _, p := range d.Params {
					got[p.Key] = p.Value
				}
				if got["alpn"] != "h2,h3" {
					t.Errorf("alpn = %q, want h2,h3", got["alpn"])
				}
				if got["ipv4hint"] != "1.2.3.4" {
					t.Errorf("ipv4hint = %q, want 1.2.3.4", got["ipv4hint"])
				}
			},
		},
		{
			name:  "SVCB",
			zone:  `_dns.example.com. 300 IN SVCB 1 dns.example.com. alpn=dot`,
			rType: "SVCB",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(SVCBData)
				if d.Priority != 1 {
					t.Errorf("priority = %v, want 1", d.Priority)
				}
				if d.Target != "dns.example.com." {
					t.Errorf("target = %v, want dns.example.com.", d.Target)
				}
				if len(d.Params) != 1 {
					t.Fatalf("params len = %d, want 1 (%v)", len(d.Params), d.Params)
				}
				if d.Params[0].Key != "alpn" || d.Params[0].Value != "dot" {
					t.Errorf("param = %v, want alpn=dot", d.Params[0])
				}
			},
		},
		{
			name:  "DS",
			zone:  `example.com. 3600 IN DS 12345 13 2 1234567890123456789012345678901234567890123456789012345678901234`,
			rType: "DS",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(DSData)
				if d.KeyTag != 12345 {
					t.Errorf("key_tag = %v, want 12345", d.KeyTag)
				}
				if d.Algorithm != 13 {
					t.Errorf("algorithm = %v, want 13", d.Algorithm)
				}
				if d.DigestType != 2 {
					t.Errorf("digest_type = %v, want 2", d.DigestType)
				}
				if d.Digest != "1234567890123456789012345678901234567890123456789012345678901234" {
					t.Errorf("digest = %v", d.Digest)
				}
			},
		},
		{
			name:  "NSEC",
			zone:  `example.com. 3600 IN NSEC next.example.com. A MX RRSIG NSEC`,
			rType: "NSEC",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(NSECData)
				if d.NextDomain != "next.example.com." {
					t.Errorf("next_domain = %v", d.NextDomain)
				}
				want := map[string]bool{"A": true, "MX": true, "RRSIG": true, "NSEC": true}
				if len(d.Types) != len(want) {
					t.Fatalf("types = %v, want %v", d.Types, want)
				}
				for _, ty := range d.Types {
					if !want[ty] {
						t.Errorf("unexpected type %v in %v", ty, d.Types)
					}
				}
			},
		},
		{
			name:  "RRSIG",
			zone:  `example.com. 3600 IN RRSIG A 13 2 3600 20250101000000 20240101000000 12345 example.com. aGVsbG8=`,
			rType: "RRSIG",
			check: func(t *testing.T, oa OutputAnswer) {
				d := oa.Data.(RRSIGData)
				if d.TypeCovered != "A" {
					t.Errorf("type_covered = %v, want A", d.TypeCovered)
				}
				if d.Algorithm != 13 {
					t.Errorf("algorithm = %v, want 13", d.Algorithm)
				}
				if d.KeyTag != 12345 {
					t.Errorf("key_tag = %v, want 12345", d.KeyTag)
				}
				if d.SignerName != "example.com." {
					t.Errorf("signer_name = %v", d.SignerName)
				}
				if d.Expiration != "20250101000000" {
					t.Errorf("expiration = %v, want 20250101000000", d.Expiration)
				}
				if d.Inception != "20240101000000" {
					t.Errorf("inception = %v, want 20240101000000", d.Inception)
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
			tc.check(t, oa)
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
	d := ptr.Data.(PTRData)
	if d.Target != "host.example.com." {
		t.Errorf("PTR target = %v, want host.example.com.", d.Target)
	}
	if d.IP != "1.2.3.4" {
		t.Errorf("PTR ip = %v, want 1.2.3.4 (from Answer.Hostname)", d.IP)
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
	var gotApex, gotWww bool
	for _, a := range out.Answers {
		if a.Rdata != "1.2.3.4" {
			t.Errorf("unexpected rdata %q survived: %+v", a.Rdata, out.Answers)
			continue
		}
		switch a.Name {
		case "example.com.":
			gotApex = true
		case "www.example.com.":
			gotWww = true
		}
	}
	if !gotApex || !gotWww {
		t.Errorf("expected both example.com. and www.example.com. to survive, got: %+v", out.Answers)
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
	var gotA, gotB bool
	for _, a := range out.Answers {
		if a.Name != "example.com." {
			t.Errorf("unexpected name %q survived: %+v", a.Name, out.Answers)
			continue
		}
		d, ok := a.Data.(TXTData)
		if !ok || len(d.Strings) != 1 {
			t.Fatalf("unexpected Data shape for TXT answer: %+v", a)
		}
		switch d.Strings[0] {
		case "a":
			gotA = true
		case "b":
			gotB = true
		}
	}
	if !gotA || !gotB {
		t.Errorf("expected both TXT strings \"a\" and \"b\" to survive, got: %+v", out.Answers)
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
	if d := cname.Data.(CNAMEData); d.Target != "example.com." {
		t.Errorf("CNAME data.target = %v, want example.com.", d.Target)
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
