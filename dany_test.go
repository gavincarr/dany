package dany

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gavincarr/dany/internal/testdns"
	"github.com/miekg/dns"
)

func TestNewResolvers(t *testing.T) {
	ip := net.ParseIP("8.8.8.8")
	r := NewResolvers(ip)
	if r.Length != 1 {
		t.Errorf("Length = %d, want 1", r.Length)
	}
	if !r.List[0].Equal(ip) {
		t.Errorf("List[0] = %v, want %v", r.List[0], ip)
	}
}

func TestNewResolversVariadic(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("1.0.0.1"),
		net.ParseIP("8.8.8.8"),
		net.ParseIP("8.8.4.4"),
	}
	r := NewResolvers(ips...)
	if r.Length != 4 {
		t.Fatalf("Length = %d, want 4", r.Length)
	}
	want := []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"}
	for i, w := range want {
		if r.List[i].String() != w {
			t.Errorf("List[%d] = %s, want %s", i, r.List[i], w)
		}
	}
}

func TestNewResolversNoArgsPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewResolvers() with no args did not panic")
		}
	}()
	NewResolvers()
}

func TestNewResolversFromStrings(t *testing.T) {
	r, err := NewResolversFromStrings([]string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Length != 4 {
		t.Fatalf("Length = %d, want 4", r.Length)
	}
	want := []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"}
	for i, w := range want {
		if r.List[i].String() != w {
			t.Errorf("List[%d] = %s, want %s", i, r.List[i], w)
		}
	}
}

func TestNewResolversFromStringsErrors(t *testing.T) {
	if _, err := NewResolversFromStrings(nil); err == nil {
		t.Error("empty input: expected error, got nil")
	}
	if _, err := NewResolversFromStrings([]string{"1.1.1.1", "not-an-ip"}); err == nil {
		t.Error("bad ip: expected error, got nil")
	}
}

func TestResolversAppend(t *testing.T) {
	r := NewResolvers(net.ParseIP("8.8.8.8"))
	r.Append(net.ParseIP("1.1.1.1"))
	r.Append(net.ParseIP("9.9.9.9"))
	if r.Length != 3 {
		t.Fatalf("Length = %d, want 3", r.Length)
	}
	want := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"}
	for i, w := range want {
		if r.List[i].String() != w {
			t.Errorf("List[%d] = %s, want %s", i, r.List[i], w)
		}
	}
}

func TestResolversNextRotation(t *testing.T) {
	r := NewResolvers(net.ParseIP("8.8.8.8"))
	r.Append(net.ParseIP("1.1.1.1"))
	r.Append(net.ParseIP("9.9.9.9"))

	// Calling Next() five times across three resolvers should cycle.
	want := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.8.8", "1.1.1.1"}
	for i, w := range want {
		if got := r.Next().String(); got != w {
			t.Errorf("Next() call %d = %s, want %s", i, got, w)
		}
	}
}

func TestResolversNextSingleStable(t *testing.T) {
	r := NewResolvers(net.ParseIP("8.8.8.8"))
	for i := 0; i < 5; i++ {
		if got := r.Next().String(); got != "8.8.8.8" {
			t.Errorf("Next() call %d = %s, want 8.8.8.8", i, got)
		}
	}
}

func TestLoadResolvers(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []string // empty means: expect error
		errSub  string   // substring expected in error message
	}{
		{
			name:    "single IPv4",
			content: "8.8.8.8\n",
			want:    []string{"8.8.8.8"},
		},
		{
			name:    "multiple IPv4",
			content: "8.8.8.8\n1.1.1.1\n9.9.9.9\n",
			want:    []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"},
		},
		{
			name:    "IPv6",
			content: "2001:4860:4860::8888\n",
			want:    []string{"2001:4860:4860::8888"},
		},
		{
			name:    "no trailing newline",
			content: "8.8.8.8",
			want:    []string{"8.8.8.8"},
		},
		{
			name:    "empty file",
			content: "",
			errSub:  "no resolvers found",
		},
		{
			name:    "invalid IP",
			content: "not-an-ip\n",
			errSub:  "failed to parse",
		},
		{
			name:    "blank line mid-file",
			content: "8.8.8.8\n\n1.1.1.1\n",
			errSub:  "failed to parse",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "resolvers.txt")
			if err := os.WriteFile(path, []byte(tc.content), 0644); err != nil {
				t.Fatal(err)
			}
			r, err := LoadResolvers(path)
			if tc.errSub != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.errSub)
				}
				if !strings.Contains(err.Error(), tc.errSub) {
					t.Errorf("error = %q, want substring %q", err, tc.errSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if r.Length != len(tc.want) {
				t.Fatalf("Length = %d, want %d", r.Length, len(tc.want))
			}
			for i, w := range tc.want {
				if r.List[i].String() != w {
					t.Errorf("List[%d] = %s, want %s", i, r.List[i], w)
				}
			}
		})
	}
}

func TestLoadResolversMissingFile(t *testing.T) {
	_, err := LoadResolvers(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestRunQuery_Basic(t *testing.T) {
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))
	srv.Add(testdns.MustRR("example.com. 300 IN A 5.6.7.8"))
	srv.Add(testdns.MustRR("example.com. 300 IN MX 10 mx1.example.com."))
	srv.Add(testdns.MustRR("example.com. 300 IN MX 20 mx2.example.com."))
	srv.Add(testdns.MustRR("example.com. 300 IN TXT \"v=spf1 -all\""))
	// SOA, NS, AAAA are unregistered → NoData (no output)

	q := &Query{
		Hostname: "example.com",
		Types:    DefaultRRTypes,
		Server:   srv.Addr,
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	got := Render(answers, false)

	want := strings.Join([]string{
		"A\t\t1.2.3.4\n",
		"A\t\t5.6.7.8\n",
		"MX\t10\tmx1.example.com.\n",
		"MX\t20\tmx2.example.com.\n",
		"TXT\t\tv=spf1 -all\n",
	}, "")
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

// TestRunQuery_ResolversOnly pins the README library example: a caller sets
// Query.Resolvers (not Query.Server) and calls RunQuery. The library must
// bridge Resolvers -> dialed server itself, so this must return answers, not
// a "missing address" dial error.
func TestRunQuery_ResolversOnly(t *testing.T) {
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))

	host, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", srv.Addr, err)
	}
	// Point the resolver bridge at testdns's random port for the test.
	restore := dnsPort
	dnsPort = port
	defer func() { dnsPort = restore }()

	q := &Query{
		Hostname:  "example.com",
		Types:     []string{"A"},
		Resolvers: NewResolvers(net.ParseIP(host)),
		// Server deliberately left empty.
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	if got := Render(answers, false); got != "A\t\t1.2.3.4\n" {
		t.Errorf("got %q, want A record", got)
	}
}

// TestRunQuery_ServerWinsOverResolvers documents precedence: an explicit
// Server is dialed even when Resolvers is also set (the CLIs rely on this,
// picking the resolver themselves and setting Server per hostname).
func TestRunQuery_ServerWinsOverResolvers(t *testing.T) {
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))

	q := &Query{
		Hostname:  "example.com",
		Types:     []string{"A"},
		Server:    srv.Addr,
		Resolvers: NewResolvers(net.ParseIP("203.0.113.1")), // bogus; must be ignored
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	if got := Render(answers, false); got != "A\t\t1.2.3.4\n" {
		t.Errorf("got %q, want A record from Server", got)
	}
}

// TestRunQuery_ApexErrorSurvivesBestEffortProbe pins that enabling a
// best-effort probe (Www here; Usd is the same code path) does NOT suppress
// errors on the apex query types. RunQuery previously flipped the shared
// q.IgnoreErrors true so the probes wouldn't fail the query — but the apex
// lookups read the same field, so a real apex SERVFAIL silently vanished
// (and that write raced with the apex reads, caught under -race).
func TestRunQuery_ApexErrorSurvivesBestEffortProbe(t *testing.T) {
	srv := testdns.New(t)
	srv.SetRcode("example.com", dns.TypeA, dns.RcodeServerFailure)
	// www.example.com is unregistered → NXDOMAIN; as a best-effort probe it
	// must stay silent and not add an error of its own.

	q := &Query{
		Hostname: "example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
		Www:      true,
	}
	answers, errs := RunQuery(q)
	if len(answers) != 0 {
		t.Errorf("expected no answers, got %v", answers)
	}

	var apexErr *QueryError
	for _, e := range errs {
		var qe *QueryError
		if errors.As(e, &qe) && qe.Type == "A" && qe.Hostname == "example.com" {
			apexErr = qe
		}
	}
	if apexErr == nil {
		t.Fatalf("apex A SERVFAIL was suppressed by the www probe; errs=%v", errs)
	}
	if apexErr.Code != "SERVFAIL" {
		t.Errorf("apex error code = %q, want SERVFAIL", apexErr.Code)
	}
}

// TestResolvers_NextConcurrent exercises Next() from many goroutines on one
// shared *Resolvers — the pattern dnx uses and that RunQuery now triggers via
// resolveServer. Run under -race to catch unsynchronized Index access; it also
// guards against an out-of-range index panic from the read-modify-write.
func TestResolvers_NextConcurrent(t *testing.T) {
	r, err := NewResolversFromStrings([]string{"1.1.1.1", "8.8.8.8", "9.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	const goroutines, iters = 8, 500
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if ip := r.Next(); ip == nil {
					t.Error("Next() returned nil")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestRunQuery_NXDomain(t *testing.T) {
	srv := testdns.New(t)
	// Don't register anything → every query returns NXDOMAIN

	q := &Query{
		Hostname: "missing.example.com",
		Types:    []string{"A", "MX"},
		Server:   srv.Addr,
	}
	answers, errs := RunQuery(q)
	if len(answers) != 0 {
		t.Errorf("expected no answers, got %d: %v", len(answers), answers)
	}
	if !errsContain(errs, "NXDOMAIN") {
		t.Errorf("expected NXDOMAIN in errors, got %v", errs)
	}
}

func TestRunQuery_CNAMERequery(t *testing.T) {
	srv := testdns.New(t)
	// www.example.com → CNAME → example.com → A
	srv.Add(testdns.MustRR("www.example.com. 300 IN CNAME example.com."))
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))

	q := &Query{
		Hostname: "www.example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	got := Render(answers, false)
	want := "A\t\t1.2.3.4\n"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRunQuery_Www_UntaggedDedups(t *testing.T) {
	srv := testdns.New(t)
	// Apex and www share an IP — the duplicate row should collapse.
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))
	srv.Add(testdns.MustRR("www.example.com. 300 IN A 1.2.3.4"))

	q := &Query{
		Hostname: "example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
		Www:      true,
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	got := Render(answers, false)
	want := "A\t\t1.2.3.4\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRunQuery_Www_UntaggedDistinctIPs(t *testing.T) {
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))
	srv.Add(testdns.MustRR("www.example.com. 300 IN A 5.6.7.8"))

	q := &Query{
		Hostname: "example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
		Www:      true,
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	got := Render(answers, false)
	want := "A\t\t1.2.3.4\nA\t\t5.6.7.8\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRunQuery_Www_Tagged(t *testing.T) {
	srv := testdns.New(t)
	// Even when the IPs match, tagged mode must emit one row per hostname.
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))
	srv.Add(testdns.MustRR("www.example.com. 300 IN A 1.2.3.4"))

	q := &Query{
		Hostname: "example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
		Www:      true,
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	got := Render(answers, true)
	want := "example.com\tA\t\t1.2.3.4\nwww.example.com\tA\t\t1.2.3.4\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRunQuery_Www_CustomTypes(t *testing.T) {
	srv := testdns.New(t)
	// Apex queried for A; www probe overridden to MX,A via WwwTypes.
	// Verifies q.WwwTypes wins over the address-only default — AAAA
	// must NOT be fired against www.
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))
	srv.Add(testdns.MustRR("www.example.com. 300 IN A 5.6.7.8"))
	srv.Add(testdns.MustRR("www.example.com. 300 IN MX 10 mx.example.com."))
	srv.Add(testdns.MustRR("www.example.com. 300 IN AAAA 2001:db8::1")) // should NOT appear

	q := &Query{
		Hostname: "example.com",
		Types:    []string{"A"},
		WwwTypes: []string{"MX", "A"},
		Server:   srv.Addr,
		Www:      true,
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	got := Render(answers, true)
	want := strings.Join([]string{
		"example.com\tA\t\t1.2.3.4\n",
		"www.example.com\tA\t\t5.6.7.8\n",
		"www.example.com\tMX\t10\tmx.example.com.\n",
	}, "")
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRunQuery_Www_MissingIsSilent(t *testing.T) {
	srv := testdns.New(t)
	// Apex exists, www does not. The NXDOMAIN on www.* shouldn't surface
	// as an error and shouldn't add any rows.
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))

	q := &Query{
		Hostname: "example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
		Www:      true,
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	got := Render(answers, false)
	want := "A\t\t1.2.3.4\n"
	if got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

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

func TestRunQuery_StructuredDedupsCNAMEHopAcrossTypes(t *testing.T) {
	srv := testdns.New(t)
	// www.example.com is a CNAME to example.com, which has both A and AAAA.
	// Querying both types independently chases the same CNAME hop twice
	// (once per dnsLookup goroutine) — a duplicate by construction, not a
	// wire duplicate. Structured output must still only carry it once.
	srv.Add(testdns.MustRR("www.example.com. 300 IN CNAME example.com."))
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))
	srv.Add(testdns.MustRR("example.com. 300 IN AAAA ::1"))

	q := &Query{
		Hostname: "www.example.com",
		Types:    []string{"A", "AAAA"},
		Server:   srv.Addr,
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}

	out := BuildOutput(answers, q, nil)

	var cnames, as, aaaas []OutputAnswer
	for _, a := range out.Answers {
		switch a.Type {
		case "CNAME":
			cnames = append(cnames, a)
		case "A":
			as = append(as, a)
		case "AAAA":
			aaaas = append(aaaas, a)
		}
	}

	if len(cnames) != 1 {
		t.Fatalf("CNAME answers = %d, want 1 (collapsed across A and AAAA queries): %+v", len(cnames), out.Answers)
	}
	if cnames[0].Name != "www.example.com." {
		t.Errorf("CNAME name = %q, want www.example.com.", cnames[0].Name)
	}
	if cnames[0].Rdata != "example.com." {
		t.Errorf("CNAME rdata = %q, want example.com.", cnames[0].Rdata)
	}

	if len(as) != 1 || as[0].Rdata != "1.2.3.4" {
		t.Errorf("A answers = %+v, want one with rdata 1.2.3.4", as)
	}
	if len(aaaas) != 1 || aaaas[0].Rdata != "::1" {
		t.Errorf("AAAA answers = %+v, want one with rdata ::1", aaaas)
	}
}

func errsContain(errs []error, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), substr) {
			return true
		}
	}
	return false
}

func TestRunNXQuery_NX(t *testing.T) {
	srv := testdns.New(t)
	q := &Query{Hostname: "totally-missing.example.com", Server: srv.Addr}
	if n := RunNXQuery(q); n != 0 {
		t.Errorf("RunNXQuery on unregistered name = %d, want 0", n)
	}
}

// TestRunNXQuery_ResolversOnly is the RunNXQuery counterpart to
// TestRunQuery_ResolversOnly: setting Resolvers (not Server) must dial the
// bridged resolver, not the empty string.
func TestRunNXQuery_ResolversOnly(t *testing.T) {
	srv := testdns.New(t)
	host, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", srv.Addr, err)
	}
	restore := dnsPort
	dnsPort = port
	defer func() { dnsPort = restore }()

	q := &Query{
		Hostname:  "totally-missing.example.com",
		Resolvers: NewResolvers(net.ParseIP(host)),
	}
	if n := RunNXQuery(q); n != 0 {
		t.Errorf("RunNXQuery (resolvers-only) on unregistered name = %d, want 0", n)
	}
}

func TestRunNXQuery_NotNX(t *testing.T) {
	srv := testdns.New(t)
	// Register SOA only — MX and NS will be NoData (NoError + empty answer),
	// not NXDOMAIN. So responseCount should be 3 (none of the three returned NXDOMAIN).
	srv.Add(testdns.MustRR("present.example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600"))

	q := &Query{Hostname: "present.example.com", Server: srv.Addr}
	if n := RunNXQuery(q); n != 3 {
		t.Errorf("RunNXQuery on existing name = %d, want 3", n)
	}
}

func TestRunNXQuery_CustomTypes(t *testing.T) {
	srv := testdns.New(t)
	// Email-style probe: only MX matters. Name has no MX → NXDOMAIN-for-purposes-of-the-probe.
	q := &Query{
		Hostname: "no-mx.example.com",
		Types:    []string{"MX"},
		Server:   srv.Addr,
	}
	if n := RunNXQuery(q); n != 0 {
		t.Errorf("RunNXQuery(MX only) on unregistered name = %d, want 0", n)
	}
}

func TestRunNXQuery_ServFail(t *testing.T) {
	srv := testdns.New(t)
	// SERVFAIL on all three default NXTypes → none counted as NXDOMAIN, so
	// responseCount = 3 (i.e. "not NX, looks alive").
	for _, qt := range []uint16{dns.TypeMX, dns.TypeNS, dns.TypeSOA} {
		srv.SetRcode("flaky.example.com", qt, dns.RcodeServerFailure)
	}
	q := &Query{Hostname: "flaky.example.com", Server: srv.Addr}
	if n := RunNXQuery(q); n != 3 {
		t.Errorf("RunNXQuery on SERVFAIL name = %d, want 3 (SERVFAIL is not NXDOMAIN)", n)
	}
}
func TestNaturalCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"9", "10", -1},             // numeric, not lexical
		{"10", "9", 1},              //
		{"20", "100", -1},           //
		{"MX\t9\t", "MX\t10\t", -1}, // full text lines
		{"10.0.0.2", "10.0.0.10", -1},
		{"a", "a", 0},
		{"A", "AAAA", -1}, // shorter shared-prefix sorts first
		{"007", "7", 1},   // equal value, more leading zeros sorts first
		{"", "0", -1},
	}
	for _, tt := range tests {
		if got := naturalCompare(tt.a, tt.b); got != tt.want {
			t.Errorf("naturalCompare(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
		// Antisymmetry: swapping args negates the sign.
		if got := naturalCompare(tt.b, tt.a); got != -tt.want {
			t.Errorf("naturalCompare(%q, %q) = %d, want %d (antisymmetry)", tt.b, tt.a, got, -tt.want)
		}
	}
}

func TestRender_NaturalMXOrder(t *testing.T) {
	srv := testdns.New(t)
	for _, mx := range []string{"9 b", "10 a", "20 c", "100 d"} {
		srv.Add(testdns.MustRR("example.com. 300 IN MX " + mx + ".example.com."))
	}
	q := &Query{Hostname: "example.com", Types: []string{"MX"}, Server: srv.Addr}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	want := strings.Join([]string{
		"MX\t9\tb.example.com.\n",
		"MX\t10\ta.example.com.\n",
		"MX\t20\tc.example.com.\n",
		"MX\t100\td.example.com.\n",
	}, "")
	if got := Render(answers, false); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRender_HTTPS(t *testing.T) {
	// HTTPS/SVCB text: priority in the numeric column, then target and
	// space-joined key=value SvcParams in the value column. Params emerge in
	// canonical ascending-key wire order (alpn=1, port=3, ipv4hint=4) after
	// the query's encode/decode round-trip, regardless of zone-file order.
	srv := testdns.New(t)
	srv.Add(testdns.MustRR(`example.com. 300 IN HTTPS 1 . alpn="h2,h3" ipv4hint=1.2.3.4 port=8443`))
	q := &Query{Hostname: "example.com", Types: []string{"HTTPS"}, Server: srv.Addr}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	want := "HTTPS\t1\t. alpn=h2,h3 port=8443 ipv4hint=1.2.3.4\n"
	if got := Render(answers, false); got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRender_DS(t *testing.T) {
	// DS text: key tag / algorithm / digest type in the numeric column, hex
	// digest in the value column. (All-digit digest sidesteps hex-case
	// normalization across the wire round-trip.)
	srv := testdns.New(t)
	srv.Add(testdns.MustRR(`example.com. 3600 IN DS 12345 13 2 1234567890123456789012345678901234567890123456789012345678901234`))
	q := &Query{Hostname: "example.com", Types: []string{"DS"}, Server: srv.Addr}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	want := "DS\t12345 13 2\t1234567890123456789012345678901234567890123456789012345678901234\n"
	if got := Render(answers, false); got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRender_CNAMEChainFoldedOut(t *testing.T) {
	// Text cares about the end result: a CNAME chased during an A query is
	// folded out, leaving only the resolved A line (unchanged legacy output).
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("www.example.com. 300 IN CNAME example.com."))
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))
	q := &Query{Hostname: "www.example.com", Types: []string{"A"}, Server: srv.Addr}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	if got, want := Render(answers, false), "A\t\t1.2.3.4\n"; got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

func TestRender_ExplicitCNAMEStillRenders(t *testing.T) {
	// An explicit `-t CNAME` query is not chased, so the CNAME must still
	// render as text (the fold-out only applies to chased chain hops).
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("www.example.com. 300 IN CNAME example.com."))
	q := &Query{Hostname: "www.example.com", Types: []string{"CNAME"}, Server: srv.Addr}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	if got, want := Render(answers, false), "CNAME\t\texample.com.\n"; got != want {
		t.Errorf("got:\n%q\nwant:\n%q", got, want)
	}
}

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

func TestRunQuery_USD_NewProbes(t *testing.T) {
	// Lock in that the newer underscore labels (TLSRPT, BIMI, atproto) are
	// actually probed: a real TXT at each must surface as an Answer under --usd.
	srv := testdns.New(t)
	srv.Add(testdns.MustRR(`_smtp._tls.example.com. 300 IN TXT "v=TLSRPTv1; rua=mailto:tls@example.com"`))
	srv.Add(testdns.MustRR(`default._bimi.example.com. 300 IN TXT "v=BIMI1; l=https://example.com/logo.svg"`))
	srv.Add(testdns.MustRR(`_atproto.example.com. 300 IN TXT "did=did:plc:abc123"`))
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))

	q := &Query{Hostname: "example.com", Types: []string{"A"}, Server: srv.Addr, Usd: true}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}

	got := make(map[string]bool)
	for _, a := range answers {
		got[a.Hostname] = true
	}
	for _, want := range []string{"_smtp._tls.example.com", "default._bimi.example.com", "_atproto.example.com"} {
		if !got[want] {
			t.Errorf("missing USD probe answer for %s; answers = %+v", want, answers)
		}
	}
}

func TestRunQuery_USDEmpty_RenderGolden(t *testing.T) {
	srv := testdns.New(t)
	srv.AddEmpty("_domainkey.example.com")
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))

	q := &Query{Hostname: "example.com", Types: []string{"A"}, Server: srv.Addr, Usd: true}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}

	untagged := Render(answers, false)
	wantUntagged := "TXT\t\t_domainkey.example.com. [present; no records]\n"
	if !strings.Contains(untagged, wantUntagged) {
		t.Errorf("untagged Render = %q, want it to contain %q", untagged, wantUntagged)
	}

	tagged := Render(answers, true)
	wantTagged := "_domainkey.example.com\tTXT\t\t[present; no records]\n"
	if !strings.Contains(tagged, wantTagged) {
		t.Errorf("tagged Render = %q, want it to contain %q", tagged, wantTagged)
	}
}

// TestNormalizeHost pins the IDNA canonicalization contract: UTF-8 U-labels
// become A-labels (punycode), names are case-folded, and the labels dany
// relies on — underscore-prefixed names, already-punycode names, plain ASCII —
// pass through unchanged. Malformed names return the original string + an error
// so best-effort callers (RunNXQuery) can still try.
func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"utf8 u-label", "café.example.com", "xn--caf-dma.example.com", false},
		{"case folded", "CAFÉ.EXAMPLE.COM", "xn--caf-dma.example.com", false},
		{"idempotent a-label", "xn--caf-dma.example.com", "xn--caf-dma.example.com", false},
		{"multi-byte", "münchen.de", "xn--mnchen-3ya.de", false},
		{"plain ascii", "example.com", "example.com", false},
		{"underscore usd label", "_dmarc.example.com", "_dmarc.example.com", false},
		{"multi-level underscore", "_smtp._tls.example.com", "_smtp._tls.example.com", false},
		{"trailing dot preserved", "example.com.", "example.com.", false},
		{"empty", "", "", false},
		// Malformed A-label: ToASCII rejects it; we return the input verbatim.
		{"invalid punycode", "xn--a.example.com", "xn--a.example.com", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeHost(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("normalizeHost(%q) err = %v, wantErr = %v", tc.in, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("normalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRunQuery_IDNA proves the library normalizes a UTF-8 hostname to its
// A-label before dialing: the zone only has the punycode name, so a match
// requires the conversion. It also pins that the emitted Answer carries the
// A-label form and that the caller's *Query is left unmutated.
func TestRunQuery_IDNA(t *testing.T) {
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("xn--caf-dma.example.com. 300 IN A 1.2.3.4"))

	q := &Query{
		Hostname: "café.example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
	}
	answers, errs := RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	if got := Render(answers, false); got != "A\t\t1.2.3.4\n" {
		t.Errorf("Render = %q, want A record", got)
	}
	if len(answers) != 1 || answers[0].Hostname != "xn--caf-dma.example.com" {
		t.Errorf("Answer.Hostname = %q, want the A-label form", answers[0].Hostname)
	}
	if q.Hostname != "café.example.com" {
		t.Errorf("RunQuery mutated q.Hostname to %q; want it left as the caller set it", q.Hostname)
	}
}

// TestRunQuery_InvalidNameError pins that an IDNA-invalid hostname is a single
// structured INVALID_NAME error and fires no lookups (no partial answers).
func TestRunQuery_InvalidNameError(t *testing.T) {
	srv := testdns.New(t)

	q := &Query{
		Hostname: "xn--a.example.com",
		Types:    []string{"A", "MX"},
		Server:   srv.Addr,
	}
	answers, errs := RunQuery(q)
	if len(answers) != 0 {
		t.Errorf("got %d answers, want 0 for an invalid name", len(answers))
	}
	if len(errs) != 1 {
		t.Fatalf("got %d errors, want exactly 1; errs = %v", len(errs), errs)
	}
	var qe *QueryError
	if !errors.As(errs[0], &qe) {
		t.Fatalf("error is not a *QueryError: %v", errs[0])
	}
	if qe.Code != "INVALID_NAME" {
		t.Errorf("QueryError.Code = %q, want INVALID_NAME", qe.Code)
	}
	if qe.Hostname != "xn--a.example.com" {
		t.Errorf("QueryError.Hostname = %q, want the original name", qe.Hostname)
	}
}

// TestRunNXQuery_IDNA proves RunNXQuery probes the A-label form: the zone has
// the punycode name existing (NoData for every NXType, so no probe returns
// NXDOMAIN), so a UTF-8 query resolves to "not NX". Without normalization the
// raw-UTF-8 name wouldn't exist and every probe would NXDOMAIN → fully NX.
func TestRunNXQuery_IDNA(t *testing.T) {
	srv := testdns.New(t)
	srv.AddEmpty("xn--caf-dma.example.com")

	q := &Query{
		Hostname: "café.example.com",
		Server:   srv.Addr,
	}
	if got := RunNXQuery(q); got != len(NXTypes) {
		t.Errorf("RunNXQuery = %d, want %d (not-NX: the A-label exists)", got, len(NXTypes))
	}
}
