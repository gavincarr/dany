package dany

import (
	"net"
	"os"
	"path/filepath"
	"strings"
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
		want    []string  // empty means: expect error
		errSub  string    // substring expected in error message
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