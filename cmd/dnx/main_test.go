package main

import (
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/gavincarr/dany/internal/testdns"
)

// withTestDNS spins up an in-process DNS server and points the package's
// dnsPort at its randomly-assigned port for the duration of the test.
func withTestDNS(t *testing.T) *testdns.Server {
	t.Helper()
	srv := testdns.New(t)
	_, port, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", srv.Addr, err)
	}
	orig := dnsPort
	dnsPort = port
	t.Cleanup(func() { dnsPort = orig })
	return srv
}

func TestParseOptsTypes(t *testing.T) {
	tests := []struct {
		name      string
		typesArg  string
		wantTypes []string
		errSub    string
	}{
		{name: "empty types", typesArg: "", wantTypes: nil},
		{name: "single lowercase", typesArg: "mx", wantTypes: []string{"mx"}},
		{name: "multiple uppercase", typesArg: "MX,SOA,NS", wantTypes: []string{"MX", "SOA", "NS"}},
		{name: "title case rejected (only all-upper or all-lower)", typesArg: "Mx,a", errSub: "Mx"},
		{name: "email-style", typesArg: "mx,a", wantTypes: []string{"mx", "a"}},
		{name: "single bad type", typesArg: "xyz", errSub: "xyz"},
		{name: "mixed valid and bad", typesArg: "mx,xyz,a", errSub: "xyz"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Pin Server so parseOpts doesn't touch /etc/resolv.conf.
			opts := Options{Server: "8.8.8.8", Types: tc.typesArg}
			_, gotTypes, err := parseOpts(opts)
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
			if len(gotTypes) != len(tc.wantTypes) {
				t.Fatalf("types = %v, want %v", gotTypes, tc.wantTypes)
			}
			for i, w := range tc.wantTypes {
				if gotTypes[i] != w {
					t.Errorf("types[%d] = %q, want %q", i, gotTypes[i], w)
				}
			}
		})
	}
}

func TestParseOptsBadServer(t *testing.T) {
	_, _, err := parseOpts(Options{Server: "not-an-ip"})
	if err == nil {
		t.Fatal("expected error for bad --server, got nil")
	}
	if !strings.Contains(err.Error(), "unable to parse") {
		t.Errorf("error = %q, want substring 'unable to parse'", err)
	}
}

func TestRunCLI_NXDomain(t *testing.T) {
	srv := withTestDNS(t)
	// present.example.com has an SOA → not NX. missing.example.com has
	// nothing registered → all NX-probe types (MX/NS/SOA) return NXDOMAIN.
	srv.Add(testdns.MustRR("present.example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600"))

	opts := Options{
		Server:      "127.0.0.1",
		Concurrency: 1,
	}
	opts.Args.Hostname = "present.example.com"
	opts.Args.Hostname2 = []string{"missing.example.com"}

	var buf bytes.Buffer
	if err := runCLI(opts, &buf); err != nil {
		t.Fatalf("runCLI: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "missing.example.com\n") {
		t.Errorf("missing.example.com not reported as NX:\n%s", got)
	}
	if strings.Contains(got, "present.example.com") {
		t.Errorf("present.example.com should be suppressed (has SOA):\n%s", got)
	}
}

func TestRunCLI_Count(t *testing.T) {
	srv := withTestDNS(t)
	// present.example.com exists at all (one SOA), so every NX-probe type
	// returns either an answer or NoData — none return NXDOMAIN — so the
	// count is len(NXTypes) = 3. missing.example.com → 0.
	srv.Add(testdns.MustRR("present.example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 3600"))

	opts := Options{
		Server:      "127.0.0.1",
		Concurrency: 1,
		Count:       true,
	}
	opts.Args.Hostname = "present.example.com"
	opts.Args.Hostname2 = []string{"missing.example.com"}

	var buf bytes.Buffer
	if err := runCLI(opts, &buf); err != nil {
		t.Fatalf("runCLI: %v", err)
	}

	got := buf.String()
	for _, want := range []string{"present.example.com,3\n", "missing.example.com,0\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n--- got ---\n%s", want, got)
		}
	}
}
