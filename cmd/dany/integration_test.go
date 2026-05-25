//go:build integration

package main

import (
	"net"
	"strings"
	"testing"

	"github.com/gavincarr/dany"
)

// TestIntegrationSmoke runs the full stack against a real recursive resolver
// (8.8.8.8) for a stable RFC 2606 reserved domain. It only checks that we
// get *some* sensible records — comprehensive output correctness is covered
// offline in the library tests. Run with: go test -tags integration ./...
func TestIntegrationSmoke(t *testing.T) {
	q, _, err := parseOpts(Options{Server: "8.8.8.8"}, []string{"example.com"}, true)
	if err != nil {
		t.Fatalf("parseOpts: %v", err)
	}
	q.Hostname = "example.com"
	q.Server = net.JoinHostPort(q.Resolvers.Next().String(), dnsPort)

	answers, errs := dany.RunQuery(q)
	if len(errs) > 0 {
		t.Fatalf("RunQuery errors: %v", errs)
	}
	out := dany.Render(answers, false)
	for _, want := range []string{"A\t", "SOA\t"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q line:\n%s", want, out)
		}
	}
}
