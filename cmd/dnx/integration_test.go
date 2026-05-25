//go:build integration

package main

import (
	"testing"

	"github.com/gavincarr/dany"
)

// TestIntegrationSmoke runs RunNXQuery against a real recursive resolver
// (8.8.8.8) for two stable cases: a known-good RFC 2606 reserved domain
// and a guaranteed-NX label. Run with: go test -tags integration ./...
func TestIntegrationSmoke(t *testing.T) {
	good := &dany.Query{Hostname: "example.com", Server: "8.8.8.8:53"}
	if n := dany.RunNXQuery(good); n == 0 {
		t.Errorf("example.com reported as NX (count=0); expected MX/NS/SOA to resolve")
	}

	// Use a .invalid TLD (RFC 2606) which by definition never resolves.
	nx := &dany.Query{Hostname: "definitely-does-not-exist.invalid", Server: "8.8.8.8:53"}
	if n := dany.RunNXQuery(nx); n != 0 {
		t.Errorf(".invalid TLD returned count=%d; expected 0 (full NXDOMAIN)", n)
	}
}
