package main

import (
	"strings"
	"testing"
)

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
