package main

import (
	"strings"
	"testing"

	"github.com/gavincarr/dany"
)

// testTypeMap builds the same case-insensitive type map that parseOpts uses.
func testTypeMap() map[string]bool {
	tm := make(map[string]bool)
	for _, t := range dany.SupportedRRTypes {
		tm[t] = true
		tm[strings.ToLower(t)] = true
	}
	return tm
}

func TestCheckValidTypes(t *testing.T) {
	tm := testTypeMap()
	tests := []struct {
		name   string
		types  []string
		errSub string // empty = expect no error
	}{
		{name: "all valid uppercase", types: []string{"A", "MX", "TXT"}},
		{name: "all valid lowercase", types: []string{"a", "mx", "txt"}},
		{name: "mixed case", types: []string{"A", "mx"}},
		{name: "single bad type", types: []string{"XYZ"}, errSub: "XYZ"},
		{name: "mixed valid and bad", types: []string{"a", "XYZ", "mx"}, errSub: "XYZ"},
		{name: "multiple bad", types: []string{"FOO", "BAR"}, errSub: "FOO,BAR"},
		{name: "empty slice", types: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkValidTypes(tc.types, tm)
			if tc.errSub == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errSub)
			}
			if !strings.Contains(err.Error(), tc.errSub) {
				t.Errorf("error = %q, want substring %q", err, tc.errSub)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	tm := testTypeMap()
	tests := []struct {
		name         string
		preSetServer string
		preSetTypes  []string
		args         []string
		wantArgs     []string
		wantServer   string
		wantTypes    []string
		errSub       string
	}{
		{
			name:     "plain hostname only",
			args:     []string{"example.com"},
			wantArgs: []string{"example.com"},
		},
		{
			name:       "@ip server arg",
			args:       []string{"example.com", "@8.8.8.8"},
			wantArgs:   []string{"example.com"},
			wantServer: "8.8.8.8:53",
		},
		{
			name:      "bare RR type",
			args:      []string{"example.com", "mx"},
			wantArgs:  []string{"example.com"},
			wantTypes: []string{"mx"},
		},
		{
			name:      "comma-separated types",
			args:      []string{"example.com", "a,mx,txt"},
			wantArgs:  []string{"example.com"},
			wantTypes: []string{"a", "mx", "txt"},
		},
		{
			name:       "all three deprecated forms together",
			args:       []string{"example.com", "@1.1.1.1", "a,mx"},
			wantArgs:   []string{"example.com"},
			wantServer: "1.1.1.1:53",
			wantTypes:  []string{"a", "mx"},
		},
		{
			name:   "bad @ip",
			args:   []string{"example.com", "@notanip"},
			errSub: "unable to parse ip address",
		},
		{
			name:         "duplicate @ip when one already set",
			preSetServer: "8.8.8.8:53",
			args:         []string{"example.com", "@1.1.1.1"},
			errSub:       "already have",
		},
		{
			name:        "duplicate types when already set",
			preSetTypes: []string{"a"},
			args:        []string{"example.com", "mx,txt"},
			errSub:      "already have",
		},
		{
			name:   "invalid type in comma list",
			args:   []string{"example.com", "a,XYZ,mx"},
			errSub: "XYZ",
		},
		{
			name:     "multiple hostnames",
			args:     []string{"example.com", "another.com"},
			wantArgs: []string{"example.com", "another.com"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := &dany.Query{Server: tc.preSetServer, Types: tc.preSetTypes}
			gotArgs, err := parseArgs(q, tc.args, tm, true)
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
			if !equalStringSlices(gotArgs, tc.wantArgs) {
				t.Errorf("args = %v, want %v", gotArgs, tc.wantArgs)
			}
			if tc.wantServer != "" && q.Server != tc.wantServer {
				t.Errorf("q.Server = %q, want %q", q.Server, tc.wantServer)
			}
			if tc.wantTypes != nil && !equalStringSlices(q.Types, tc.wantTypes) {
				t.Errorf("q.Types = %v, want %v", q.Types, tc.wantTypes)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
