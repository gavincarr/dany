package main

import (
	"flag"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gavincarr/dany"
)

var update = flag.Bool("update", false, "update .golden files")

func TestDefaults(t *testing.T) {
	var hostnames = []string{
		"openfusion.com.au",
		"profound.net",
		"shell.com",
	}

	query, _, err := parseOpts(Options{}, []string{}, true)
	if err != nil {
		log.Fatal(err)
	}
	query.Server = net.JoinHostPort(query.Resolvers.Next().String(), dnsPort)

	for _, hostname := range hostnames {
		golden := "testdata/" + hostname + ".golden"
		query.Hostname = hostname
		actual, errors := dany.RunQuery(query)
		if errors != "" {
			t.Fatalf("RunQuery errors for %q: %s", hostname, errors)
		}

		// Read expected output from golden file
		expected, err := ioutil.ReadFile(golden)
		if err != nil {
			t.Fatalf("failed reading .golden: %s\n", err)
		}

		// Test
		if actual != string(expected) {
			// Support -u/--update
			if *update {
				if err := ioutil.WriteFile(golden, []byte(actual), 0644); err != nil {
					t.Fatalf("failed to update %q golden file: %s\n", golden, err)
				}
			} else {
				// Otherwise report errors
				t.Errorf("%q output errors, default types:\nactual:\n%s\nexpected:\n%s\n",
					hostname, actual, string(expected))
			}
		}
	}
}

func TestTypesParseArgs(t *testing.T) {
	var tests = []struct {
		hostname string
		types    []string
		label    string
	}{
		{"openfusion.com.au", []string{"a"}, "a"},
		{"openfusion.com.au", []string{"cname"}, "cname"},
		{"openfusion.com.au", []string{"soa", "txt"}, "soa_txt"},
		{"profound.net", []string{"a", "mx"}, "a_mx"},
		{"cisco.com", []string{"a", "aaaa"}, "a_aaaa"},
		{"_sip._tcp.cisco.com", []string{"srv"}, "srv"},
		{"www.zoom.us", []string{"ns"}, "ns"},
		{"www.zoom.us", []string{"cname"}, "cname"},
		{"www.zoom.us", []string{"soa", "ns"}, "soa_ns"},
		{"shell.com", []string{"caa", "dnskey"}, "caa_dnskey"},
		{"comcast.com", []string{"nsec", "soa"}, "nsec_soa"},
		{"comcast.com", []string{"rrsig", "soa"}, "rrsig_soa"},
	}

	for _, test := range tests {
		golden := "testdata/" + test.hostname + "_" + test.label + ".golden"

		// Randomise args
		r := rand.New(rand.NewSource(time.Now().Unix()))
		args := []string{test.hostname, "@8.8.8.8", strings.Join(test.types, ",")}
		argsRand := make([]string, len(args))
		perm := r.Perm(len(args))
		for i, randIndex := range perm {
			argsRand[i] = args[randIndex]
		}
		query, args, err := parseOpts(Options{}, argsRand, true)
		if err != nil {
			log.Fatal(err)
		}
		if query.Server == "" {
			query.Server = net.JoinHostPort(query.Resolvers.Next().String(), dnsPort)
		}
		query.Hostname = args[0]

		actual, errors := dany.RunQuery(query)
		if errors != "" {
			t.Fatalf("RunQuery errors for %q %v: %s", test.hostname, test.types, errors)
		}

		// Read expected output from golden file
		expected, err := ioutil.ReadFile(golden)
		if err != nil {
			t.Fatalf("failed reading .golden: %s\n", err)
		}

		// Test
		if actual != string(expected) {
			// Support -u/--update
			if *update {
				if err := ioutil.WriteFile(golden, []byte(actual), 0644); err != nil {
					t.Fatalf("failed to update %q golden file: %s\n", golden, err)
				}
			} else {
				// Otherwise report errors
				t.Errorf("%q output errors, default types:\nactual:\n%s\nexpected:\n%s\n",
					test.hostname, actual, string(expected))
			}
		}
	}
}

func TestPtr(t *testing.T) {
	var tests = []string{
		"att.com",
		"cisco.com",
		"hpe.com",
	}

	query, _, err := parseOpts(Options{}, []string{}, true)
	if err != nil {
		log.Fatal(err)
	}
	query.Server = net.JoinHostPort(query.Resolvers.Next().String(), dnsPort)
	query.Ptr = true
	query.Types = []string{"a", "aaaa"}

	for _, hostname := range tests {
		golden := "testdata/" + hostname + "_ptr.golden"
		query.Hostname = hostname
		actual, errors := dany.RunQuery(query)
		if errors != "" {
			t.Fatalf("RunQuery errors for %q: %s", hostname, errors)
		}

		// Read expected output from golden file
		expected, err := ioutil.ReadFile(golden)
		if err != nil {
			t.Fatalf("failed reading .golden: %s\n", err)
		}

		// Test
		if actual != string(expected) {
			// Support -u/--update
			if *update {
				if err := ioutil.WriteFile(golden, []byte(actual), 0644); err != nil {
					t.Fatalf("failed to update %q golden file: %s\n", golden, err)
				}
			} else {
				// Otherwise report errors
				t.Errorf("%q output errors, default types:\nactual:\n%s\nexpected:\n%s\n",
					hostname, actual, string(expected))
			}
		}
	}
}

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
