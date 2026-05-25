package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gavincarr/dany"
	"github.com/gavincarr/dany/internal/testdns"
)

// withTestDNS spins up an in-process DNS server and points the package's
// dnsPort at its randomly-assigned port for the duration of the test, so
// runCLI's resolver IP → host:port construction lands on testdns.
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

func TestOpenOutput(t *testing.T) {
	t.Run("empty path returns defaultOut", func(t *testing.T) {
		var buf bytes.Buffer
		w, c, err := openOutput("", &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if w != &buf {
			t.Errorf("writer = %v, want defaultOut (&buf)", w)
		}
		// Closing the nop closer must be safe and must NOT close defaultOut.
		if err := c.Close(); err != nil {
			t.Errorf("Close() = %v, want nil", err)
		}
	})

	t.Run("valid path opens and truncates (ignores defaultOut)", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.txt")
		// Pre-create with content so we can confirm os.Create truncates.
		if err := os.WriteFile(path, []byte("stale\n"), 0644); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		w, c, err := openOutput(path, &buf)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, err := w.Write([]byte("fresh\n")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if err := c.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != "fresh\n" {
			t.Errorf("file contents = %q, want %q (truncation failed?)", got, "fresh\n")
		}
		if buf.Len() != 0 {
			t.Errorf("defaultOut buffer = %q, want empty when -o is set", buf.String())
		}
	})

	t.Run("invalid path returns error", func(t *testing.T) {
		// Parent dir doesn't exist → os.Create fails.
		path := filepath.Join(t.TempDir(), "no-such-subdir", "out.txt")
		_, _, err := openOutput(path, os.Stdout)
		if err == nil {
			t.Errorf("expected error for unreachable path %q, got nil", path)
		}
	})
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

func TestParseOpts_WwwTypesMirroring(t *testing.T) {
	tests := []struct {
		name         string
		opts         Options
		wantTypes    []string
		wantWwwTypes []string // nil means: expect WwwTypes == nil (fall back to library default)
	}{
		{
			name:         "www without explicit types → WwwTypes nil",
			opts:         Options{Www: true},
			wantTypes:    dany.DefaultRRTypes,
			wantWwwTypes: nil,
		},
		{
			name:         "www without -w → WwwTypes still mirrored when types explicit",
			opts:         Options{Types: "a,mx"},
			wantTypes:    []string{"a", "mx"},
			wantWwwTypes: []string{"a", "mx"}, // harmless: library ignores it when !Www
		},
		{
			name:         "www + explicit -t → WwwTypes mirrors q.Types",
			opts:         Options{Www: true, Types: "a,mx"},
			wantTypes:    []string{"a", "mx"},
			wantWwwTypes: []string{"a", "mx"},
		},
		{
			name:         "www + -a → WwwTypes mirrors the all-types set",
			opts:         Options{Www: true, All: true},
			wantTypes:    dany.SupportedRRTypes,
			wantWwwTypes: dany.SupportedRRTypes,
		},
		{
			name:         "no www, no explicit types → WwwTypes nil",
			opts:         Options{},
			wantTypes:    dany.DefaultRRTypes,
			wantWwwTypes: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q, _, err := parseOpts(tc.opts, []string{"example.com"}, true)
			if err != nil {
				t.Fatalf("parseOpts: %v", err)
			}
			if !equalStringSlices(q.Types, tc.wantTypes) {
				t.Errorf("q.Types = %v, want %v", q.Types, tc.wantTypes)
			}
			if tc.wantWwwTypes == nil {
				if q.WwwTypes != nil {
					t.Errorf("q.WwwTypes = %v, want nil", q.WwwTypes)
				}
			} else if !equalStringSlices(q.WwwTypes, tc.wantWwwTypes) {
				t.Errorf("q.WwwTypes = %v, want %v", q.WwwTypes, tc.wantWwwTypes)
			}
		})
	}
}

func TestRunCLI_Text(t *testing.T) {
	srv := withTestDNS(t)
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))
	srv.Add(testdns.MustRR("example.com. 300 IN MX 10 mx.example.com."))

	opts := Options{
		Server: "127.0.0.1",
		Types:  "A,MX",
		Fmt:    "text",
	}
	opts.Args.Hostname = "example.com"

	var buf bytes.Buffer
	if err := runCLI(opts, &buf); err != nil {
		t.Fatalf("runCLI: %v", err)
	}

	want := "A\t\t1.2.3.4\nMX\t10\tmx.example.com.\n"
	if got := buf.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRunCLI_JSON(t *testing.T) {
	srv := withTestDNS(t)
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))

	opts := Options{
		Server: "127.0.0.1",
		Types:  "A",
		Fmt:    "json",
	}
	opts.Args.Hostname = "example.com"

	var buf bytes.Buffer
	if err := runCLI(opts, &buf); err != nil {
		t.Fatalf("runCLI: %v", err)
	}

	// RenderJSON is NDJSON-ready (one doc per line) — for a single hostname,
	// the buffer holds exactly one JSON object followed by '\n'.
	var env struct {
		Query struct {
			Hostname string `json:"hostname"`
		} `json:"query"`
		Answers []struct {
			Type string `json:"type"`
		} `json:"answers"`
	}
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if env.Query.Hostname != "example.com" {
		t.Errorf("query.hostname = %q, want example.com", env.Query.Hostname)
	}
	if len(env.Answers) != 1 || env.Answers[0].Type != "A" {
		t.Errorf("answers = %+v, want one A record", env.Answers)
	}
}

func TestRunCLI_OutputFileOverridesWriter(t *testing.T) {
	srv := withTestDNS(t)
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))

	outPath := filepath.Join(t.TempDir(), "out.txt")
	opts := Options{
		Server: "127.0.0.1",
		Types:  "A",
		Fmt:    "text",
		Output: outPath,
	}
	opts.Args.Hostname = "example.com"

	var buf bytes.Buffer
	if err := runCLI(opts, &buf); err != nil {
		t.Fatalf("runCLI: %v", err)
	}

	if buf.Len() != 0 {
		t.Errorf("writer received output despite -o: %q", buf.String())
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	want := "A\t\t1.2.3.4\n"
	if string(got) != want {
		t.Errorf("file = %q, want %q", got, want)
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
