package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/gavincarr/dany"
)

var update = flag.Bool("update", false, "update .golden files")

func TestDNXDefaults(t *testing.T) {
	testdata := "testdata/hostnames_delta_com.txt"
	data, err := ioutil.ReadFile(testdata)
	if err != nil {
		log.Fatal(err)
	}
	hostnames := strings.Split(string(data), "\n")

	golden := "testdata/golden/hostnames_delta_com_nx.txt"
	hostnames_nx, err := ioutil.ReadFile(golden)
	if err != nil {
		log.Fatal(err)
	}

	resolvers, _, err := parseOpts(opts)
	if err != nil {
		log.Fatal(err)
	}

	// Seem to need to constrain number of goroutines in flight
	sem := make(chan bool, 10)
	ch := make(chan string, len(hostnames))
	for _, hostname := range hostnames {
		sem <- true
		go func(h string) {
			defer func() { <-sem }()
			server := net.JoinHostPort(resolvers.Next().String(), dnsPort)
			responseCount := dany.RunNXQuery(&dany.Query{Hostname: h, Server: server})
			if responseCount == 0 {
				ch <- h
			} else {
				ch <- ""
			}
		}(hostname)
	}
	// Wait for remaining goroutines by refilling all sem slots
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}

	var got []string
	count := 0
	for count < len(hostnames) {
		select {
		case nx := <-ch:
			if nx != "" {
				got = append(got, nx)
			}
			count++
		}
	}

	sort.Strings(got)
	gotString := strings.Join(got, "\n") + "\n"

	if gotString != string(hostnames_nx) {
		// Support -u/--update
		if *update {
			if err := ioutil.WriteFile(golden, []byte(gotString), 0644); err != nil {
				t.Fatalf("failed to update %q golden file: %s\n", golden, err)
			}
		} else {
			// Otherwise report errors
			t.Errorf("errors:\ngotString:\n%s\nhostnames_nx:\n%s\n",
				gotString, string(hostnames_nx))
		}
	}
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
