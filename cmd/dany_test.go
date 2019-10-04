package main

import (
	dany "dany/pkg"
	"flag"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"
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
	query.Server = net.JoinHostPort(query.Resolvers.Choose().String(), dnsPort)

	for _, hostname := range hostnames {
		golden := "testdata/" + hostname + ".golden"
		query.Hostname = hostname
		actual, errors := dany.RunQuery(query)
		if errors != "" {
			t.Fatalf("RunQuery errors: %s\n", err)
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
		query.Server = net.JoinHostPort(query.Resolvers.Choose().String(), dnsPort)
		query.Hostname = args[0]

		actual, errors := dany.RunQuery(query)
		if errors != "" {
			t.Fatalf("RunQuery errors: %s\n", err)
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
	query.Server = net.JoinHostPort(query.Resolvers.Choose().String(), dnsPort)
	query.Ptr = true
	query.Types = []string{"a", "aaaa"}

	for _, hostname := range tests {
		golden := "testdata/" + hostname + "_ptr.golden"
		query.Hostname = hostname
		actual, errors := dany.RunQuery(query)
		if errors != "" {
			t.Fatalf("RunQuery errors: %s\n", err)
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
