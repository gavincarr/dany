package main

import (
	"flag"
	"io/ioutil"
	"testing"
)

var update = flag.Bool("update", false, "update .golden files")

func TestDefaults(t *testing.T) {
	var hostnames = []string{
		"openfusion.com.au",
		"profound.net",
	}
	for _, hostname := range hostnames {
		golden := "testdata/" + hostname + ".golden"
		actual := dany(nil, hostname)

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

func TestSpecific(t *testing.T) {
	var tests = []struct {
		hostname string
		types    []string
		label    string
	}{
		{"openfusion.com.au", []string{"a"}, "a"},
		{"openfusion.com.au", []string{"cname"}, "cname"},
		{"openfusion.com.au", []string{"soa", "txt"}, "soa_txt"},
		{"profound.net", []string{"a", "mx"}, "a_mx"},
		{"www.zoom.us", []string{"ns"}, "ns"},
		{"www.zoom.us", []string{"cname"}, "cname"},
		{"www.zoom.us", []string{"soa", "ns"}, "soa_ns"},
	}
	for _, test := range tests {
		golden := "testdata/" + test.hostname + "_" + test.label + ".golden"
		actual := dany(test.types, test.hostname)

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
