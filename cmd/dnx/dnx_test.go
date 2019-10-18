package main

import (
	dany "dany/pkg"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "update .golden files")

func TestDefaults(t *testing.T) {
	testdata := "testdata/hostnames_delta_com.txt"
	data, err := ioutil.ReadFile(testdata)
	if err != nil {
		log.Fatal(err)
	}
	hostnames := strings.Split(string(data), "\n")

	golden := "testdata/hostnames_delta_com_nx.txt"
	hostnames_nx, err := ioutil.ReadFile(golden)
	if err != nil {
		log.Fatal(err)
	}

	resolvers, err := parseOpts(opts)
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
			nxdomain, err := dany.RunNXQuery(h, server)
			if err != nil {
				log.Fatal(err)
			}
			if nxdomain {
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
