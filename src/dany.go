// A DNS ANY client

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	flags "github.com/jessevdk/go-flags"
)

const TIMEOUT_SECONDS = 10

// Options
var opts struct {
	Verbose bool `short:"v" long:"verbose" description:"display verbose debug output"`
}

func vprintf(format string, args ...interface{}) {
	if !opts.Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "+ "+format, args...)
}

func lookup(t, hostname string, ch chan<- string) {
	switch t {
	case "A":
		lookup_a(hostname, ch)
	case "MX":
		lookup_mx(hostname, ch)
	case "NS":
		lookup_ns(hostname, ch)
	case "TXT":
		lookup_txt(hostname, ch)
	default:
		log.Fatal("Error: unhandled type '" + t + "'")
	}
}

func lookup_a(hostname string, ch chan<- string) {
	elts, err := net.LookupIP(hostname)
	if err != nil {
		log.Fatal(err)
	}
	var text string
	for _, ip := range elts {
		if ip.To4() != nil {
			text += fmt.Sprintf("%s\t\t%s\n", "A", ip.String())
		} else {
			text += fmt.Sprintf("%s\t\t%s\n", "AAAA", ip.String())
		}
	}
	ch <- text
}

func lookup_mx(hostname string, ch chan<- string) {
	elts, err := net.LookupMX(hostname)
	if err != nil {
		log.Fatal(err)
	}
	var text string
	for _, mx := range elts {
		text += fmt.Sprintf("%s\t%d\t%s\n", "MX", mx.Pref, mx.Host)
	}
	ch <- text
}

func lookup_ns(hostname string, ch chan<- string) {
	nss, err := net.LookupNS(hostname)
	if err != nil {
		log.Fatal(err)
	}
	var elts []string
	for _, ns := range nss {
		elts = append(elts, ns.Host)
	}
	sort.Strings(elts)

	var text string
	for _, elt := range elts {
		text += fmt.Sprintf("%s\t\t%s\n", "NS", elt)
	}
	ch <- text
}

func lookup_txt(hostname string, ch chan<- string) {
	elts, err := net.LookupTXT(hostname)
	if err != nil {
		log.Fatal(err)
	}
	sort.Strings(elts)

	var text string
	for _, elt := range elts {
		text += fmt.Sprintf("%s\t\t%s\n", "TXT", elt)
	}
	ch <- text
}

func main() {
	// Parse options
	args, err := flags.Parse(&opts)
	if err != nil {
		//log.Fatal(err)
		os.Exit(1)
	}

	// Setup
	log.SetFlags(0)
	if len(args) < 1 || len(args) > 2 {
		fmt.Fprintln(os.Stderr, "usage: dany [OPTIONS] [<TYPES>] <HOSTNAME>")
		os.Exit(1)
	}
	var types []string
	var hostname string
	if len(args) == 1 {
		types = []string{"NS", "A", "MX", "TXT"}
		hostname = args[0]
	} else {
		types_arg := args[0]
		types = strings.Split(types_arg, ",")
		hostname = args[1]
	}
	vprintf("types: %s\n", types)
	vprintf("hostname: %s\n", hostname)

	// Do lookups, using resultStream to gather results
	resultStream := make(chan string, len(types))
	for _, t := range types {
		go lookup(strings.ToUpper(t), hostname, resultStream)
	}

	var results []string
	count := 0
loop:
	for {
		select {
		// Get results from resultStream
		case res := <-resultStream:
			if res != "" {
				results = append(results, res)
			}
			count++
			if count >= len(types) {
				break loop
			}
		// Timeout if some results just take too long
		case <-time.After(TIMEOUT_SECONDS * time.Second):
			break loop
		}
	}

	// Sort text results and output
	sort.Strings(results)
	fmt.Print(strings.Join(results, ""))
}
