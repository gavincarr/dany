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
	"github.com/miekg/dns"
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

func lookup(t, hostname string, ch chan<- string, client *dns.Client, server string) {
	switch t {
	case "A":
		lookup_a(hostname, ch, client, server)
	case "AAAA":
		lookup_aaaa(hostname, ch, client, server)
	case "MX":
		lookup_mx(hostname, ch)
	case "NS":
		lookup_ns(hostname, ch)
	case "SOA":
		lookup_soa(hostname, ch, client, server)
	case "TXT":
		lookup_txt(hostname, ch)
	default:
		log.Fatal("Error: unhandled type '" + t + "'")
	}
}

func lookup_a(hostname string, ch chan<- string, client *dns.Client, server string) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	msg.RecursionDesired = true

	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		log.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		log.Fatalf("Error in SOA request for %s\n", hostname)
	}

	var text string
	for _, ans := range resp.Answer {
		a := ans.(*dns.A)
		text += fmt.Sprintf("%s\t\t%s\n", "A", a.A.String())
	}
	ch <- text
}

func lookup_aaaa(hostname string, ch chan<- string, client *dns.Client, server string) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
	msg.RecursionDesired = true

	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		log.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		log.Fatalf("Error in SOA request for %s\n", hostname)
	}

	var text string
	for _, ans := range resp.Answer {
		aaaa := ans.(*dns.AAAA)
		text += fmt.Sprintf("%s\t\t%s\n", "AAAA", aaaa.AAAA.String())
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

func lookup_soa(hostname string, ch chan<- string, client *dns.Client, server string) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSOA)
	msg.RecursionDesired = true

	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		log.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		log.Fatalf("Error in SOA request for %s\n", hostname)
	}

	var text string
	for _, ans := range resp.Answer {
		soa := ans.(*dns.SOA)
		text += fmt.Sprintf("%s\t\t%s\t%s\n", "SOA", soa.Ns, soa.Mbox)
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
		fmt.Fprintln(os.Stderr, "usage: dany [OPTIONS] [<Types>] <Hostname>")
		os.Exit(1)
	}
	var types []string
	var hostname string
	if len(args) == 1 {
		types = []string{"SOA", "NS", "A", "AAAA", "MX", "TXT"}
		hostname = args[0]
	} else {
		types_arg := args[0]
		types = strings.Split(types_arg, ",")
		hostname = args[1]
	}
	vprintf("types: %s\n", types)
	vprintf("hostname: %s\n", hostname)

	// miekg/dns setup
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		log.Fatal(err)
	}
	server := net.JoinHostPort(config.Servers[0], config.Port)
	client := new(dns.Client)

	// Do lookups, using resultStream to gather results
	resultStream := make(chan string, len(types))
	for _, t := range types {
		go lookup(strings.ToUpper(t), hostname, resultStream, client, server)
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
