// dany is a commandline DNS client that simulates (unreliable/semi-deprecated) dns `ANY`
// queries by doing individual typed DNS queries concurrently and aggregating the results

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

func dns_lookup(client *dns.Client, server string, msg *dns.Msg, rrtype, hostname string) *dns.Msg {
	resp, _, err := client.Exchange(msg, server)
	// Handle message truncation with udp
	if resp.Truncated && client.Net != "tcp" {
		vprintf("%s lookup truncated, trying TCP\n", rrtype)
		client.Net = "tcp"
		resp, _, err = client.Exchange(msg, server)
	}
	if err != nil {
		log.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		log.Fatalf("Error in %s request for %q\n", rrtype, hostname)
	}
	return resp
}

func lookup(rrtype, hostname string, ch chan<- string, client *dns.Client, server string) {
	msg := new(dns.Msg)
	msg.RecursionDesired = true

	var text string
	switch rrtype {
	case "A":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		text = format_a(rrtype, resp)
	case "AAAA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		text = format_aaaa(rrtype, resp)
	case "MX":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeMX)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		text = format_mx(rrtype, resp)
	case "NS":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeNS)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		text = format_ns(rrtype, resp)
	case "SOA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSOA)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		text = format_soa(rrtype, resp)
	case "SRV":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSRV)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		text = format_srv(rrtype, resp)
	case "TXT":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		text = format_txt(rrtype, resp)
	default:
		log.Fatalf("Error: unhandled type %q", rrtype)
	}

	ch <- text
}

func format_a(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		a := ans.(*dns.A)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\n", rrtype, a.A.String()))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_aaaa(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		aaaa := ans.(*dns.AAAA)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\n", rrtype, aaaa.AAAA.String()))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_mx(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		mx := ans.(*dns.MX)
		elts = append(elts, fmt.Sprintf("%s\t%d\t%s\n", rrtype, mx.Preference, mx.Mx))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_ns(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		ns := ans.(*dns.NS)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\n", rrtype, ns.Ns))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_soa(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		soa := ans.(*dns.SOA)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\t%s\n", rrtype, soa.Ns, soa.Mbox))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_srv(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		srv := ans.(*dns.SRV)
		elts = append(elts, fmt.Sprintf("%s\t%d\t%d\t%d\t%s\n", rrtype, srv.Priority, srv.Weight, srv.Port, srv.Target))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_txt(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		txt := ans.(*dns.TXT)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\n", rrtype, strings.Join(txt.Txt, "")))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
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
