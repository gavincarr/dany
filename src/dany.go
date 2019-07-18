// dany is a commandline DNS client that simulates (unreliable/semi-deprecated) dns `ANY`
// queries by doing individual typed DNS queries concurrently and aggregating the results

package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	flags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
)

const TIMEOUT_SECONDS = 10
const DNS_PORT = "53"

var DEFAULT_RRTYPES = []string{"A", "AAAA", "MX", "NS", "SOA", "TXT"}
var SUPPORTED_RRTYPES = []string{"A", "AAAA", "CAA", "CNAME", "DNSKEY", "MX", "NS", "NSEC", "SOA", "SRV", "TXT"}

type Query struct {
	Hostname string
	Server   string
	Types    []string
}

// Options
var opts struct {
	Verbose bool `short:"v" long:"verbose" description:"display verbose debug output"`
	All     bool `short:"a" long:"all" description:"display all supported DNS records (rather than default set below)"`
	Args    struct {
		Types    string `description:"comma-separated list of DNS resource types to lookup (case-insensitive)"`
		Hostname string `description:"hostname/domain to lookup"`
		Extra    []string
	} `positional-args:"yes"`
}

// Disable flags.PrintErrors for more control
var parser = flags.NewParser(&opts, flags.Default&^flags.PrintErrors)

func usage() {
	parser.WriteHelp(os.Stderr)
	fmt.Fprintf(os.Stderr, "\nDefault DNS resource types: %s\n", strings.Join(DEFAULT_RRTYPES, ","))
	fmt.Fprintf(os.Stderr, "Supported DNS resource types: %s\n", strings.Join(SUPPORTED_RRTYPES, ","))
	os.Exit(2)
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
	if resp != nil && resp.Truncated && client.Net != "tcp" {
		vprintf("%s lookup truncated, retrying using TCP\n", rrtype)
		client.Net = "tcp"
		resp, _, err = client.Exchange(msg, server)
	}
	// Die on non-truncation errors
	if err != nil {
		log.Fatal(err)
	}
	if resp != nil {
		// Fail on errors
		if resp.Rcode != dns.RcodeSuccess {
			log.Fatalf("Error in %s request for %q\n", rrtype, hostname)
		}
		// Handle CNAMEs
		ans := resp.Answer
		if ans != nil && len(ans) > 0 && ans[0].Header().Rrtype == dns.TypeCNAME && rrtype != "CNAME" {
			// dig reports CNAME targets and then requeries, but that seems too noisy for N rrtypes
			cname := ans[0].(*dns.CNAME)
			vprintf("%s %s lookup returned CNAME %q - requerying\n", hostname, rrtype, cname.Target)
			msg.SetQuestion(dns.Fqdn(cname.Target), msg.Question[0].Qtype)
			return dns_lookup(client, server, msg, rrtype, hostname)
		}
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
		if resp != nil {
			text = format_a(rrtype, resp)
		}
	case "AAAA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		if resp != nil {
			text = format_aaaa(rrtype, resp)
		}
	case "CAA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeCAA)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		if resp != nil {
			text = format_caa(rrtype, resp)
		}
	case "CNAME":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeCNAME)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		if resp != nil {
			text = format_cname(rrtype, resp)
		}
	case "DNSKEY":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeDNSKEY)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		if resp != nil {
			text = format_dnskey(rrtype, resp)
		}
	case "MX":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeMX)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		if resp != nil {
			text = format_mx(rrtype, resp)
		}
	case "NS":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeNS)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		if resp != nil {
			text = format_ns(rrtype, resp)
		}
	case "NSEC":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeNSEC)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		if resp != nil {
			text = format_nsec(rrtype, resp)
		}
	case "SOA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSOA)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		if resp != nil {
			text = format_soa(rrtype, resp)
		}
	case "SRV":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSRV)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		if resp != nil {
			text = format_srv(rrtype, resp)
		}
	case "TXT":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)
		resp := dns_lookup(client, server, msg, rrtype, hostname)
		if resp != nil {
			text = format_txt(rrtype, resp)
		}
	default:
		log.Fatalf("Error: unhandled type %q", rrtype)
	}

	ch <- text
}

func format_a(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.A)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\n", rrtype, rr.A.String()))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_aaaa(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.AAAA)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\n", rrtype, rr.AAAA.String()))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_caa(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.CAA)
		elts = append(elts, fmt.Sprintf("%s\t%d\t%s %s\n", rrtype, rr.Flag, rr.Tag, rr.Value))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_cname(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.CNAME)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\n", rrtype, rr.Target))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_dnskey(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.DNSKEY)
		elts = append(elts, fmt.Sprintf("%s\t%d %d %d\t%s\n", rrtype, rr.Flags, rr.Protocol, rr.Algorithm, rr.PublicKey))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_mx(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.MX)
		elts = append(elts, fmt.Sprintf("%s\t%d\t%s\n", rrtype, rr.Preference, rr.Mx))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_ns(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.NS)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\n", rrtype, rr.Ns))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_nsec(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.NSEC)
		s := fmt.Sprintf("%s\t\t%s", rrtype, rr.NextDomain)
		for _, t := range rr.TypeBitMap {
			s += " " + dns.Type(t).String()
		}
		s += "\n"
		elts = append(elts, s)
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_soa(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.SOA)
		elts = append(elts, fmt.Sprintf("%s\t\t%s %s\n", rrtype, rr.Ns, rr.Mbox))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_srv(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.SRV)
		elts = append(elts, fmt.Sprintf("%s\t%d %d %d\t%s\n", rrtype, rr.Priority, rr.Weight, rr.Port, rr.Target))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func format_txt(rrtype string, resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.TXT)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\n", rrtype, strings.Join(rr.Txt, "")))
	}
	sort.Strings(elts)
	return strings.Join(elts, "")
}

func dany(query *Query) string {
	client := new(dns.Client)

	// Do lookups, using resultStream to gather results
	resultStream := make(chan string, len(query.Types))
	for _, t := range query.Types {
		go lookup(strings.ToUpper(t), query.Hostname, resultStream, client, query.Server)
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
			if count >= len(query.Types) {
				break loop
			}
		// Timeout if some results just take too long
		case <-time.After(TIMEOUT_SECONDS * time.Second):
			break loop
		}
	}

	// Sort text results
	sort.Strings(results)

	return strings.Join(results, "")
}

func parseArgs(args []string) (*Query, error) {
	query := new(Query)

	// Regexps
	re_at_prefix := regexp.MustCompile("^@")
	re_dot := regexp.MustCompile("\\.")
	re_comma := regexp.MustCompile(",")

	typeMap := make(map[string]bool)
	for _, t := range SUPPORTED_RRTYPES {
		typeMap[t] = true
		typeMap[strings.ToLower(t)] = true
	}

	// Args: 1 domain (required); 1 @-prefixed server ip (optional); 1 comma-separated list of types (optional)
	for _, arg := range args {
		arg_is_rrtype := false
		// Check whether non-dotted args are bare RRtypes
		if !re_dot.MatchString(arg) {
			if _, ok := typeMap[arg]; ok {
				arg_is_rrtype = true
			}
		}
		// Check for @<ip> server argument
		if re_at_prefix.MatchString(arg) {
			if query.Server != "" {
				err := errors.New(fmt.Sprintf("Error: argument %q looks like `@<ip>`, but we already have %q",
					arg, query.Server))
				return nil, err
			}
			server_ip := net.ParseIP(arg[1:])
			if server_ip == nil {
				err := errors.New(fmt.Sprintf("Error: argument %q looks like `@<ip>`, but unable to parse ip address",
					arg))
				return nil, err
			}
			query.Server = net.JoinHostPort(server_ip.String(), DNS_PORT)
			continue
		}
		// Check for <RR>[,<RR>...] types argument
		if arg_is_rrtype || re_comma.MatchString(arg) {
			if len(query.Types) != 0 {
				err := errors.New(fmt.Sprintf("Error: argument %q looks like types list, but we already have %q",
					arg, query.Types))
				return nil, err
			}
			// Check all types are valid
			types := strings.Split(arg, ",")
			var badTypes []string
			for _, t := range types {
				if _, ok := typeMap[t]; !ok {
					badTypes = append(badTypes, t)
				}
			}
			if len(badTypes) > 0 {
				err := errors.New(fmt.Sprintf("Error: unsupported types found in %q: %s",
					arg, strings.Join(badTypes, ",")))
				return nil, err
			}
			query.Types = strings.Split(arg, ",")
			continue
		}
		// Otherwise assume hostname
		if query.Hostname != "" {
			err := errors.New(fmt.Sprintf("Error: argument %q looks like hostname, but we already have %q",
				arg, query.Hostname))
			return nil, err
		}
		query.Hostname = arg
	}

	if query.Types == nil || len(query.Types) == 0 {
		if opts.All {
			query.Types = SUPPORTED_RRTYPES
		} else {
			query.Types = DEFAULT_RRTYPES
		}
	}

	if query.Server == "" {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		query.Server = net.JoinHostPort(config.Servers[0], config.Port)
	}

	vprintf("hostname: %s\n", query.Hostname)
	vprintf("server: %s\n", query.Server)
	vprintf("types: %v\n", query.Types)

	return query, nil
}

func main() {
	// Parse options
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type != flags.ErrHelp {
			fmt.Fprintf(os.Stderr, "%s\n\n", err)
		}
		usage()
	}

	// Setup
	log.SetFlags(0)
	if opts.Args.Types == "" {
		usage()
	}
	// Actually treat opts.Args as an unordered []string and parse into query elements
	args := []string{opts.Args.Types}
	if opts.Args.Hostname != "" {
		args = append(args, opts.Args.Hostname)
	}
	if len(opts.Args.Extra) > 0 {
		args = append(args, opts.Args.Extra...)
	}
	query, err := parseArgs(args)
	if err != nil {
		log.Fatal(err)
	}

	// Do lookups
	results := dany(query)
	fmt.Print(results)
}
