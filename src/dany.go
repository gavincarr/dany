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

const timeoutSeconds = 10
const dnsPort = "53"

var defaultRRTypes = []string{"A", "AAAA", "MX", "NS", "SOA", "TXT"}
var supportedRRTypes = []string{
	"A", "AAAA", "CAA", "CNAME", "DNSKEY", "MX", "NS", "NSEC", "RRSIG", "SOA", "SRV", "TXT",
}
var supportedUSDs = []string{
	"_dmarc", "_domainkey", "_mta-sts",
}

type Query struct {
	Server    string
	Hostnames []string
	Types     []string
	NonFatal  bool
	Ptr       bool
}
type Result struct {
	Label   string
	Results string
}

// Options
var opts struct {
	Verbose bool `short:"v" long:"verbose" description:"display verbose debug output"`
	All     bool `short:"a" long:"all" description:"display all supported DNS records (rather than default set below)"`
	Ptr     bool `short:"p" long:"ptr" description:"lookup and append ptr records to ip results"`
	Usd     bool `short:"u" long:"usd" description:"also lookup TXT records of well-known underscore-subdomains of domain (see below)"`
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
	fmt.Fprintf(os.Stderr, "\nDefault DNS resource types: %s\n", strings.Join(defaultRRTypes, ","))
	fmt.Fprintf(os.Stderr, "Supported DNS resource types: %s\n", strings.Join(supportedRRTypes, ","))
	fmt.Fprintf(os.Stderr, "Supported underscore-subdomains with --usd: %s\n", strings.Join(supportedUSDs, ","))
	os.Exit(2)
}

func vprintf(format string, args ...interface{}) {
	if !opts.Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "+ "+format, args...)
}

// Do an `rrtype` lookup on `hostname`, returning the dns response
func dnsLookup(client *dns.Client, server string, msg *dns.Msg, rrtype, hostname string, nonFatal bool) *dns.Msg {
	resp, _, err := client.Exchange(msg, server)
	// Die on exchange errors
	if err != nil {
		log.Fatalf("Error (%s): %s", rrtype, err)
	}
	if resp != nil {
		// Die on dns errors (unless nonFatal is true)
		if resp.Rcode != dns.RcodeSuccess {
			if nonFatal {
				return nil
			}
			log.Fatalf("Error (%s): %s", rrtype, dns.RcodeToString[resp.Rcode])
		}
		// Handle CNAMEs
		ans := resp.Answer
		if ans != nil && len(ans) > 0 && ans[0].Header().Rrtype == dns.TypeCNAME && rrtype != "CNAME" {
			// dig reports CNAME targets and then requeries, but that seems too noisy for N rrtypes,
			// so just silently requery (except with --verbose)
			cname := ans[0].(*dns.CNAME)
			vprintf("%s %s lookup returned CNAME %q - requerying\n", hostname, rrtype, cname.Target)
			msg.SetQuestion(dns.Fqdn(cname.Target), msg.Question[0].Qtype)
			return dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		}
	}
	return resp
}

func lookup(resultStream chan<- Result, client *dns.Client, rrtype, hostname string, query *Query) {
	server := query.Server
	nonFatal := query.NonFatal

	msg := new(dns.Msg)
	msg.RecursionDesired = true

	var results []string
	switch rrtype {
	case "A":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			var ptrMap map[string]string
			if query.Ptr {
				ptrMap = ptrLookupAll(client, server, rrtype, resp)
				//vprintf("ptrMap: %v\n", ptrMap)
			}
			results = formatA(rrtype, resp, ptrMap)
		}
	case "AAAA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			var ptrMap map[string]string
			if query.Ptr {
				ptrMap = ptrLookupAll(client, server, rrtype, resp)
				//vprintf("ptrMap: %v\n", ptrMap)
			}
			results = formatAAAA(rrtype, resp, ptrMap)
		}
	case "CAA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeCAA)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			results = formatCAA(rrtype, resp)
		}
	case "CNAME":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeCNAME)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			results = formatCNAME(rrtype, resp)
		}
	case "DNSKEY":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeDNSKEY)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			results = formatDNSKEY(rrtype, resp)
		}
	case "MX":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeMX)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			results = formatMX(rrtype, resp)
		}
	case "NS":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeNS)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			results = formatNS(rrtype, resp)
		}
	case "NSEC":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeNSEC)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			results = formatNSEC(rrtype, resp)
		}
	case "RRSIG":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeRRSIG)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			results = formatRRSIG(rrtype, resp)
		}
	case "SOA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSOA)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			results = formatSOA(rrtype, resp)
		}
	case "SRV":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSRV)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			results = formatSRV(rrtype, resp)
		}
	case "TXT":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			results = formatTXT(rrtype, resp)
		}
	default:
		log.Fatalf("Error: unhandled type %q", rrtype)
	}

	sort.Strings(results)

	res := Result{Label: rrtype, Results: strings.Join(results, "")}
	resultStream <- res
}

func ptrLookupOne(resultStream chan<- Result, client *dns.Client, server, ip, ipArpa string) {
	msg := new(dns.Msg)
	msg.RecursionDesired = true
	msg.SetQuestion(ipArpa, dns.TypePTR)

	resp, _, err := client.Exchange(msg, server)
	// Die on exchange errors
	if err != nil {
		log.Fatalf("Error (%s PTR): %s", ip, err)
	}
	// Silently give up on dns errors (resp.Rcode != dns.RcodeSuccess)
	if resp.Rcode != dns.RcodeSuccess {
		vprintf("dns error on PTR lookup on %s: %s\n", ip, dns.RcodeToString[resp.Rcode])
	}

	var results string
	if resp != nil {
		results = formatPTRAppend(resp)
	}
	result := Result{Label: ip, Results: results}
	resultStream <- result
}

func ptrLookupAll(client *dns.Client, server, rrtype string, resp *dns.Msg) map[string]string {
	resultStream := make(chan Result)
	ptrMap := make(map[string]string)

	count := 0
	for _, ans := range resp.Answer {
		// Extract ip
		var ip string
		if rr, ok := ans.(*dns.A); ok {
			ip = rr.A.String()
		} else if rr, ok := ans.(*dns.AAAA); ok {
			ip = rr.AAAA.String()
		}

		// Do PTR lookup
		ipArpa, err := dns.ReverseAddr(ip)
		if err != nil {
			vprintf("Warning: failed to convert ip %q to arpa form\n", ip)
			continue
		}

		vprintf("doing %s PTR lookup on %s\n", rrtype, ip)
		count++
		go ptrLookupOne(resultStream, client, server, ip, ipArpa)
	}

loop:
	for count > 0 {
		select {
		// Get results from resultStream
		case res := <-resultStream:
			if res.Results != "" {
				ptrMap[res.Label] = res.Results
			} else {
				vprintf("%s query returned no data\n", res.Label+" PTR")
			}
			count--
		// Timeout if some results just take too long
		case <-time.After(timeoutSeconds * time.Second):
			break loop
		}
	}

	return ptrMap
}

func formatA(rrtype string, resp *dns.Msg, ptrMap map[string]string) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.A)
		ip := rr.A.String()
		ptrEntry := ""
		if ptrMap != nil {
			if pe, ok := ptrMap[ip]; ok {
				ptrEntry = "\t" + pe
			}
		}
		elts = append(elts,
			fmt.Sprintf("%s\t\t%s%s\n", rrtype, ip, ptrEntry))
	}
	return elts
}

func formatAAAA(rrtype string, resp *dns.Msg, ptrMap map[string]string) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.AAAA)
		ip := rr.AAAA.String()
		ptrEntry := ""
		if ptrMap != nil {
			if pe, ok := ptrMap[ip]; ok {
				ptrEntry = "\t" + pe
			}
		}
		elts = append(elts,
			fmt.Sprintf("%s\t\t%s%s\n", rrtype, ip, ptrEntry))
	}
	return elts
}

func formatCAA(rrtype string, resp *dns.Msg) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.CAA)
		elts = append(elts,
			fmt.Sprintf("%s\t%d\t%s %s\n", rrtype, rr.Flag, rr.Tag, rr.Value))
	}
	return elts
}

func formatCNAME(rrtype string, resp *dns.Msg) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.CNAME)
		elts = append(elts,
			fmt.Sprintf("%s\t\t%s\n", rrtype, rr.Target))
	}
	return elts
}

func formatDNSKEY(rrtype string, resp *dns.Msg) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.DNSKEY)
		elts = append(elts,
			fmt.Sprintf("%s\t%d %d %d\t%s\n", rrtype, rr.Flags, rr.Protocol, rr.Algorithm, rr.PublicKey))
	}
	return elts
}

func formatMX(rrtype string, resp *dns.Msg) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.MX)
		elts = append(elts,
			fmt.Sprintf("%s\t%d\t%s\n", rrtype, rr.Preference, rr.Mx))
	}
	return elts
}

func formatNS(rrtype string, resp *dns.Msg) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.NS)
		elts = append(elts, fmt.Sprintf("%s\t\t%s\n", rrtype, rr.Ns))
	}
	return elts
}

func formatNSEC(rrtype string, resp *dns.Msg) []string {
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
	return elts
}

func formatPTRAppend(resp *dns.Msg) string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.PTR)
		elts = append(elts, rr.Ptr)
	}
	sort.Strings(elts)
	return strings.Join(elts, " ")
}

func formatRRSIG(rrtype string, resp *dns.Msg) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.RRSIG)
		elts = append(elts,
			fmt.Sprintf("%s\t\t%s %d %d %d %s %s %d %s %s\n",
				rrtype, dns.Type(rr.TypeCovered).String(),
				rr.Algorithm, rr.Labels, rr.OrigTtl,
				dns.TimeToString(rr.Expiration), dns.TimeToString(rr.Inception),
				rr.KeyTag, rr.SignerName, rr.Signature,
			))
	}
	return elts
}

func formatSOA(rrtype string, resp *dns.Msg) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.SOA)
		elts = append(elts,
			fmt.Sprintf("%s\t\t%s %s\n", rrtype, rr.Ns, rr.Mbox))
	}
	return elts
}

func formatSRV(rrtype string, resp *dns.Msg) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.SRV)
		elts = append(elts,
			fmt.Sprintf("%s\t%d %d %d\t%s\n", rrtype, rr.Priority, rr.Weight, rr.Port, rr.Target))
	}
	return elts
}

func formatTXT(rrtype string, resp *dns.Msg) []string {
	var elts []string
	for _, ans := range resp.Answer {
		rr := ans.(*dns.TXT)
		elts = append(elts,
			fmt.Sprintf("%s\t\t%s\n", rrtype, strings.Join(rr.Txt, "")))
	}
	return elts
}

func dany(query *Query) string {
	// Do lookups, using resultStream to gather results
	resultStream := make(chan Result, len(query.Types))
	client := new(dns.Client)
	// We're often going to want long records like TXT or DNSKEY, so let's just always use tcp
	client.Net = "tcp"
	// Set client timeouts (dial/read/write) to timeoutSeconds / 2
	client.Timeout = timeoutSeconds / 2 * time.Second
	// Run standard lookups
	count := 0
	for _, h := range query.Hostnames {
		for _, t := range query.Types {
			go lookup(resultStream, client, strings.ToUpper(t), h, query)
			count++
		}
		// Add USD TXT lookups
		if opts.Usd {
			query.NonFatal = true
			domain := h
			for _, usd := range supportedUSDs {
				h = usd + "." + domain
				go lookup(resultStream, client, "TXT", h, query)
				count++
			}
		}
	}

	var results []string
loop:
	for {
		select {
		// Get results from resultStream
		case res := <-resultStream:
			if res.Results != "" {
				results = append(results, res.Results)
			} else {
				vprintf("%s query returned no data\n", res.Label)
			}
			count--
			if count <= 0 {
				break loop
			}
		// Timeout if some results just take too long
		case <-time.After(timeoutSeconds * time.Second):
			break loop
		}
	}

	// Sort text results
	sort.Strings(results)

	return strings.Join(results, "")
}

func parseArgs(args []string) (*Query, error) {
	query := new(Query)
	query.NonFatal = false
	query.Ptr = opts.Ptr

	// Regexps
	reAtPrefix := regexp.MustCompile("^@")
	reDot := regexp.MustCompile("\\.")
	reComma := regexp.MustCompile(",")

	typeMap := make(map[string]bool)
	for _, t := range supportedRRTypes {
		typeMap[t] = true
		typeMap[strings.ToLower(t)] = true
	}

	// Args: 1 domain (required); 1 @-prefixed server ip (optional); 1 comma-separated list of types (optional)
	for _, arg := range args {
		argIsRRType := false
		// Check whether non-dotted args are bare RRtypes
		if !reDot.MatchString(arg) {
			if _, ok := typeMap[arg]; ok {
				argIsRRType = true
			}
		}
		// Check for @<ip> server argument
		if reAtPrefix.MatchString(arg) {
			if query.Server != "" {
				err := errors.New(fmt.Sprintf("Error: argument %q looks like `@<ip>`, but we already have %q",
					arg, query.Server))
				return nil, err
			}
			serverIP := net.ParseIP(arg[1:])
			if serverIP == nil {
				err := errors.New(fmt.Sprintf("Error: argument %q looks like `@<ip>`, but unable to parse ip address",
					arg))
				return nil, err
			}
			query.Server = net.JoinHostPort(serverIP.String(), dnsPort)
			continue
		}
		// Check for <RR>[,<RR>...] types argument
		if argIsRRType || reComma.MatchString(arg) {
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
		if len(query.Hostnames) >= 1 {
			err := errors.New(fmt.Sprintf("Error: argument %q looks like hostname, but we already have %q",
				arg, query.Hostnames[0]))
			return nil, err
		}
		query.Hostnames = []string{arg}
	}

	if query.Types == nil || len(query.Types) == 0 {
		if opts.All {
			query.Types = supportedRRTypes
		} else {
			query.Types = defaultRRTypes
		}
	}

	if query.Server == "" {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		query.Server = net.JoinHostPort(config.Servers[0], config.Port)
	}

	vprintf("server: %s\n", query.Server)
	vprintf("hostname: %s\n", query.Hostnames[0])
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
