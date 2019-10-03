// dany is a commandline DNS client that simulates (unreliable/semi-deprecated) dns `ANY`
// queries by doing individual typed DNS queries concurrently and aggregating the results

package dany

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const timeoutSeconds = 10

var DefaultRRTypes = []string{"A", "AAAA", "MX", "NS", "SOA", "TXT"}
var SupportedRRTypes = []string{
	"A", "AAAA", "CAA", "CNAME", "DNSKEY", "MX", "NS", "NSEC", "RRSIG", "SOA", "SRV", "TXT",
}
var SupportedUSDs = []string{
	"_dmarc", "_domainkey", "_mta-sts",
}

type ResolverIPs []net.IP

func LoadResolvers(filename string) (ResolverIPs, error) {
	fh, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	var resolvers ResolverIPs
	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		ipText := scanner.Text()
		ip := net.ParseIP(ipText)
		if ip == nil {
			err := fmt.Errorf("Error: failed to parse --resolv ip address %q", ipText)
			return nil, err
		}
		resolvers = append(resolvers, ip)
	}
	// Must have at least one resolver
	if len(resolvers) == 0 {
		err := fmt.Errorf("Error: no resolvers found in --resolv file %q", filename)
		return nil, err
	}
	return resolvers, nil
}

func (resolvers ResolverIPs) Choose() net.IP {
	if len(resolvers) == 1 {
		return resolvers[0]
	} else {
		src := rand.NewSource(time.Now().UnixNano())
		rinst := rand.New(src)
		return resolvers[rinst.Intn(len(resolvers))]
	}
}

// dany Query - lookup Types for Hostname using Server
type Query struct {
	Hostname  string
	Types     []string
	Resolvers ResolverIPs
	Server    string
	NonFatal  bool
	Ptr       bool
	Usd       bool
}

// dany query Result
type Result struct {
	Label   string
	Results string
}

/*
func vprintf(format string, args ...interface{}) {
	if !opts.Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "+ "+format, args...)
}
*/

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
			//vprintf("%s %s lookup returned CNAME %q - requerying\n", hostname, rrtype, cname.Target)
			msg.SetQuestion(dns.Fqdn(cname.Target), msg.Question[0].Qtype)
			return dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		}
	}
	return resp
}

func lookup(resultStream chan<- Result, client *dns.Client, rrtype, hostname string, q *Query) {
	server := q.Server
	nonFatal := q.NonFatal

	msg := new(dns.Msg)
	msg.RecursionDesired = true

	var resultList []string
	switch rrtype {
	case "A":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			var ptrMap map[string]string
			if q.Ptr {
				ptrMap = ptrLookupAll(client, server, rrtype, resp)
			}
			resultList = formatA(rrtype, resp, ptrMap)
		}
	case "AAAA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			var ptrMap map[string]string
			if q.Ptr {
				ptrMap = ptrLookupAll(client, server, rrtype, resp)
			}
			resultList = formatAAAA(rrtype, resp, ptrMap)
		}
	case "CAA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeCAA)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			resultList = formatCAA(rrtype, resp)
		}
	case "CNAME":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeCNAME)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			resultList = formatCNAME(rrtype, resp)
		}
	case "DNSKEY":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeDNSKEY)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			resultList = formatDNSKEY(rrtype, resp)
		}
	case "MX":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeMX)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			resultList = formatMX(rrtype, resp)
		}
	case "NS":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeNS)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			resultList = formatNS(rrtype, resp)
		}
	case "NSEC":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeNSEC)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			resultList = formatNSEC(rrtype, resp)
		}
	case "RRSIG":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeRRSIG)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			resultList = formatRRSIG(rrtype, resp)
		}
	case "SOA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSOA)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			resultList = formatSOA(rrtype, resp)
		}
	case "SRV":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSRV)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			resultList = formatSRV(rrtype, resp)
		}
	case "TXT":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)
		resp := dnsLookup(client, server, msg, rrtype, hostname, nonFatal)
		if resp != nil {
			resultList = formatTXT(rrtype, resp)
		}
	default:
		log.Fatalf("Error: unhandled type %q", rrtype)
	}

	sort.Strings(resultList)

	res := Result{Label: rrtype, Results: strings.Join(resultList, "")}
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
		//vprintf("dns error on PTR lookup on %s: %s\n", ip, dns.RcodeToString[resp.Rcode])
	}

	var resultText string
	if resp != nil {
		resultText = formatPTRAppend(resp)
	}
	res := Result{Label: ip, Results: resultText}
	resultStream <- res
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
			//vprintf("Warning: failed to convert ip %q to arpa form\n", ip)
			continue
		}

		//vprintf("doing %s PTR lookup on %s\n", rrtype, ip)
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
				//vprintf("%s query returned no data\n", res.Label+" PTR")
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

func RunQuery(q *Query) string {
	// Do lookups, using resultStream to gather results
	resultStream := make(chan Result, len(q.Types))
	client := new(dns.Client)
	// We're often going to want long records like TXT or DNSKEY, so let's just always use tcp
	client.Net = "tcp"
	// Set client timeouts (dial/read/write) to timeoutSeconds / 2
	client.Timeout = timeoutSeconds / 2 * time.Second
	// Run standard lookups
	count := 0
	h := q.Hostname
	for _, t := range q.Types {
		go lookup(resultStream, client, strings.ToUpper(t), h, q)
		count++
	}
	// Add USD TXT lookups
	if q.Usd {
		q.NonFatal = true
		domain := h
		for _, usd := range SupportedUSDs {
			h = usd + "." + domain
			go lookup(resultStream, client, "TXT", h, q)
			count++
		}
	}

	var resultList []string
loop:
	for {
		select {
		// Get results from resultStream
		case res := <-resultStream:
			if res.Results != "" {
				resultList = append(resultList, res.Results)
			} else {
				//vprintf("%s query returned no data\n", res.Label)
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
	sort.Strings(resultList)

	return strings.Join(resultList, "")
}
