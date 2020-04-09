// dany is a commandline DNS client that simulates (unreliable/semi-deprecated) dns `ANY`
// queries by doing individual typed DNS queries concurrently and aggregating the results

package dany

import (
	"bufio"
	"errors"
	"fmt"
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
var NXTypes = []string{
	"MX", "NS", "SOA",
}
var SupportedUSDs = []string{
	"_dmarc", "_domainkey", "_mta-sts",
}

// List of Resolver ips
type Resolvers struct {
	List   []net.IP
	Length int
	Index  int
}

func NewResolvers(ip net.IP) *Resolvers {
	return &Resolvers{List: []net.IP{ip}, Length: 1}
}

func LoadResolvers(filename string) (*Resolvers, error) {
	fh, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	var resolvers []net.IP
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
	return &Resolvers{List: resolvers, Length: len(resolvers)}, nil
}

func (r *Resolvers) Append(ip net.IP) {
	r.List = append(r.List, ip)
	r.Length = len(r.List)
}

func (r *Resolvers) Next() net.IP {
	if r.Length == 1 {
		return r.List[0]
	} else {
		resolverIP := r.List[r.Index]
		if r.Index >= r.Length-1 {
			r.Index = 0
		} else {
			r.Index++
		}
		return resolverIP
	}
}

// dany Query - lookup Types for Hostname using Server
type Query struct {
	Hostname     string
	Types        []string
	Resolvers    *Resolvers
	Server       string
	IgnoreErrors bool
	Ptr          bool
	Usd          bool
	Tag          bool
}

// dany query Result
type Result struct {
	Label   string
	Results string
	Error   error
}

var ErrNXDomain = errors.New("NXDOMAIN")
var ErrServFail = errors.New("SERVFAIL")

/*
func vprintf(format string, args ...interface{}) {
	if !opts.Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "+ "+format, args...)
}
*/

// Do an `rrtype` lookup on `hostname`, returning the dns response
func dnsLookup(client *dns.Client, server string, msg *dns.Msg, rrtype, hostname string, ignoreErrors bool) (*dns.Msg, error) {
	resp, _, err := client.Exchange(msg, server)
	// Return exchange errors
	if err != nil {
		err := fmt.Errorf("Error on %s lookup for %q: %w", rrtype, hostname, err)
		return nil, err
	}
	if resp != nil {
		// Return dns response errors (unless ignoreErrors is true)
		if resp.Rcode != dns.RcodeSuccess {
			if ignoreErrors {
				return nil, nil
			}
			// Treat NXDomain and ServFail errors as wrapped ErrNXDomain and ErrServFail errors
			if resp.Rcode == dns.RcodeNameError {
				err1 := ErrNXDomain
				err2 := fmt.Errorf("Error on %s lookup for %q: %w", rrtype, hostname, err1)
				return nil, err2
			} else if resp.Rcode == dns.RcodeServerFailure {
				err1 := ErrServFail
				err2 := fmt.Errorf("Error on %s lookup for %q: %w", rrtype, hostname, err1)
				return nil, err2
			} else {
				err := fmt.Errorf("Error on %s lookup for %q: %s", rrtype, hostname, dns.RcodeToString[resp.Rcode])
				return nil, err
			}
		}
		// Handle CNAMEs
		ans := resp.Answer
		if ans != nil && len(ans) > 0 && ans[0].Header().Rrtype == dns.TypeCNAME && rrtype != "CNAME" {
			// dig reports CNAME targets and then requeries, but that seems too noisy for N rrtypes,
			// so just silently requery
			cname := ans[0].(*dns.CNAME)
			//vprintf("%s %s lookup returned CNAME %q - requerying\n", hostname, rrtype, cname.Target)
			msg.SetQuestion(dns.Fqdn(cname.Target), msg.Question[0].Qtype)
			return dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		}
	}
	return resp, nil
}

func nxlookup(errorStream chan<- error, client *dns.Client, server, rrtype, hostname string) {
	msg := new(dns.Msg)
	msg.RecursionDesired = true
	ignoreErrors := false

	msg.SetQuestion(dns.Fqdn(hostname), dns.StringToType[rrtype])
	_, err := dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)

	errorStream <- err
}

func lookup(resultStream chan<- Result, client *dns.Client, rrtype, hostname string, q *Query) {
	server := q.Server
	ignoreErrors := q.IgnoreErrors

	msg := new(dns.Msg)
	msg.RecursionDesired = true

	var resultList []string
	var err error
	var resp *dns.Msg
	switch rrtype {
	case "A":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			var ptrMap map[string]string
			if q.Ptr {
				ptrMap = ptrLookupAll(client, server, rrtype, resp)
			}
			resultList = formatA(rrtype, resp, ptrMap)
		}
	case "AAAA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeAAAA)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			var ptrMap map[string]string
			if q.Ptr {
				ptrMap = ptrLookupAll(client, server, rrtype, resp)
			}
			resultList = formatAAAA(rrtype, resp, ptrMap)
		}
	case "CAA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeCAA)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			resultList = formatCAA(rrtype, resp)
		}
	case "CNAME":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeCNAME)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			resultList = formatCNAME(rrtype, resp)
		}
	case "DNSKEY":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeDNSKEY)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			resultList = formatDNSKEY(rrtype, resp)
		}
	case "MX":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeMX)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			resultList = formatMX(rrtype, resp)
		}
	case "NS":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeNS)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			resultList = formatNS(rrtype, resp)
		}
	case "NSEC":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeNSEC)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			resultList = formatNSEC(rrtype, resp)
		}
	case "RRSIG":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeRRSIG)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			resultList = formatRRSIG(rrtype, resp)
		}
	case "SOA":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSOA)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			resultList = formatSOA(rrtype, resp)
		}
	case "SRV":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeSRV)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			resultList = formatSRV(rrtype, resp)
		}
	case "TXT":
		msg.SetQuestion(dns.Fqdn(hostname), dns.TypeTXT)
		resp, err = dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
		if err == nil && resp != nil {
			resultList = formatTXT(rrtype, resp)
		}
	default:
		err = fmt.Errorf("Error: unhandled type %q", rrtype)
	}

	sort.Strings(resultList)
	var results string
	if q.Tag && len(resultList) > 0 {
		tag := hostname + "\t"
		for _, r := range resultList {
			results = results + tag + r
		}
	} else {
		results = strings.Join(resultList, "")
	}

	res := Result{Label: rrtype, Results: results, Error: err}
	resultStream <- res
}

func ptrLookupOne(resultStream chan<- Result, client *dns.Client, server, ip, ipArpa string) {
	msg := new(dns.Msg)
	msg.RecursionDesired = true
	msg.SetQuestion(ipArpa, dns.TypePTR)

	resp, _, err := client.Exchange(msg, server)
	// Return exchange errors
	if err != nil {
		err = fmt.Errorf("Error on PTR lookup for %q: %s", ip, err)
	}
	// Silently give up on dns errors (resp.Rcode != dns.RcodeSuccess)
	if resp.Rcode != dns.RcodeSuccess {
		//vprintf("dns error on PTR lookup on %s: %s\n", ip, dns.RcodeToString[resp.Rcode])
	}

	var resultText string
	if resp != nil && resp != nil {
		resultText = formatPTRAppend(resp)
	}
	res := Result{Label: ip, Results: resultText, Error: err}
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

func RunQuery(q *Query) (string, string) {
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
		q.IgnoreErrors = true
		domain := h
		for _, usd := range SupportedUSDs {
			h = usd + "." + domain
			go lookup(resultStream, client, "TXT", h, q)
			count++
		}
	}

	var resultList []string
	var errors []string
loop:
	for {
		select {
		// Get results from resultStream
		case res := <-resultStream:
			if res.Error != nil {
				errors = append(errors, res.Error.Error()+"\n")
			} else if res.Results != "" {
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

	return strings.Join(resultList, ""), strings.Join(errors, "")
}

// Run a set of N dns queries on hostname, returning true if N-1 responses are NXDOMAINs
func RunNXQuery(hostname string, server string) (bool, error) {
	// Do lookups, using errorStream to gather results
	errorStream := make(chan error, len(NXTypes))
	client := new(dns.Client)
	// Set client timeouts (dial/read/write) to timeoutSeconds / 2
	client.Timeout = timeoutSeconds / 2 * time.Second
	// Run standard lookups
	count := 0
	for _, t := range NXTypes {
		go nxlookup(errorStream, client, server, t, hostname)
		count++
	}

	nxcount := 0
loop:
	for {
		select {
		// Get results from errorStream
		case err := <-errorStream:
			if errors.Is(err, ErrNXDomain) {
				nxcount++
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

	if nxcount >= len(NXTypes)-1 {
		return true, nil
	}
	return false, nil
}
