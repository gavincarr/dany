// dany is a commandline DNS client that simulates (unreliable/semi-deprecated)
// dns `ANY` queries by doing individual typed DNS queries concurrently and
// aggregating the results

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
	Udp          bool
	Ptr          bool
	Usd          bool
	Www          bool
	// WwwTypes, when non-empty, overrides the default www-probe type set
	// (A, AAAA). Only consulted when Www is true. Callers that want the
	// www. probe to mirror the user's explicit -t/--types selection set
	// this; callers that want the address-only default leave it nil.
	WwwTypes []string
	Tag      bool
}

// Answer is a single DNS resource record returned from a typed query.
// Type is the queried RR type, uppercase ("A", "MX", "TXT", ...) — plus
// "PTR" for reverse-lookups synthesised when q.Ptr is set.
// Hostname is the queried hostname (e.g. "example.com", or "_dmarc.example.com"
// for USD probes; for PTR Answers it is the IP whose PTR was looked up, in
// dotted/colon form).
// RR is the raw record from miekg/dns.
type Answer struct {
	Type     string
	Hostname string
	RR       dns.RR
}

// result is the internal channel message used by RunQuery's goroutine
// fan-out. Each typed lookup emits one result carrying zero or more Answers
// (including any PTR follow-ups for A/AAAA lookups) plus an optional error.
type result struct {
	Answers []Answer
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

// lookup performs a single typed DNS query and emits one result on stream
// carrying the answer records as []Answer. For A/AAAA queries with q.Ptr
// set, it also fans out PTR lookups in parallel and appends PTR-typed
// Answers (Hostname=IP, RR=*dns.PTR) to the same slice.
func lookup(stream chan<- result, client *dns.Client, rrtype, hostname string, q *Query) {
	qtype, ok := dns.StringToType[rrtype]
	if !ok {
		stream <- result{Error: fmt.Errorf("Error: unhandled type %q", rrtype)}
		return
	}

	msg := new(dns.Msg)
	msg.RecursionDesired = true
	msg.SetQuestion(dns.Fqdn(hostname), qtype)

	resp, err := dnsLookup(client, q.Server, msg, rrtype, hostname, q.IgnoreErrors)
	if err != nil || resp == nil {
		stream <- result{Error: err}
		return
	}

	answers := make([]Answer, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		answers = append(answers, Answer{Type: rrtype, Hostname: hostname, RR: rr})
	}

	if q.Ptr && (rrtype == "A" || rrtype == "AAAA") {
		answers = append(answers, ptrLookupAll(client, q.Server, resp.Answer)...)
	}

	stream <- result{Answers: answers}
}

// ptrLookupOne issues a single PTR query for ipArpa and emits a result
// carrying one Answer per dns.PTR RR in the response. The Hostname field
// on each Answer is the original IP (in dotted/colon form), so Render
// can group PTRs back by IP without re-parsing the in-addr.arpa name.
// PTR lookup failures are silently dropped (matching prior behavior).
func ptrLookupOne(stream chan<- result, client *dns.Client, server, ip, ipArpa string) {
	msg := new(dns.Msg)
	msg.RecursionDesired = true
	msg.SetQuestion(ipArpa, dns.TypePTR)

	resp, _, err := client.Exchange(msg, server)
	if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
		stream <- result{}
		return
	}

	var answers []Answer
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.PTR); ok {
			answers = append(answers, Answer{Type: "PTR", Hostname: ip, RR: rr})
		}
	}
	stream <- result{Answers: answers}
}

// ptrLookupAll fans out PTR queries for the A/AAAA records in addrRRs and
// returns the collected PTR Answers. Blocks until all goroutines respond
// or timeoutSeconds elapses.
func ptrLookupAll(client *dns.Client, server string, addrRRs []dns.RR) []Answer {
	stream := make(chan result)

	count := 0
	for _, rr := range addrRRs {
		var ip string
		switch x := rr.(type) {
		case *dns.A:
			ip = x.A.String()
		case *dns.AAAA:
			ip = x.AAAA.String()
		default:
			continue
		}
		ipArpa, err := dns.ReverseAddr(ip)
		if err != nil {
			continue
		}
		count++
		go ptrLookupOne(stream, client, server, ip, ipArpa)
	}

	var out []Answer
loop:
	for count > 0 {
		select {
		case res := <-stream:
			out = append(out, res.Answers...)
			count--
		case <-time.After(timeoutSeconds * time.Second):
			break loop
		}
	}
	return out
}

// Each formatX helper formats a single RR of its type into one
// `\n`-terminated tab-separated line. They are called from Render (not from
// the query path) so they perform no I/O.

func formatA(rrtype string, rr *dns.A, ptrMap map[string]string) string {
	ip := rr.A.String()
	ptrEntry := ""
	if pe, ok := ptrMap[ip]; ok {
		ptrEntry = "\t" + pe
	}
	return fmt.Sprintf("%s\t\t%s%s\n", rrtype, ip, ptrEntry)
}

func formatAAAA(rrtype string, rr *dns.AAAA, ptrMap map[string]string) string {
	ip := rr.AAAA.String()
	ptrEntry := ""
	if pe, ok := ptrMap[ip]; ok {
		ptrEntry = "\t" + pe
	}
	return fmt.Sprintf("%s\t\t%s%s\n", rrtype, ip, ptrEntry)
}

func formatCAA(rrtype string, rr *dns.CAA) string {
	return fmt.Sprintf("%s\t%d\t%s %s\n", rrtype, rr.Flag, rr.Tag, rr.Value)
}

func formatCNAME(rrtype string, rr *dns.CNAME) string {
	return fmt.Sprintf("%s\t\t%s\n", rrtype, rr.Target)
}

func formatDNSKEY(rrtype string, rr *dns.DNSKEY) string {
	return fmt.Sprintf("%s\t%d %d %d\t%s\n", rrtype, rr.Flags, rr.Protocol, rr.Algorithm, rr.PublicKey)
}

func formatMX(rrtype string, rr *dns.MX) string {
	return fmt.Sprintf("%s\t%d\t%s\n", rrtype, rr.Preference, rr.Mx)
}

func formatNS(rrtype string, rr *dns.NS) string {
	return fmt.Sprintf("%s\t\t%s\n", rrtype, rr.Ns)
}

func formatNSEC(rrtype string, rr *dns.NSEC) string {
	s := fmt.Sprintf("%s\t\t%s", rrtype, rr.NextDomain)
	for _, t := range rr.TypeBitMap {
		s += " " + dns.Type(t).String()
	}
	return s + "\n"
}

func formatRRSIG(rrtype string, rr *dns.RRSIG) string {
	return fmt.Sprintf("%s\t\t%s %d %d %d %s %s %d %s %s\n",
		rrtype, dns.Type(rr.TypeCovered).String(),
		rr.Algorithm, rr.Labels, rr.OrigTtl,
		dns.TimeToString(rr.Expiration), dns.TimeToString(rr.Inception),
		rr.KeyTag, rr.SignerName, rr.Signature,
	)
}

func formatSOA(rrtype string, rr *dns.SOA) string {
	return fmt.Sprintf("%s\t\t%s %s\n", rrtype, rr.Ns, rr.Mbox)
}

func formatSRV(rrtype string, rr *dns.SRV) string {
	return fmt.Sprintf("%s\t%d %d %d\t%s\n", rrtype, rr.Priority, rr.Weight, rr.Port, rr.Target)
}

func formatTXT(rrtype string, rr *dns.TXT) string {
	return fmt.Sprintf("%s\t\t%s\n", rrtype, strings.Join(rr.Txt, ""))
}

// Render turns a slice of Answers into the canonical dany text output:
// one tab-separated `\n`-terminated line per non-PTR Answer, with PTR
// records folded into their corresponding A/AAAA lines, sorted globally.
// Exact-duplicate lines are collapsed (relevant when --www queries surface
// IPs the apex already returned).
// If tagHostname is true each line is prefixed with the queried hostname
// and a tab — useful when caller is multiplexing multiple hostnames.
// Render does no I/O.
func Render(answers []Answer, tagHostname bool) string {
	// Fold PTR Answers into an ip -> "target1 target2 ..." map.
	// Multiple PTRs for one IP are sorted alphabetically and space-joined,
	// matching the legacy formatPTRAppend behavior.
	ptrTargets := make(map[string][]string)
	for _, a := range answers {
		if a.Type != "PTR" {
			continue
		}
		if rr, ok := a.RR.(*dns.PTR); ok {
			ptrTargets[a.Hostname] = append(ptrTargets[a.Hostname], rr.Ptr)
		}
	}
	ptrMap := make(map[string]string, len(ptrTargets))
	for ip, targets := range ptrTargets {
		sort.Strings(targets)
		ptrMap[ip] = strings.Join(targets, " ")
	}

	var lines []string
	seen := make(map[string]bool)
	for _, a := range answers {
		line := formatAnswer(a, ptrMap)
		if line == "" {
			continue
		}
		if tagHostname {
			line = a.Hostname + "\t" + line
		}
		if seen[line] {
			continue
		}
		seen[line] = true
		lines = append(lines, line)
	}
	sort.Strings(lines)
	return strings.Join(lines, "")
}

// formatAnswer renders a single Answer into one `\n`-terminated line,
// dispatching to the per-RR formatX helpers. Returns "" for Answers whose
// Type doesn't have a registered formatter (notably PTR, which is folded
// into A/AAAA output by Render rather than emitted as its own line).
func formatAnswer(a Answer, ptrMap map[string]string) string {
	switch rr := a.RR.(type) {
	case *dns.A:
		return formatA(a.Type, rr, ptrMap)
	case *dns.AAAA:
		return formatAAAA(a.Type, rr, ptrMap)
	case *dns.CAA:
		return formatCAA(a.Type, rr)
	case *dns.CNAME:
		return formatCNAME(a.Type, rr)
	case *dns.DNSKEY:
		return formatDNSKEY(a.Type, rr)
	case *dns.MX:
		return formatMX(a.Type, rr)
	case *dns.NS:
		return formatNS(a.Type, rr)
	case *dns.NSEC:
		return formatNSEC(a.Type, rr)
	case *dns.RRSIG:
		return formatRRSIG(a.Type, rr)
	case *dns.SOA:
		return formatSOA(a.Type, rr)
	case *dns.SRV:
		return formatSRV(a.Type, rr)
	case *dns.TXT:
		return formatTXT(a.Type, rr)
	}
	return ""
}

// defaultWwwTypes is the default set of RR types fired against the
// www.<hostname> probe when Query.Www is set and Query.WwwTypes is empty.
// Intentionally address-only: --www is a "what does www. point at?" probe,
// and Render dedups identical A/AAAA lines so a matching apex IP collapses
// into the existing row.
var defaultWwwTypes = []string{"A", "AAAA"}

// wwwTypes returns the RR types to fire against www.<q.Hostname>:
// q.WwwTypes when set, defaultWwwTypes otherwise.
func wwwTypes(q *Query) []string {
	if len(q.WwwTypes) > 0 {
		return q.WwwTypes
	}
	return defaultWwwTypes
}

// RunQuery fans out concurrent typed DNS lookups for q.Hostname across
// q.Types (plus USD TXT probes if q.Usd is set, plus A/AAAA probes against
// www.<q.Hostname> if q.Www is set, plus PTR follow-ups for A/AAAA if q.Ptr
// is set) and returns the collected Answers and per-query errors. The
// returned slice is unsorted; pass it through Render for the canonical
// tab-separated text representation.
//
// On wall-clock timeout (timeoutSeconds), in-flight goroutines' results
// are silently dropped — they appear as neither Answers nor errors.
func RunQuery(q *Query) ([]Answer, []error) {
	count := len(q.Types)
	if q.Usd {
		count += len(SupportedUSDs)
	}
	if q.Www {
		count += len(wwwTypes(q))
	}
	stream := make(chan result, count)

	client := new(dns.Client)
	// Default to TCP; TXT/DNSKEY responses are often too big for UDP.
	if !q.Udp {
		client.Net = "tcp"
	}
	client.Timeout = timeoutSeconds / 2 * time.Second

	for _, t := range q.Types {
		go lookup(stream, client, strings.ToUpper(t), q.Hostname, q)
	}
	if q.Usd {
		q.IgnoreErrors = true
		for _, usd := range SupportedUSDs {
			go lookup(stream, client, "TXT", usd+"."+q.Hostname, q)
		}
	}
	if q.Www {
		// www probes are best-effort: a missing www.<host> shouldn't
		// surface as an error alongside successful apex answers.
		q.IgnoreErrors = true
		for _, t := range wwwTypes(q) {
			go lookup(stream, client, strings.ToUpper(t), "www."+q.Hostname, q)
		}
	}

	var answers []Answer
	var errs []error
loop:
	for count > 0 {
		select {
		case res := <-stream:
			if res.Error != nil {
				errs = append(errs, res.Error)
			}
			answers = append(answers, res.Answers...)
			count--
		case <-time.After(timeoutSeconds * time.Second):
			break loop
		}
	}

	return answers, errs
}

// RunNXQuery probes q.Hostname across multiple RR types and returns the
// count of probes that did NOT return NXDOMAIN — i.e. len(types) - nxcount,
// where types is q.Types if non-empty else NXTypes.
//
// Interpretation:
//   - 0           — every probe returned NXDOMAIN; hostname is fully NX.
//   - len(types)  — no probe returned NXDOMAIN (either real answers, other
//                   errors, or timeouts; we can't distinguish these here).
//   - in between  — partial NXDOMAIN; treated as not-NX by callers (dnx).
//
// Probes that time out or error with anything other than ErrNXDomain are
// counted as non-NX, so transient failures bias toward "not NX" rather than
// false-positive NXDOMAIN reports.
//
// NX probes intentionally stay on UDP regardless of q.Udp — responses are
// tiny and there is no benefit to TCP for this codepath.
func RunNXQuery(q *Query) int {
	types := NXTypes
	if len(q.Types) > 0 {
		types = make([]string, len(q.Types))
		for i, t := range q.Types {
			types[i] = strings.ToUpper(t)
		}
	}

	// Do lookups, using errorStream to gather results
	errorStream := make(chan error, len(types))
	client := new(dns.Client)
	// Set client timeouts (dial/read/write) to timeoutSeconds / 2
	client.Timeout = timeoutSeconds / 2 * time.Second
	// Run standard lookups
	count := 0
	for _, t := range types {
		go nxlookup(errorStream, client, q.Server, t, q.Hostname)
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

	return len(types) - nxcount
}
