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

var DefaultRRTypes = []string{"A", "AAAA", "HTTPS", "MX", "NS", "SOA", "TXT"}
var SupportedRRTypes = []string{
	"A", "AAAA", "CAA", "CNAME", "DNSKEY", "HTTPS", "MX", "NS", "NSEC", "RRSIG", "SOA", "SRV", "SVCB", "TXT",
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
	Empty    bool // present-empty (NODATA); RR is nil when true
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

// QueryError is the structured error type emitted by RunQuery / RunNXQuery
// goroutines. It carries the RR type and hostname that were being queried
// plus a stable string Code (DNS rcode names like "NXDOMAIN"/"SERVFAIL",
// plus "EXCHANGE_ERROR" for transport-level failures and "UNSUPPORTED_TYPE"
// for unknown RR types) so structured consumers — notably the JSON renderer
// — can act on errors without parsing the message.
//
// Error() preserves the historical `Error on <type> lookup for "<host>": <…>`
// format so legacy text consumers and existing substring-based tests keep
// working. Unwrap exposes the underlying error so errors.Is(err, ErrNXDomain)
// / ErrServFail continue to match.
type QueryError struct {
	Type     string
	Hostname string
	Code     string
	Err      error
}

func (e *QueryError) Error() string {
	tail := e.Code
	if e.Err != nil {
		tail = e.Err.Error()
	}
	return fmt.Sprintf("Error on %s lookup for %q: %s", e.Type, e.Hostname, tail)
}

func (e *QueryError) Unwrap() error { return e.Err }

// rcodeCode maps a DNS response rcode to the stable string code used in
// QueryError.Code. Falls back to "RCODE_<n>" for rcodes the dns library
// doesn't have a registered name for.
func rcodeCode(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return fmt.Sprintf("RCODE_%d", rcode)
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
func dnsLookup(client *dns.Client, server string, msg *dns.Msg, rrtype, hostname string, ignoreErrors bool) (*dns.Msg, error) {
	resp, _, err := client.Exchange(msg, server)
	// Return exchange errors
	if err != nil {
		return nil, &QueryError{
			Type:     rrtype,
			Hostname: hostname,
			Code:     "EXCHANGE_ERROR",
			Err:      err,
		}
	}
	if resp != nil {
		// Return dns response errors (unless ignoreErrors is true)
		if resp.Rcode != dns.RcodeSuccess {
			if ignoreErrors {
				return nil, nil
			}
			qe := &QueryError{
				Type:     rrtype,
				Hostname: hostname,
				Code:     rcodeCode(resp.Rcode),
			}
			// Wrap the canonical sentinels so errors.Is keeps working.
			switch resp.Rcode {
			case dns.RcodeNameError:
				qe.Err = ErrNXDomain
			case dns.RcodeServerFailure:
				qe.Err = ErrServFail
			}
			return nil, qe
		}
		// Handle CNAMEs: chase the target, but preserve the CNAME hop so
		// structured renderers can capture the mapping. The traversed CNAME
		// is prepended to the resolved answers; the text renderer folds it
		// out (it cares about the end result), while JSON/YAML emit it as its
		// own record. Multi-hop chains accumulate one CNAME per level.
		ans := resp.Answer
		if len(ans) > 0 && ans[0].Header().Rrtype == dns.TypeCNAME && rrtype != "CNAME" {
			cname := ans[0].(*dns.CNAME)
			msg.SetQuestion(dns.Fqdn(cname.Target), msg.Question[0].Qtype)
			target, err := dnsLookup(client, server, msg, rrtype, hostname, ignoreErrors)
			if err != nil || target == nil {
				return target, err
			}
			target.Answer = append([]dns.RR{cname}, target.Answer...)
			return target, nil
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
func lookup(stream chan<- result, client *dns.Client, rrtype, hostname string, q *Query, usd bool) {
	qtype, ok := dns.StringToType[rrtype]
	if !ok {
		stream <- result{Error: &QueryError{
			Type:     rrtype,
			Hostname: hostname,
			Code:     "UNSUPPORTED_TYPE",
			Err:      fmt.Errorf("unhandled type %q", rrtype),
		}}
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

	// USD probes: a name that exists but returns no records (NODATA / empty
	// non-terminal) is a positive existence signal — surface it as a
	// record-less Answer. NXDOMAIN returns resp==nil above and is omitted.
	if usd && len(resp.Answer) == 0 {
		answers = append(answers, Answer{Type: rrtype, Hostname: hostname, Empty: true})
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

// formatSVCB renders an SVCB/HTTPS record: priority in the numeric column,
// then the target followed by its SvcParams (key=value, space-joined) in the
// value column. Handles both SVCB and its HTTPS alias — callers pass the
// embedded *dns.SVCB and the queried type name.
func formatSVCB(rrtype string, rr *dns.SVCB) string {
	value := rr.Target
	for _, kv := range rr.Value {
		value += " " + kv.Key().String() + "=" + kv.String()
	}
	return fmt.Sprintf("%s\t%d\t%s\n", rrtype, rr.Priority, value)
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
		line := formatAnswer(a, ptrMap, tagHostname)
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
	sort.Slice(lines, func(i, j int) bool {
		return naturalCompare(lines[i], lines[j]) < 0
	})
	return strings.Join(lines, "")
}

// naturalCompare compares a and b in "natural" order: maximal runs of ASCII
// digits are compared by numeric value rather than bytewise, so "9" orders
// before "10" and "10.0.0.2" before "10.0.0.10". Non-digit bytes compare
// bytewise. Returns -1, 0, or +1. Shared by the text renderer (Render) and
// the structured renderers (BuildOutput) so numeric rdata fields — MX
// preference, SRV priority/weight/port, etc. — sort by value, not by their
// leading digit.
func naturalCompare(a, b string) int {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		ca, cb := a[i], b[j]
		if isDigit(ca) && isDigit(cb) {
			ie := i
			for ie < len(a) && isDigit(a[ie]) {
				ie++
			}
			je := j
			for je < len(b) && isDigit(b[je]) {
				je++
			}
			if c := compareDigitRun(a[i:ie], b[j:je]); c != 0 {
				return c
			}
			i, j = ie, je
			continue
		}
		if ca != cb {
			if ca < cb {
				return -1
			}
			return 1
		}
		i++
		j++
	}
	// Shared prefix consumed; the shorter remainder sorts first.
	switch {
	case len(a)-i < len(b)-j:
		return -1
	case len(a)-i > len(b)-j:
		return 1
	default:
		return 0
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// compareDigitRun compares two all-digit substrings by numeric value,
// tiebreaking equal values by raw run length (more leading zeros sort first)
// so the result is a deterministic total order.
func compareDigitRun(a, b string) int {
	as, bs := strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	switch {
	case len(as) != len(bs):
		if len(as) < len(bs) {
			return -1
		}
		return 1
	case as != bs:
		if as < bs {
			return -1
		}
		return 1
	case len(a) != len(b):
		if len(a) < len(b) {
			return -1
		}
		return 1
	default:
		return 0
	}
}

// formatAnswer renders a single Answer into one `\n`-terminated line,
// dispatching to the per-RR formatX helpers. An Answer with Empty == true
// (an empty non-terminal) short-circuits before the RR-type switch and
// returns the tag-aware "[present; no records]" marker line instead.
// Returns "" for Answers whose Type doesn't have a registered formatter
// (notably PTR, which is folded into A/AAAA output by Render rather than
// emitted as its own line).
func formatAnswer(a Answer, ptrMap map[string]string, tagHostname bool) string {
	// An empty non-terminal (name exists, no records of the queried type) has
	// no RR. Show the owner name exactly once: in the value when untagged,
	// or via the tag column Render prepends under --tag.
	if a.Empty {
		if tagHostname {
			return fmt.Sprintf("%s\t\t[present; no records]\n", a.Type)
		}
		return fmt.Sprintf("%s\t\t%s [present; no records]\n", a.Type, dns.Fqdn(a.Hostname))
	}
	// A CNAME surfaced under a non-CNAME query type is a chain hop captured
	// for the structured renderers; text folds it out, since the resolved
	// target records it points at are already present. Explicit `-t CNAME`
	// queries (Type == "CNAME") still render via the case below.
	if _, ok := a.RR.(*dns.CNAME); ok && a.Type != "CNAME" {
		return ""
	}
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
	case *dns.HTTPS:
		return formatSVCB(a.Type, &rr.SVCB)
	case *dns.SVCB:
		return formatSVCB(a.Type, rr)
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
		go lookup(stream, client, strings.ToUpper(t), q.Hostname, q, false)
	}
	if q.Usd {
		q.IgnoreErrors = true
		for _, usd := range SupportedUSDs {
			go lookup(stream, client, "TXT", usd+"."+q.Hostname, q, true)
		}
	}
	if q.Www {
		// www probes are best-effort: a missing www.<host> shouldn't
		// surface as an error alongside successful apex answers.
		q.IgnoreErrors = true
		for _, t := range wwwTypes(q) {
			go lookup(stream, client, strings.ToUpper(t), "www."+q.Hostname, q, false)
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
//     errors, or timeouts; we can't distinguish these here).
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
