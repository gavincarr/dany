package dany

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// SchemaVersion is the JSON output schema version, bumped only for
// backwards-incompatible changes. Additive changes (new optional fields,
// new RR types, new error codes) do not bump it.
const SchemaVersion = 1

// Output is the top-level envelope returned per hostname. Used as the
// data model for every renderer (JSON, YAML, ...) — see render_json.go /
// render_yaml.go for the format-specific wrappers around BuildOutput.
// Stable shape; new fields may be added but existing fields must not be
// renamed or removed without bumping SchemaVersion.
type Output struct {
	SchemaVersion int            `json:"schema_version" yaml:"schema_version"`
	Query         OutputQuery    `json:"query"          yaml:"query"`
	Answers       []OutputAnswer `json:"answers"        yaml:"answers"`
	Errors        []OutputError  `json:"errors"         yaml:"errors"`
}

type OutputQuery struct {
	Hostname string        `json:"hostname" yaml:"hostname"`
	Types    []string      `json:"types"    yaml:"types"`
	Server   string        `json:"server"   yaml:"server"`
	Options  OutputOptions `json:"options"  yaml:"options"`
}

type OutputOptions struct {
	Www bool `json:"www" yaml:"www"`
	Usd bool `json:"usd" yaml:"usd"`
	Ptr bool `json:"ptr" yaml:"ptr"`
}

// OutputAnswer is one DNS resource record. Rdata is the canonical DNS
// presentation form (always present); Data is the typed per-RR payload —
// see the per-type *Data structs for shapes.
type OutputAnswer struct {
	Type         string      `json:"type"          yaml:"type"`
	Name         string      `json:"name"          yaml:"name"`
	TTL          uint32      `json:"ttl"           yaml:"ttl"`
	Class        string      `json:"class"         yaml:"class"`
	Rdata        string      `json:"rdata"         yaml:"rdata"`
	Data         interface{} `json:"data"          yaml:"data"`
	PresentEmpty bool        `json:"present_empty,omitempty" yaml:"present_empty,omitempty"`
}

// OutputError mirrors QueryError for the envelope. Code is a stable
// machine-readable identifier (e.g. "NXDOMAIN", "SERVFAIL",
// "EXCHANGE_ERROR", "UNSUPPORTED_TYPE", or "UNKNOWN" for errors lacking a
// QueryError wrapper). Message preserves the human-readable text.
type OutputError struct {
	Type     string `json:"type,omitempty"     yaml:"type,omitempty"`
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	Code     string `json:"code"               yaml:"code"`
	Message  string `json:"message"            yaml:"message"`
}

// Per-RR-type data payloads. Keep field tags snake_case (json and yaml
// match). New RR types require: a new *Data struct, a case in
// marshalData, and a case in formatAnswer + a formatX helper (for text
// output).

type AData struct {
	Address string `json:"address" yaml:"address"`
}

type AAAAData struct {
	Address string `json:"address" yaml:"address"`
}

type CNAMEData struct {
	Target string `json:"target" yaml:"target"`
}

type NSData struct {
	Target string `json:"target" yaml:"target"`
}

// PTRData carries Target (the resolved hostname) and IP (the original IP
// the PTR was queried for, recovered from the in-addr.arpa/ip6.arpa name).
// IP is empty for PTR records that aren't reverse lookups of an IP.
type PTRData struct {
	Target string `json:"target"        yaml:"target"`
	IP     string `json:"ip,omitempty"  yaml:"ip,omitempty"`
}

type MXData struct {
	Preference uint16 `json:"preference" yaml:"preference"`
	Exchange   string `json:"exchange"   yaml:"exchange"`
}

type SOAData struct {
	MName   string `json:"mname"   yaml:"mname"`
	RName   string `json:"rname"   yaml:"rname"`
	Serial  uint32 `json:"serial"  yaml:"serial"`
	Refresh uint32 `json:"refresh" yaml:"refresh"`
	Retry   uint32 `json:"retry"   yaml:"retry"`
	Expire  uint32 `json:"expire"  yaml:"expire"`
	Minimum uint32 `json:"minimum" yaml:"minimum"`
}

// TXTData exposes the raw multi-string form (TXT can legitimately carry
// multiple character-strings). Consumers wanting the concatenated text
// can join them; Rdata also carries the presentation form.
type TXTData struct {
	Strings []string `json:"strings" yaml:"strings"`
}

type CAAData struct {
	Flag  uint8  `json:"flag"  yaml:"flag"`
	Tag   string `json:"tag"   yaml:"tag"`
	Value string `json:"value" yaml:"value"`
}

type SRVData struct {
	Priority uint16 `json:"priority" yaml:"priority"`
	Weight   uint16 `json:"weight"   yaml:"weight"`
	Port     uint16 `json:"port"     yaml:"port"`
	Target   string `json:"target"   yaml:"target"`
}

// SVCBData is the shared payload for SVCB and its HTTPS alias (RFC 9460).
// Params is an ordered slice (not a map) to preserve the record's canonical
// ascending-key wire order and keep output deterministic. Values are the
// presentation form of each SvcParamValue (e.g. alpn -> "h2,h3"); the ech
// param carries an opaque base64 ECHConfig, surfaced verbatim.
type SVCBParam struct {
	Key   string `json:"key"   yaml:"key"`
	Value string `json:"value" yaml:"value"`
}

type SVCBData struct {
	Priority uint16      `json:"priority" yaml:"priority"`
	Target   string      `json:"target"   yaml:"target"`
	Params   []SVCBParam `json:"params"   yaml:"params"`
}

type DNSKEYData struct {
	Flags     uint16 `json:"flags"      yaml:"flags"`
	Protocol  uint8  `json:"protocol"   yaml:"protocol"`
	Algorithm uint8  `json:"algorithm"  yaml:"algorithm"`
	PublicKey string `json:"public_key" yaml:"public_key"`
}

type NSECData struct {
	NextDomain string   `json:"next_domain" yaml:"next_domain"`
	Types      []string `json:"types"       yaml:"types"`
}

type RRSIGData struct {
	TypeCovered string `json:"type_covered" yaml:"type_covered"`
	Algorithm   uint8  `json:"algorithm"    yaml:"algorithm"`
	Labels      uint8  `json:"labels"       yaml:"labels"`
	OriginalTTL uint32 `json:"original_ttl" yaml:"original_ttl"`
	Expiration  string `json:"expiration"   yaml:"expiration"`
	Inception   string `json:"inception"    yaml:"inception"`
	KeyTag      uint16 `json:"key_tag"      yaml:"key_tag"`
	SignerName  string `json:"signer_name"  yaml:"signer_name"`
	Signature   string `json:"signature"    yaml:"signature"`
}

// BuildOutput assembles the typed Output envelope from a RunQuery result.
// Answers and Errors are sorted into a stable total order (see below) so
// consecutive runs render identically despite RunQuery's nondeterministic
// concurrent arrival order. The marshaling step (json/yaml/...) is the
// caller's concern — see RenderJSON for the canonical NDJSON wrapper.
func BuildOutput(answers []Answer, q *Query, errs []error) *Output {
	out := &Output{
		SchemaVersion: SchemaVersion,
		Query: OutputQuery{
			Hostname: q.Hostname,
			Types:    q.Types,
			Server:   q.Server,
			Options: OutputOptions{
				Www: q.Www,
				Usd: q.Usd,
				Ptr: q.Ptr,
			},
		},
		Answers: make([]OutputAnswer, 0, len(answers)),
		Errors:  make([]OutputError, 0, len(errs)),
	}
	for _, a := range answers {
		oa, ok := buildAnswer(a)
		if !ok {
			continue
		}
		out.Answers = append(out.Answers, oa)
	}
	for _, e := range errs {
		out.Errors = append(out.Errors, buildError(e))
	}

	// RunQuery drains a stream of concurrent goroutines, so Answers and
	// Errors arrive in nondeterministic order. Sort both into a stable total
	// order so consecutive runs produce identical output. The answer key
	// (Type, then Rdata) mirrors the text renderer, which sorts its
	// tab-separated lines by RR type followed by the rdata columns; Name and
	// TTL are pure tiebreakers for full determinism. Rdata is compared in
	// natural order (see naturalCompare) so numeric fields like MX preference
	// sort by value ("9" before "10"), not lexically.
	sort.Slice(out.Answers, func(i, j int) bool {
		a, b := out.Answers[i], out.Answers[j]
		switch {
		case a.Type != b.Type:
			return a.Type < b.Type
		case a.Rdata != b.Rdata:
			return naturalCompare(a.Rdata, b.Rdata) < 0
		case a.Name != b.Name:
			return a.Name < b.Name
		default:
			return a.TTL < b.TTL
		}
	})

	// Dedup on RRset identity (Type, Name, Class, Rdata). An RRset is a set,
	// so duplicate wire RRs carry no meaning (RFC 2181 §5). Runs after the
	// sort above, so the first occurrence of each key is the lowest-TTL copy
	// (TTL is the sort's final tiebreaker) — matching RFC 2181 §5.2's "treat
	// as the minimum TTL". Name-distinct records (www/apex, per-IP PTRs,
	// CNAME hops) differ in Name or Rdata and are preserved.
	if len(out.Answers) > 1 {
		seen := make(map[string]bool, len(out.Answers))
		deduped := out.Answers[:0]
		for _, a := range out.Answers {
			key := a.Type + "\x00" + a.Name + "\x00" + a.Class + "\x00" + a.Rdata
			if seen[key] {
				continue
			}
			seen[key] = true
			deduped = append(deduped, a)
		}
		out.Answers = deduped
	}

	sort.Slice(out.Errors, func(i, j int) bool {
		a, b := out.Errors[i], out.Errors[j]
		switch {
		case a.Type != b.Type:
			return a.Type < b.Type
		case a.Hostname != b.Hostname:
			return a.Hostname < b.Hostname
		case a.Code != b.Code:
			return a.Code < b.Code
		default:
			return a.Message < b.Message
		}
	})

	return out
}

// RenderJSON serializes BuildOutput as a single JSON object terminated by
// a newline — i.e. ready to concatenate into NDJSON across multiple
// hostname invocations.
func RenderJSON(answers []Answer, q *Query, errs []error) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(BuildOutput(answers, q, errs))
	return buf.String()
}

func buildAnswer(a Answer) (OutputAnswer, bool) {
	if a.Empty {
		return OutputAnswer{
			Type:         a.Type,
			Name:         dns.Fqdn(a.Hostname),
			PresentEmpty: true,
		}, true
	}
	data, ok := marshalData(a)
	if !ok {
		return OutputAnswer{}, false
	}
	hdr := a.RR.Header()
	return OutputAnswer{
		Type:  dns.TypeToString[hdr.Rrtype],
		Name:  hdr.Name,
		TTL:   hdr.Ttl,
		Class: dns.ClassToString[hdr.Class],
		Rdata: rdataString(a.RR),
		Data:  data,
	}, true
}

// svcbData builds the shared SVCB/HTTPS payload, flattening the SvcParams
// into an ordered key/value slice (wire order is canonical ascending-key,
// so the result is deterministic without an explicit sort).
func svcbData(r *dns.SVCB) SVCBData {
	params := make([]SVCBParam, 0, len(r.Value))
	for _, kv := range r.Value {
		params = append(params, SVCBParam{Key: kv.Key().String(), Value: kv.String()})
	}
	return SVCBData{Priority: r.Priority, Target: r.Target, Params: params}
}

// marshalData returns the per-RR-type Data payload. Returns (nil, false)
// for RR types we don't have a schema for — buildAnswer drops them so the
// output never contains a half-described record.
func marshalData(a Answer) (interface{}, bool) {
	switch r := a.RR.(type) {
	case *dns.A:
		return AData{Address: r.A.String()}, true
	case *dns.AAAA:
		return AAAAData{Address: r.AAAA.String()}, true
	case *dns.CNAME:
		return CNAMEData{Target: r.Target}, true
	case *dns.NS:
		return NSData{Target: r.Ns}, true
	case *dns.PTR:
		return PTRData{Target: r.Ptr, IP: a.Hostname}, true
	case *dns.MX:
		return MXData{Preference: r.Preference, Exchange: r.Mx}, true
	case *dns.SOA:
		return SOAData{
			MName:   r.Ns,
			RName:   r.Mbox,
			Serial:  r.Serial,
			Refresh: r.Refresh,
			Retry:   r.Retry,
			Expire:  r.Expire,
			Minimum: r.Minttl,
		}, true
	case *dns.TXT:
		return TXTData{Strings: r.Txt}, true
	case *dns.CAA:
		return CAAData{Flag: r.Flag, Tag: r.Tag, Value: r.Value}, true
	case *dns.SRV:
		return SRVData{
			Priority: r.Priority,
			Weight:   r.Weight,
			Port:     r.Port,
			Target:   r.Target,
		}, true
	case *dns.HTTPS:
		return svcbData(&r.SVCB), true
	case *dns.SVCB:
		return svcbData(r), true
	case *dns.DNSKEY:
		return DNSKEYData{
			Flags:     r.Flags,
			Protocol:  r.Protocol,
			Algorithm: r.Algorithm,
			PublicKey: r.PublicKey,
		}, true
	case *dns.NSEC:
		types := make([]string, 0, len(r.TypeBitMap))
		for _, t := range r.TypeBitMap {
			types = append(types, dns.Type(t).String())
		}
		return NSECData{NextDomain: r.NextDomain, Types: types}, true
	case *dns.RRSIG:
		return RRSIGData{
			TypeCovered: dns.Type(r.TypeCovered).String(),
			Algorithm:   r.Algorithm,
			Labels:      r.Labels,
			OriginalTTL: r.OrigTtl,
			Expiration:  dns.TimeToString(r.Expiration),
			Inception:   dns.TimeToString(r.Inception),
			KeyTag:      r.KeyTag,
			SignerName:  r.SignerName,
			Signature:   r.Signature,
		}, true
	}
	return nil, false
}

// buildError converts a query error into the structured OutputError shape.
// QueryError values are unpacked into Type/Hostname/Code; anything else
// surfaces as Code "UNKNOWN" with the raw message preserved.
func buildError(e error) OutputError {
	var qe *QueryError
	if errors.As(e, &qe) {
		return OutputError{
			Type:     qe.Type,
			Hostname: qe.Hostname,
			Code:     qe.Code,
			Message:  e.Error(),
		}
	}
	return OutputError{Code: "UNKNOWN", Message: e.Error()}
}

// rdataString returns the rdata portion of an RR's zone-file presentation,
// i.e. rr.String() with the "name\tttl\tclass\ttype\t" header stripped.
// miekg's RR.String() is defined as Hdr.String() + <rdata>, so TrimPrefix
// is exact.
func rdataString(rr dns.RR) string {
	return strings.TrimPrefix(rr.String(), rr.Header().String())
}
