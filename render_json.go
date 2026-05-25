package dany

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/miekg/dns"
)

// SchemaVersion is the JSON output schema version, bumped only for
// backwards-incompatible changes. Additive changes (new optional fields,
// new RR types, new error codes) do not bump it.
const SchemaVersion = 1

// Output is the top-level JSON envelope returned per hostname.
// Stable shape; new fields may be added but existing fields must not be
// renamed or removed without bumping SchemaVersion.
type Output struct {
	SchemaVersion int           `json:"schema_version"`
	Query         OutputQuery   `json:"query"`
	Answers       []OutputAnswer `json:"answers"`
	Errors        []OutputError  `json:"errors"`
}

type OutputQuery struct {
	Hostname string        `json:"hostname"`
	Types    []string      `json:"types"`
	Server   string        `json:"server"`
	Options  OutputOptions `json:"options"`
}

type OutputOptions struct {
	Www bool `json:"www"`
	Usd bool `json:"usd"`
	Ptr bool `json:"ptr"`
}

// OutputAnswer is one DNS resource record. Rdata is the canonical DNS
// presentation form (always present); Data is the typed per-RR payload —
// see the per-type *Data structs for shapes.
type OutputAnswer struct {
	Type  string      `json:"type"`
	Name  string      `json:"name"`
	TTL   uint32      `json:"ttl"`
	Class string      `json:"class"`
	Rdata string      `json:"rdata"`
	Data  interface{} `json:"data"`
}

// OutputError mirrors QueryError for the JSON envelope. Code is a stable
// machine-readable identifier (e.g. "NXDOMAIN", "SERVFAIL",
// "EXCHANGE_ERROR", "UNSUPPORTED_TYPE", or "UNKNOWN" for errors lacking a
// QueryError wrapper). Message preserves the human-readable text.
type OutputError struct {
	Type     string `json:"type,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// Per-RR-type data payloads. Keep field tags snake_case. New RR types
// require: a new *Data struct, a case in marshalData, and a case in
// formatAnswer + a formatX helper (for text output).

type AData struct {
	Address string `json:"address"`
}

type AAAAData struct {
	Address string `json:"address"`
}

type CNAMEData struct {
	Target string `json:"target"`
}

type NSData struct {
	Target string `json:"target"`
}

// PTRData carries Target (the resolved hostname) and IP (the original IP
// the PTR was queried for, recovered from the in-addr.arpa/ip6.arpa name).
// IP is empty for PTR records that aren't reverse lookups of an IP.
type PTRData struct {
	Target string `json:"target"`
	IP     string `json:"ip,omitempty"`
}

type MXData struct {
	Preference uint16 `json:"preference"`
	Exchange   string `json:"exchange"`
}

type SOAData struct {
	MName   string `json:"mname"`
	RName   string `json:"rname"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	Minimum uint32 `json:"minimum"`
}

// TXTData exposes the raw multi-string form (TXT can legitimately carry
// multiple character-strings). Consumers wanting the concatenated text
// can join them; Rdata also carries the presentation form.
type TXTData struct {
	Strings []string `json:"strings"`
}

type CAAData struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

type SRVData struct {
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
	Port     uint16 `json:"port"`
	Target   string `json:"target"`
}

type DNSKEYData struct {
	Flags     uint16 `json:"flags"`
	Protocol  uint8  `json:"protocol"`
	Algorithm uint8  `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

type NSECData struct {
	NextDomain string   `json:"next_domain"`
	Types      []string `json:"types"`
}

type RRSIGData struct {
	TypeCovered string `json:"type_covered"`
	Algorithm   uint8  `json:"algorithm"`
	Labels      uint8  `json:"labels"`
	OriginalTTL uint32 `json:"original_ttl"`
	Expiration  string `json:"expiration"`
	Inception   string `json:"inception"`
	KeyTag      uint16 `json:"key_tag"`
	SignerName  string `json:"signer_name"`
	Signature   string `json:"signature"`
}

// BuildOutput assembles the typed Output envelope from a RunQuery result.
// The marshaling step (json/yaml/...) is the caller's concern — see
// RenderJSON for the canonical NDJSON wrapper.
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
