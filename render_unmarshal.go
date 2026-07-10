package dany

import (
	"encoding/json"
	"reflect"

	"gopkg.in/yaml.v3"
)

// newData returns a pointer to a fresh, zero-valued per-RR-type *Data struct
// for the given RR type name, or nil for a type dany has no schema for. It is
// the single source of truth mapping a type name to its Data struct and is
// shared by UnmarshalJSON and UnmarshalYAML, so the two decode paths can never
// disagree about a type's shape.
//
// The arms here must stay in lockstep with marshalData's RR-type arms (the
// marshal-side counterpart in render_json.go): marshalData maps a concrete
// dns.RR to a populated Data *value*; newData maps the resulting wire "type"
// discriminator back to an empty *Data *pointer* to decode into. Adding an RR
// type is now a fifth coordinated edit (the four in CLAUDE.md plus this one).
// TestOutputAnswer_RoundTrip drives every marshalData-supported type through a
// full round-trip and fails if the two lists drift apart.
func newData(typeName string) interface{} {
	switch typeName {
	case "A":
		return &AData{}
	case "AAAA":
		return &AAAAData{}
	case "CNAME":
		return &CNAMEData{}
	case "NS":
		return &NSData{}
	case "PTR":
		return &PTRData{}
	case "MX":
		return &MXData{}
	case "SOA":
		return &SOAData{}
	case "TXT":
		return &TXTData{}
	case "CAA":
		return &CAAData{}
	case "SRV":
		return &SRVData{}
	case "HTTPS", "SVCB":
		// Both share SVCBData (dns.HTTPS embeds dns.SVCB); see render_json.go.
		return &SVCBData{}
	case "DNSKEY":
		return &DNSKEYData{}
	case "DS":
		return &DSData{}
	case "NSEC":
		return &NSECData{}
	case "RRSIG":
		return &RRSIGData{}
	}
	return nil
}

// decodeData resolves the concrete Data value for an answer of the given RR
// type using the supplied format-specific decode function (json/yaml). Known
// types decode into their *Data struct and are returned as the *value* type
// (matching marshalData's value-typed payloads, so Marshal->Unmarshal is a
// faithful round-trip). Unknown types fall back to a generic decode so a
// forward-compatible producer's extra RR types survive as a map rather than
// being dropped.
func decodeData(typeName string, decode func(interface{}) error) (interface{}, error) {
	dst := newData(typeName)
	if dst == nil {
		var generic interface{}
		if err := decode(&generic); err != nil {
			return nil, err
		}
		return generic, nil
	}
	if err := decode(dst); err != nil {
		return nil, err
	}
	// dst is a *T; return the dereferenced T to mirror marshalData.
	return reflect.ValueOf(dst).Elem().Interface(), nil
}

// UnmarshalJSON decodes an OutputAnswer, restoring the typed per-RR-type Data
// payload that a plain interface{} decode would otherwise flatten into a
// map[string]interface{} (with numbers as float64). The record's own "type"
// field is the discriminator: after decoding the envelope fields, the raw
// "data" object is re-decoded into the concrete *Data struct newData picks.
//
// Marshal keeps its natural interface{} path (encoding/json reflects the
// concrete Data value it holds), so no MarshalJSON counterpart is needed and
// Marshal->Unmarshal is symmetric: a value that went out as MXData comes back
// as MXData, not a map.
func (oa *OutputAnswer) UnmarshalJSON(b []byte) error {
	// shadow aliases OutputAnswer but drops its methods (a defined type does
	// not inherit the underlying type's method set), so decoding into it does
	// not recurse back into this method. The explicit depth-0 Data field
	// (json.RawMessage) shadows shadow's promoted depth-1 Data field, so the
	// raw payload is captured verbatim instead of being eagerly decoded.
	type shadow OutputAnswer
	aux := struct {
		*shadow
		Data json.RawMessage `json:"data"`
	}{shadow: (*shadow)(oa)}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}

	oa.Data = nil
	if len(aux.Data) == 0 || string(aux.Data) == "null" {
		// present-empty answers and any record with no data payload.
		return nil
	}
	data, err := decodeData(oa.Type, func(v interface{}) error {
		return json.Unmarshal(aux.Data, v)
	})
	if err != nil {
		return err
	}
	oa.Data = data
	return nil
}

// UnmarshalYAML mirrors UnmarshalJSON for the yaml.v3 decoder: it restores the
// typed Data payload keyed off the "type" discriminator. Without it yaml.v3
// decodes the interface{} Data field into a map[string]interface{}, the same
// way encoding/json does. Marshalling stays on the default reflection path, so
// there is no MarshalYAML counterpart.
func (oa *OutputAnswer) UnmarshalYAML(value *yaml.Node) error {
	// Decode the envelope fields first (Data lands as a generic map here and
	// is discarded below). The alias drops UnmarshalYAML, so no recursion.
	type shadow OutputAnswer
	if err := value.Decode((*shadow)(oa)); err != nil {
		return err
	}

	oa.Data = nil
	if value.Kind != yaml.MappingNode {
		return nil
	}
	// A mapping node's Content is a flat [key, val, key, val, ...] slice. Find
	// the raw "data" value node and re-decode it into the concrete type.
	for i := 0; i+1 < len(value.Content); i += 2 {
		if value.Content[i].Value != "data" {
			continue
		}
		dataNode := value.Content[i+1]
		if dataNode.Tag == "!!null" {
			// present-empty answers marshal Data as an explicit null.
			return nil
		}
		data, err := decodeData(oa.Type, dataNode.Decode)
		if err != nil {
			return err
		}
		oa.Data = data
		return nil
	}
	return nil
}
