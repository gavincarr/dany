package dany

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/gavincarr/dany/internal/testdns"
	"gopkg.in/yaml.v3"
)

// TestOutputAnswer_RoundTrip is the drift guard between marshalData
// (render_json.go) and newData (render_unmarshal.go): every RR type
// marshalData can emit must survive a Marshal->Unmarshal round-trip with its
// typed Data payload byte-for-byte intact, for both JSON and YAML. A type
// added to marshalData but not newData decodes back to a generic map and
// fails the DeepEqual; the reverse fails the "still typed" check.
func TestOutputAnswer_RoundTrip(t *testing.T) {
	cases := []struct {
		typ, zone, hostname string
	}{
		{"A", "example.com. 300 IN A 1.2.3.4", "example.com"},
		{"AAAA", "example.com. 300 IN AAAA 2001:db8::1", "example.com"},
		{"CNAME", "alias.example.com. 300 IN CNAME target.example.com.", "example.com"},
		{"NS", "example.com. 86400 IN NS ns1.example.com.", "example.com"},
		{"PTR", "4.3.2.1.in-addr.arpa. 3600 IN PTR host.example.com.", "1.2.3.4"},
		{"MX", "example.com. 300 IN MX 10 mx1.example.com.", "example.com"},
		{"SOA", "example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 12345 7200 3600 1209600 300", "example.com"},
		{"TXT", `example.com. 60 IN TXT "v=spf1" "include:_spf.google.com" "~all"`, "example.com"},
		{"CAA", `example.com. 300 IN CAA 0 issue "letsencrypt.org"`, "example.com"},
		{"SRV", "_sip._tcp.example.com. 300 IN SRV 10 60 5060 sipserver.example.com.", "example.com"},
		{"HTTPS", `example.com. 300 IN HTTPS 1 . alpn="h2,h3" ipv4hint=1.2.3.4`, "example.com"},
		{"SVCB", `_dns.example.com. 300 IN SVCB 1 dns.example.com. alpn=dot`, "example.com"},
		{"DNSKEY", "example.com. 3600 IN DNSKEY 257 3 13 aGVsbG8=", "example.com"},
		{"DS", `example.com. 3600 IN DS 12345 13 2 1234567890123456789012345678901234567890123456789012345678901234`, "example.com"},
		{"NSEC", `example.com. 3600 IN NSEC next.example.com. A MX RRSIG NSEC`, "example.com"},
		{"RRSIG", `example.com. 3600 IN RRSIG A 13 2 3600 20250101000000 20240101000000 12345 example.com. aGVsbG8=`, "example.com"},
	}

	q := &Query{Hostname: "example.com"}
	for _, tc := range cases {
		t.Run(tc.typ, func(t *testing.T) {
			a := Answer{Type: tc.typ, Hostname: tc.hostname, RR: testdns.MustRR(tc.zone)}
			out := BuildOutput([]Answer{a}, q, nil)
			if len(out.Answers) != 1 {
				t.Fatalf("Answers len = %d, want 1", len(out.Answers))
			}
			orig := out.Answers[0]
			if orig.Data == nil {
				t.Fatalf("BuildOutput produced nil Data for %s — marshalData missing this type?", tc.typ)
			}

			t.Run("json", func(t *testing.T) {
				b, err := json.Marshal(orig)
				if err != nil {
					t.Fatalf("json.Marshal: %v", err)
				}
				var got OutputAnswer
				if err := json.Unmarshal(b, &got); err != nil {
					t.Fatalf("json.Unmarshal: %v", err)
				}
				assertRoundTrip(t, orig, got, "JSON")
			})

			t.Run("yaml", func(t *testing.T) {
				b, err := yaml.Marshal(orig)
				if err != nil {
					t.Fatalf("yaml.Marshal: %v", err)
				}
				var got OutputAnswer
				if err := yaml.Unmarshal(b, &got); err != nil {
					t.Fatalf("yaml.Unmarshal: %v", err)
				}
				assertRoundTrip(t, orig, got, "YAML")
			})
		})
	}
}

func assertRoundTrip(t *testing.T, orig, got OutputAnswer, format string) {
	t.Helper()
	if !reflect.DeepEqual(orig, got) {
		t.Errorf("%s round-trip mismatch:\n orig = %#v\n got  = %#v", format, orig, got)
	}
	// The whole point: Data comes back as the concrete *Data struct, not the
	// map[string]interface{} a plain interface{} decode would produce.
	if reflect.TypeOf(got.Data) != reflect.TypeOf(orig.Data) {
		t.Errorf("%s Data type = %T, want %T (typed, not flattened to a map)", format, got.Data, orig.Data)
	}
}

// TestOutputAnswer_UnmarshalPresentEmpty verifies a present-empty answer
// (Data marshalled as an explicit null) round-trips with nil Data and the
// present_empty discriminator preserved — the null must not blow up the
// type-directed decode.
func TestOutputAnswer_UnmarshalPresentEmpty(t *testing.T) {
	answers := []Answer{{Type: "TXT", Hostname: "_domainkey.example.com", Empty: true}}
	q := &Query{Hostname: "example.com", Types: []string{"A"}, Usd: true}
	orig := BuildOutput(answers, q, nil).Answers[0]

	for _, f := range []struct {
		name      string
		marshal   func(interface{}) ([]byte, error)
		unmarshal func([]byte, interface{}) error
	}{
		{"json", json.Marshal, json.Unmarshal},
		{"yaml", yaml.Marshal, yaml.Unmarshal},
	} {
		t.Run(f.name, func(t *testing.T) {
			b, err := f.marshal(orig)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got OutputAnswer
			if err := f.unmarshal(b, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !got.PresentEmpty {
				t.Errorf("PresentEmpty = false, want true")
			}
			if got.Data != nil {
				t.Errorf("Data = %#v, want nil for present-empty answer", got.Data)
			}
			if got.Name != "_domainkey.example.com." {
				t.Errorf("Name = %q, want _domainkey.example.com.", got.Name)
			}
		})
	}
}

// TestOutputAnswer_UnmarshalUnknownType verifies forward compatibility: an
// answer whose "type" newData has no schema for decodes its data into a
// generic value rather than being dropped or erroring.
func TestOutputAnswer_UnmarshalUnknownType(t *testing.T) {
	const js = `{"type":"FUTURE","name":"example.com.","ttl":300,"class":"IN","rdata":"whatever","data":{"some":"field","n":7}}`
	var got OutputAnswer
	if err := json.Unmarshal([]byte(js), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got.Type != "FUTURE" {
		t.Errorf("Type = %q, want FUTURE", got.Type)
	}
	d, ok := got.Data.(map[string]interface{})
	if !ok {
		t.Fatalf("unknown-type Data = %T, want map[string]interface{} (generic fallback)", got.Data)
	}
	if d["some"] != "field" {
		t.Errorf("data.some = %v, want field", d["some"])
	}
}
