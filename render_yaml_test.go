package dany

import (
	"strings"
	"testing"

	"github.com/gavincarr/dany/internal/testdns"
	"gopkg.in/yaml.v3"
)

// decodeYAML round-trips RenderYAML through the same Output struct used by
// BuildOutput. Comparing parsed structures (rather than raw bytes) avoids
// fragility around yaml.v3's indent/quoting choices.
func decodeYAML(t *testing.T, answers []Answer, q *Query, errs []error) Output {
	t.Helper()
	s := RenderYAML(answers, q, errs)
	if !strings.HasPrefix(s, "---\n") {
		t.Fatalf("RenderYAML output missing leading `---\\n` doc separator: %q", s)
	}
	var out Output
	if err := yaml.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("yaml.Unmarshal: %v\noutput was:\n%s", err, s)
	}
	return out
}

func TestRenderYAML_Envelope(t *testing.T) {
	srv := testdns.New(t)
	srv.Add(testdns.MustRR("example.com. 300 IN A 1.2.3.4"))

	q := &Query{
		Hostname: "example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
	}
	answers, errs := RunQuery(q)
	out := decodeYAML(t, answers, q, errs)

	if out.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", out.SchemaVersion, SchemaVersion)
	}
	if out.Query.Hostname != "example.com" {
		t.Errorf("Query.Hostname = %q, want example.com", out.Query.Hostname)
	}
	if len(out.Answers) != 1 || out.Answers[0].Type != "A" {
		t.Fatalf("Answers = %+v, want one A record", out.Answers)
	}
	// yaml.v3 unmarshals the typed Data payload into map[string]interface{}
	// the same way encoding/json does, so we can do the same assertion.
	d, ok := out.Answers[0].Data.(map[string]interface{})
	if !ok {
		t.Fatalf("Data not an object: %T", out.Answers[0].Data)
	}
	if d["address"] != "1.2.3.4" {
		t.Errorf("data.address = %v, want 1.2.3.4", d["address"])
	}
}

func TestRenderYAML_MultiDoc(t *testing.T) {
	// Concatenating two RenderYAML outputs must yield valid multi-doc YAML
	// — i.e. two parseable documents separated by `---`.
	q1 := &Query{Hostname: "a.example.com"}
	q2 := &Query{Hostname: "b.example.com"}
	combined := RenderYAML(nil, q1, nil) + RenderYAML(nil, q2, nil)

	dec := yaml.NewDecoder(strings.NewReader(combined))
	var docs []Output
	for {
		var o Output
		if err := dec.Decode(&o); err != nil {
			break
		}
		docs = append(docs, o)
	}
	if len(docs) != 2 {
		t.Fatalf("got %d documents, want 2:\n%s", len(docs), combined)
	}
	if docs[0].Query.Hostname != "a.example.com" || docs[1].Query.Hostname != "b.example.com" {
		t.Errorf("doc hostnames = %q, %q; want a.example.com, b.example.com",
			docs[0].Query.Hostname, docs[1].Query.Hostname)
	}
}

func TestRenderYAML_NXDOMAINError(t *testing.T) {
	srv := testdns.New(t)
	q := &Query{
		Hostname: "missing.example.com",
		Types:    []string{"A"},
		Server:   srv.Addr,
	}
	answers, errs := RunQuery(q)
	out := decodeYAML(t, answers, q, errs)

	if len(out.Errors) == 0 {
		t.Fatal("expected NXDOMAIN errors, got none")
	}
	if out.Errors[0].Code != "NXDOMAIN" {
		t.Errorf("error Code = %q, want NXDOMAIN", out.Errors[0].Code)
	}
	if out.Errors[0].Hostname != "missing.example.com" {
		t.Errorf("error Hostname = %q, want missing.example.com", out.Errors[0].Hostname)
	}
}
