package dany

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

// RenderYAML serializes BuildOutput as one YAML document prefixed with
// `---\n`. Concatenating multiple RenderYAML outputs across hostnames
// yields a well-formed multi-document YAML stream.
//
// Output shape is the same Output envelope used by RenderJSON; the yaml
// struct tags on the *Data types are kept in lockstep with the json tags
// (snake_case, same field names) so consumers can swap formats without
// schema surprises.
func RenderYAML(answers []Answer, q *Query, errs []error) string {
	var buf bytes.Buffer
	buf.WriteString("---\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode(BuildOutput(answers, q, errs))
	_ = enc.Close()
	return buf.String()
}
