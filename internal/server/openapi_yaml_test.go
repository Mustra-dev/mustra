package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// yamlAsJSON writes a decoded YAML document back as compact JSON, in its
// own key order, so it can be compared with the JSON document byte for
// byte. It fails on what RFC 9512's profile rules out: anchors, aliases,
// non-string keys and tags JSON has no value for.
func yamlAsJSON(t *testing.T, n *yaml.Node, out *bytes.Buffer) {
	t.Helper()
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		t.Fatalf("line %d: anchor or alias", n.Line)
	}
	switch n.Kind {
	case yaml.DocumentNode:
		yamlAsJSON(t, n.Content[0], out)
	case yaml.MappingNode:
		out.WriteByte('{')
		for i := 0; i < len(n.Content); i += 2 {
			if i > 0 {
				out.WriteByte(',')
			}
			if k := n.Content[i]; k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" {
				t.Fatalf("line %d: key %q is %s, not a string", k.Line, k.Value, k.ShortTag())
			}
			yamlAsJSON(t, n.Content[i], out)
			out.WriteByte(':')
			yamlAsJSON(t, n.Content[i+1], out)
		}
		out.WriteByte('}')
	case yaml.SequenceNode:
		out.WriteByte('[')
		for i, c := range n.Content {
			if i > 0 {
				out.WriteByte(',')
			}
			yamlAsJSON(t, c, out)
		}
		out.WriteByte(']')
	case yaml.ScalarNode:
		switch n.ShortTag() {
		case "!!str":
			b, _ := json.Marshal(n.Value)
			out.Write(b)
		case "!!int", "!!float", "!!bool", "!!null":
			out.WriteString(n.Value)
		default:
			t.Fatalf("line %d: %q is a %s", n.Line, n.Value, n.ShortTag())
		}
	}
}

// The YAML document is the JSON one: same keys in the same order, same
// numbers, same strings, served the same on every request.
func TestOpenAPIServesYAML(t *testing.T) {
	s := &Server{logger: slog.Default()}
	s.routes()
	var bodies []string
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		s.handleOpenAPIYAML(rec, httptest.NewRequest(http.MethodGet, "/api/openapi.yaml", nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/yaml" {
			t.Fatalf("status %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
		}
		bodies = append(bodies, rec.Body.String())
	}
	if bodies[0] != bodies[1] {
		t.Error("the YAML changed between requests")
	}
	if strings.HasPrefix(bodies[0], "{") {
		t.Fatal("JSON served as YAML")
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(bodies[0]), &root); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	yamlAsJSON(t, &root, &got)
	want, _ := s.openAPIDocument()
	if !bytes.Equal(got.Bytes(), want) {
		g, w := got.String(), string(want)
		i := 0
		for i < len(g) && i < len(w) && g[i] == w[i] {
			i++
		}
		t.Fatalf("the YAML reads back differently from the JSON at byte %d:\n got …%.80s\nwant …%.80s", i, g[i:], w[i:])
	}
}

// A string or key YAML 1.1 reads as something else is quoted: tools on
// 1.1 (PyYAML, SnakeYAML) would take plain off or n as false and 22:00 as
// the number 1320. Numbers, booleans and null stay plain.
func TestJSONToYAMLQuotesWhatYAML11Misreads(t *testing.T) {
	in := `{"mode":"off","at":"22:00","ok":"yes","word":"true","ver":"1.0","day":"2026-10-21","neg":"-x","none":"","nil":null,` +
		`"n":-1.5e3,"big":18446744073709551615,"t":true,"text":"two\nlines\n","200":{"name":"Plain words"}}`
	out, err := jsonToYAML([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	y := string(out)
	for _, want := range []string{`mode: "off"`, `at: "22:00"`, `ok: "yes"`, `word: "true"`, `ver: "1.0"`, `day: "2026-10-21"`, `neg: "-x"`, `none: ""`,
		"nil: null", `"n": -1.5e3`, "big: 18446744073709551615", "t: true", `"200":`, "name: Plain words"} {
		if !strings.Contains(y, "\n"+want) && !strings.HasPrefix(y, want) && !strings.Contains(y, " "+want) {
			t.Errorf("want %s in\n%s", want, y)
		}
	}
	var root yaml.Node
	if err := yaml.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	yamlAsJSON(t, &root, &got)
	if got.String() != in {
		t.Errorf("round trip:\n got %s\nwant %s", got.String(), in)
	}
	if _, err := jsonToYAML([]byte(`{} {}`)); err == nil {
		t.Error("two documents accepted")
	}
}
