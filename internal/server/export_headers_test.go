package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mustra-dev/mustra/internal/store"
)

func TestExportViewNeverAnswersHeaderValues(t *testing.T) {
	s := &Server{}
	cfg := store.ExportConfig{ID: "exp-1", Name: "x", Headers: map[string]string{"Authorization": "Bearer secret-token"}}
	out, _ := json.Marshal(s.exportViewOf(cfg))
	if strings.Contains(string(out), "secret-token") {
		t.Fatalf("header value leaked: %s", out)
	}
	if !strings.Contains(string(out), `"headers_set":true`) || !strings.Contains(string(out), `"header_names":["Authorization"]`) {
		t.Fatalf("names/set missing: %s", out)
	}
	sealed := store.ExportConfig{ID: "exp-2", Name: "y", HeadersSealed: "plain:{\"X-Token\":\"abc\"}"}
	out, _ = json.Marshal(s.exportViewOf(sealed))
	if strings.Contains(string(out), "abc") || !strings.Contains(string(out), `"header_names":["X-Token"]`) {
		t.Fatalf("sealed view wrong: %s", out)
	}
	h, err := s.exportHeaders(sealed)
	if err != nil || h["X-Token"] != "abc" {
		t.Fatalf("open: %v %v", h, err)
	}
	var in exportBody
	if err := json.Unmarshal([]byte(`{"name":"n","headers":{"A":"1"}}`), &in); err != nil || in.Headers == nil || (*in.Headers)["A"] != "1" {
		t.Fatalf("body headers not decoded: %+v %v", in, err)
	}
	var none exportBody
	if err := json.Unmarshal([]byte(`{"name":"n"}`), &none); err != nil || none.Headers != nil {
		t.Fatal(err)
	}
}
