package server

import (
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	mustra "github.com/mustra-dev/mustra"
)

// The renderer escapes everything a guide says and adds only its own tags,
// so a guide cannot put markup or script into the console.
func TestGuideMarkdownEscapes(t *testing.T) {
	out := renderGuideMarkdown("## Title <b>x</b>\n\nText <script>alert(1)</script> and **bold** and `<code>`.\n\n" +
		"- [ok](/agents)\n- [bad](javascript:alert(1))\n- [proto](//evil.example)\n- [guide](deploy-software.md)\n- [ext](https://example.com/x)\n")
	for _, bad := range []string{"<script>", "<b>x</b>", "javascript:", "//evil.example", "<code><code>"} {
		if strings.Contains(out, bad) {
			t.Errorf("rendered output contains %q:\n%s", bad, out)
		}
	}
	for _, want := range []string{"&lt;script&gt;", "<strong>bold</strong>", "<code>&lt;code&gt;</code>", `href="/agents"`, `href="/help#deploy-software"`, `href="https://example.com/x" target="_blank" rel="noopener noreferrer"`} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output lacks %q:\n%s", want, out)
		}
	}
}

func TestGuideSummaryIsNotRepeated(t *testing.T) {
	lib := buildHelp(fstest.MapFS{
		"g/a.md": {Data: []byte("# A guide\n<!-- group: Start; order: 3; pages: /x, /y -->\n\nThe summary line.\n\n## Steps\n\n1. One\n")},
	}, "g")
	if len(lib.index) != 1 {
		t.Fatalf("index: %+v", lib.index)
	}
	g := lib.bySlug["a"]
	if g.Title != "A guide" || g.Group != "Start" || g.Order != 3 || len(g.Pages) != 2 || g.Summary != "The summary line." {
		t.Errorf("parsed %+v", g.helpGuide)
	}
	if strings.Contains(g.HTML, "The summary line.") {
		t.Errorf("the summary is repeated in the body: %s", g.HTML)
	}
}

// Every shipped guide carries its index line and a summary, and links only
// to guides that exist.
func TestShippedGuides(t *testing.T) {
	lib := buildHelp(mustra.Guides, "docs/guides")
	if len(lib.index) < 25 {
		t.Fatalf("only %d guides", len(lib.index))
	}
	link := regexp.MustCompile(`href="/help#([^"]+)"`)
	for _, g := range lib.index {
		if g.Group == "Guides" || g.Order == 1000 {
			t.Errorf("%s: no index comment", g.Slug)
		}
		if g.Summary == "" {
			t.Errorf("%s: no summary paragraph", g.Slug)
		}
		for _, m := range link.FindAllStringSubmatch(lib.bySlug[g.Slug].HTML, -1) {
			if _, ok := lib.bySlug[m[1]]; !ok {
				t.Errorf("%s links to a guide that does not exist: %s", g.Slug, m[1])
			}
		}
	}
}
