package server

import (
	"bufio"
	"bytes"
	"html"
	"io/fs"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	mustra "github.com/mustra-dev/mustra"
	"github.com/mustra-dev/mustra/internal/server/auth"
)

// Help: the step-by-step guides in docs/guides, embedded in the binary so
// the console always explains the build that is running, and readable on
// the repository host as ordinary Markdown.
//
// Each guide starts with a "# Title" line, then an HTML comment carrying
// its place in the index:
//
//	<!-- group: Manage endpoints; order: 20; pages: /agents, /groups -->
//
// "pages" names the console paths the guide explains; the page header's
// help link opens it from there.

// helpGuide is one guide in the index.
type helpGuide struct {
	// Slug is the file name without .md; GET /api/help/{slug} returns it.
	Slug    string `json:"slug"`
	Title   string `json:"title"`
	Summary string `json:"summary"`
	Group   string `json:"group"`
	Order   int    `json:"order"`
	// Pages are the console paths this guide explains.
	Pages []string `json:"pages,omitempty"`
}

// helpIndexResponse lists every guide, grouped and ordered for reading.
type helpIndexResponse struct {
	Guides []helpGuide `json:"guides"`
}

// helpGuideResponse is one guide, rendered.
type helpGuideResponse struct {
	helpGuide
	// HTML is the guide rendered from its Markdown; every piece of text in
	// it was escaped, and only a fixed set of tags was added.
	HTML string `json:"html"`
}

type helpLibrary struct {
	index  []helpGuide
	bySlug map[string]helpGuideResponse
}

var (
	helpOnce sync.Once
	helpLib  helpLibrary
)

func loadHelp() helpLibrary {
	helpOnce.Do(func() { helpLib = buildHelp(mustra.Guides, "docs/guides") })
	return helpLib
}

var helpMetaRe = regexp.MustCompile(`^<!--\s*(.*?)\s*-->$`)

func buildHelp(fsys fs.FS, dir string) helpLibrary {
	lib := helpLibrary{bySlug: map[string]helpGuideResponse{}}
	entries, _ := fs.ReadDir(fsys, dir)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".md") || name == "README.md" {
			continue
		}
		data, err := fs.ReadFile(fsys, dir+"/"+name)
		if err != nil {
			continue
		}
		g, body := parseGuide(strings.TrimSuffix(name, ".md"), string(data))
		lib.index = append(lib.index, g)
		lib.bySlug[g.Slug] = helpGuideResponse{helpGuide: g, HTML: renderGuideMarkdown(body)}
	}
	sort.SliceStable(lib.index, func(i, j int) bool {
		if lib.index[i].Order != lib.index[j].Order {
			return lib.index[i].Order < lib.index[j].Order
		}
		return lib.index[i].Title < lib.index[j].Title
	})
	return lib
}

// parseGuide takes the title, the index comment and the first paragraph
// (the summary) off the top of a guide and returns the rest as its body.
func parseGuide(slug, src string) (helpGuide, string) {
	g := helpGuide{Slug: slug, Title: slug, Group: "Guides", Order: 1000}
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	i := 0
	skipBlank := func() {
		for i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
	}
	skipBlank()
	if i < len(lines) && strings.HasPrefix(lines[i], "# ") {
		g.Title = strings.TrimSpace(lines[i][2:])
		i++
	}
	skipBlank()
	if i < len(lines) {
		if m := helpMetaRe.FindStringSubmatch(strings.TrimSpace(lines[i])); m != nil {
			for _, part := range strings.Split(m[1], ";") {
				k, v, ok := strings.Cut(part, ":")
				if !ok {
					continue
				}
				v = strings.TrimSpace(v)
				switch strings.TrimSpace(k) {
				case "group":
					g.Group = v
				case "order":
					if n, err := strconv.Atoi(v); err == nil {
						g.Order = n
					}
				case "pages":
					for _, p := range strings.Split(v, ",") {
						if p = strings.TrimSpace(p); p != "" {
							g.Pages = append(g.Pages, p)
						}
					}
				}
			}
			i++
		}
	}
	skipBlank()
	// The first paragraph is the summary: the index shows it, and the page
	// shows it as the guide's lede, so the body starts after it.
	var summary []string
	for ; i < len(lines) && strings.TrimSpace(lines[i]) != ""; i++ {
		if strings.HasPrefix(lines[i], "#") || strings.HasPrefix(lines[i], "-") || strings.HasPrefix(lines[i], ">") {
			break
		}
		summary = append(summary, strings.TrimSpace(lines[i]))
	}
	g.Summary = stripInlineMarkdown(strings.Join(summary, " "))
	return g, strings.Join(lines[i:], "\n")
}

var (
	mdLinkRe   = regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)\)`)
	mdCodeRe   = regexp.MustCompile("`([^`]+)`")
	mdBoldRe   = regexp.MustCompile(`\*\*([^*]+)\*\*`)
	mdItalicRe = regexp.MustCompile(`(^|[\s(])_([^_]+)_([\s).,;:!?]|$)`)
	mdOLRe     = regexp.MustCompile(`^(\d+)\.\s+(.*)$`)
)

func stripInlineMarkdown(s string) string {
	s = mdLinkRe.ReplaceAllString(s, "$1")
	s = mdCodeRe.ReplaceAllString(s, "$1")
	s = mdBoldRe.ReplaceAllString(s, "$1")
	return mdItalicRe.ReplaceAllString(s, "$1$2$3")
}

// renderInline escapes a line, then adds code, bold, italic and links. A
// link keeps its target only when it is a console path, a fragment, another
// guide (name.md) or an https URL; anything else is left as text.
func renderInline(s string) string {
	// Code spans first, set aside so their contents are not formatted.
	var codes []string
	s = mdCodeRe.ReplaceAllStringFunc(s, func(m string) string {
		codes = append(codes, "<code>"+html.EscapeString(m[1:len(m)-1])+"</code>")
		return "\x00" + strconv.Itoa(len(codes)-1) + "\x00"
	})
	var links []string
	s = mdLinkRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := mdLinkRe.FindStringSubmatch(m)
		text, target := sub[1], sub[2]
		href, ok := guideLinkTarget(target)
		if !ok {
			return text
		}
		attrs := ""
		if strings.HasPrefix(href, "https://") {
			attrs = ` target="_blank" rel="noopener noreferrer"`
		}
		links = append(links, `<a href="`+html.EscapeString(href)+`"`+attrs+`>`+html.EscapeString(text)+`</a>`)
		return "\x01" + strconv.Itoa(len(links)-1) + "\x01"
	})
	s = html.EscapeString(s)
	s = mdBoldRe.ReplaceAllString(s, "<strong>$1</strong>")
	s = mdItalicRe.ReplaceAllString(s, "$1<em>$2</em>$3")
	s = regexp.MustCompile("\x01(\\d+)\x01").ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.Atoi(m[1 : len(m)-1])
		return links[n]
	})
	return regexp.MustCompile("\x00(\\d+)\x00").ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.Atoi(m[1 : len(m)-1])
		return codes[n]
	})
}

func guideLinkTarget(t string) (string, bool) {
	switch {
	case strings.HasPrefix(t, "https://"):
		return t, true
	case strings.HasPrefix(t, "#"):
		return t, true
	case strings.HasSuffix(t, ".md") && !strings.Contains(t, "/"):
		return "/help#" + strings.TrimSuffix(t, ".md"), true
	case strings.HasPrefix(t, "/") && !strings.HasPrefix(t, "//"):
		return t, true
	}
	return "", false
}

var headingID = regexp.MustCompile(`[^a-z0-9]+`)

// renderGuideMarkdown renders the subset of Markdown the guides use:
// headings (## to ####), paragraphs, ordered and unordered lists (one
// level, with indented continuation lines), fenced code, block quotes as
// callouts, and pipe tables.
func renderGuideMarkdown(src string) string {
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(src))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	var para []string
	flushPara := func() {
		if len(para) > 0 {
			b.WriteString("<p>" + renderInline(strings.Join(para, " ")) + "</p>\n")
			para = nil
		}
	}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		t := strings.TrimSpace(line)
		switch {
		case t == "":
			flushPara()
		case strings.HasPrefix(t, "```"):
			flushPara()
			var code []string
			for i++; i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```"); i++ {
				code = append(code, lines[i])
			}
			b.WriteString("<pre><code>" + html.EscapeString(strings.Join(code, "\n")) + "</code></pre>\n")
		case strings.HasPrefix(t, "<!--"):
			for !strings.Contains(lines[i], "-->") && i+1 < len(lines) {
				i++
			}
		case strings.HasPrefix(t, "#"):
			flushPara()
			level := len(t) - len(strings.TrimLeft(t, "#"))
			if level < 2 {
				level = 2
			}
			if level > 4 {
				level = 4
			}
			text := strings.TrimSpace(strings.TrimLeft(t, "#"))
			id := strings.Trim(headingID.ReplaceAllString(strings.ToLower(stripInlineMarkdown(text)), "-"), "-")
			tag := "h" + strconv.Itoa(level)
			b.WriteString("<" + tag + ` id="` + id + `">` + renderInline(text) + "</" + tag + ">\n")
		case strings.HasPrefix(t, ">"):
			flushPara()
			var q []string
			for ; i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), ">"); i++ {
				q = append(q, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[i]), ">")))
			}
			i--
			b.WriteString(`<div class="callout">` + renderInline(strings.Join(q, " ")) + "</div>\n")
		case strings.HasPrefix(t, "|"):
			flushPara()
			var rows [][]string
			for ; i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "|"); i++ {
				cells := strings.Split(strings.Trim(strings.TrimSpace(lines[i]), "|"), "|")
				for k := range cells {
					cells[k] = strings.TrimSpace(cells[k])
				}
				rows = append(rows, cells)
			}
			i--
			b.WriteString(`<div class="table-wrap"><table>`)
			for r, cells := range rows {
				if r == 1 && strings.Trim(strings.Join(cells, ""), "-: ") == "" {
					continue
				}
				tag := "td"
				if r == 0 {
					tag = "th"
				}
				b.WriteString("<tr>")
				for _, c := range cells {
					b.WriteString("<" + tag + ">" + renderInline(c) + "</" + tag + ">")
				}
				b.WriteString("</tr>")
			}
			b.WriteString("</table></div>\n")
		case strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* ") || mdOLRe.MatchString(t):
			flushPara()
			ordered := mdOLRe.MatchString(t)
			tag := "ul"
			if ordered {
				tag = "ol"
			}
			b.WriteString("<" + tag + ">\n")
			var item []string
			flushItem := func() {
				if item != nil {
					b.WriteString("<li>" + renderInline(strings.Join(item, " ")) + "</li>\n")
					item = nil
				}
			}
			for ; i < len(lines); i++ {
				l := lines[i]
				lt := strings.TrimSpace(l)
				if lt == "" {
					// A blank line ends the list unless the next line is
					// another item of the same kind.
					if i+1 < len(lines) {
						nt := strings.TrimSpace(lines[i+1])
						if (ordered && mdOLRe.MatchString(nt)) || (!ordered && (strings.HasPrefix(nt, "- ") || strings.HasPrefix(nt, "* "))) {
							continue
						}
					}
					break
				}
				if ordered && mdOLRe.MatchString(lt) {
					flushItem()
					item = []string{mdOLRe.FindStringSubmatch(lt)[2]}
				} else if !ordered && (strings.HasPrefix(lt, "- ") || strings.HasPrefix(lt, "* ")) {
					flushItem()
					item = []string{lt[2:]}
				} else if strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") {
					item = append(item, lt)
				} else {
					break
				}
			}
			flushItem()
			i--
			b.WriteString("</" + tag + ">\n")
		default:
			para = append(para, t)
		}
	}
	flushPara()
	return b.String()
}

func (s *Server) handleHelpIndex(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, helpIndexResponse{Guides: loadHelp().index})
}

func (s *Server) handleHelpGuide(w http.ResponseWriter, r *http.Request) {
	g, ok := loadHelp().bySlug[r.PathValue("slug")]
	if !ok {
		http.Error(w, "no such guide", http.StatusNotFound)
		return
	}
	writeJSONResponse(w, g)
}

// helpPageHandler serves Help: the guides, with the index on the left.
func helpPageHandler() http.Handler {
	return staticPageHandler("static/help.html")
}

// requirePermsPage serves a console page only to an account holding one of
// perms. Anyone else gets a page that says which permission it needs and
// how to ask for it, rather than a page whose every panel fails.
func (s *Server) requirePermsPage(perms []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := auth.CurrentUser(r.Context())
		for _, p := range perms {
			ok, err := s.auth.HasPermission(r.Context(), u, p)
			if err != nil {
				http.Error(w, "permission check failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			if ok {
				next.ServeHTTP(w, r)
				return
			}
		}
		data, err := staticFS.ReadFile("static/noaccess.html")
		if err != nil {
			http.Error(w, "forbidden: this page requires one of \""+strings.Join(perms, "\", \"")+"\"", http.StatusForbidden)
			return
		}
		data = bytes.Replace(data, []byte(`data-missing=""`), []byte(`data-missing="`+html.EscapeString(strings.Join(perms, " "))+`"`), 1)
		writeConsolePageStatus(w, data, http.StatusForbidden)
	})
}
