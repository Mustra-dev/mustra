package agent

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	bnats "github.com/mustra-dev/mustra/internal/nats"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/reveal"
)

// Reveal: a sensitive-data scan on this endpoint.
//
// The rule arrives as a command; the walk happens here; what goes back is
// a report of which files matched which patterns, with masked snippets.
// The file contents never leave the machine, which is the whole design:
// finding out that a spreadsheet of card numbers exists on a workstation
// must not itself copy the card numbers anywhere.
//
// It is budgeted in three ways -- files, time, and matches -- and it
// yields between files, because a scan that pegs a CPU for ten minutes is
// the surest way to get an agent uninstalled.

// Text-like extensions searched when a rule does not say otherwise.
// Documents, data and configuration -- not source code. Code assigns
// variables called password all day long; a rule that wants to search a
// codebase can name the extensions itself.
var revealDefaultExtensions = []string{
	"txt", "csv", "tsv", "log", "json", "xml", "yaml", "yml", "ini", "conf", "cfg", "toml", "env",
	"sql", "eml", "msg", "rtf", "properties", "sh", "ps1", "bat", "pem", "key",
	"docx", "xlsx", "pptx", "odt", "ods",
}

// Directories never entered, by name, on any platform: they are large,
// they are not user data, and several of them are not readable anyway.
// The second line is the developer's machine: language caches, build
// trees and vendored source are documentation and test fixtures by the
// gigabyte, and every one of them explains what a private key looks like.
// The third is Windows profile clutter: browser and app caches under
// AppData\Local, which hold numbers by the million and secrets almost
// never; Roaming is kept.
var revealDefaultExclude = []string{
	"proc", "sys", "dev", "run", "snap", "lost+found", "node_modules", ".git", ".svn", ".cache", "__pycache__",
	"site-packages", "dist-packages", "vendor", "mustra-agent", "saltstack", "pkg", "registry", ".cargo", ".rustup", ".npm", ".gradle", ".m2",
	".claude", ".vscode", "pnpm", "docs", "doc", "website", "tests", "test", "testdata", "fixtures", "examples", "staging", "charts", "source", "build",
	"locales", "locale", "i18n", "l10n", "translations",
	"Local", "LocalLow", "Cache", "Caches", "Code Cache", "Temp", "tmp",
	"Windows", "WinSxS", "$Recycle.Bin", "System Volume Information", "Program Files", "Program Files (x86)", "ProgramData",
	"Library", ".Trash", "Applications", "System", "Volumes", "private",
}

func (a *Agent) runRevealScan(ctx context.Context, job proto.RevealJob) {
	report := proto.RevealReport{ScanID: job.ScanID, RuleID: job.RuleID, AgentID: a.agentID,
		Started: time.Now().UTC().Format(time.RFC3339), Matches: []proto.RevealMatch{}}
	patterns, err := reveal.Compile(job.Patterns)
	if err != nil {
		report.Error = err.Error()
	} else {
		scanReveal(ctx, job, patterns, &report)
	}
	report.Finished = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.Marshal(report)
	if err != nil {
		a.logger.Error("marshal reveal report failed", "error", err)
		return
	}
	snap := proto.SensorSnapshot{AgentID: a.agentID, Sensor: proto.SensorReveal, Timestamp: time.Now().UTC(), Data: raw}
	payload, _ := json.Marshal(snap)
	if err := a.pub.Publish(ctx, bnats.AgentSensor(a.agentID, string(proto.SensorReveal)), payload); err != nil {
		a.logger.Error("publish reveal report failed", "error", err)
	}
	a.logger.Info("reveal scan finished", "rule", job.RuleName, "files_scanned", report.FilesScanned,
		"files_matched", report.FilesMatched, "matches", len(report.Matches), "truncated", report.Truncated, "error", report.Error)
}

const (
	revealMaxMatches   = 5000
	revealReadCap      = 8 << 20 // never read more than this of one file, whatever the rule says
	revealSnippetChars = 24
)

func scanReveal(ctx context.Context, job proto.RevealJob, patterns []reveal.Compiled, report *proto.RevealReport) {
	maxSize := job.MaxSizeBytes
	if maxSize <= 0 || maxSize > revealReadCap {
		maxSize = revealReadCap
	}
	maxFiles := job.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 100000
	}
	budget := time.Duration(job.TimeBudgetSeconds) * time.Second
	if budget <= 0 {
		budget = 10 * time.Minute
	}
	deadline := time.Now().Add(budget)
	minMatches := job.MinMatches
	if minMatches <= 0 {
		minMatches = 1
	}
	exts := map[string]bool{}
	for _, e := range job.Extensions {
		exts[strings.ToLower(strings.TrimPrefix(e, "."))] = true
	}
	if len(exts) == 0 {
		for _, e := range revealDefaultExtensions {
			exts[e] = true
		}
	}
	excludeNames := map[string]bool{}
	var excludePrefixes []string
	for _, x := range append(append([]string{}, revealDefaultExclude...), job.Exclude...) {
		if strings.ContainsAny(x, `/\`) {
			excludePrefixes = append(excludePrefixes, strings.ToLower(filepath.Clean(x)))
		} else {
			excludeNames[strings.ToLower(x)] = true
		}
	}
	var since time.Time
	if job.ModifiedWithinDays > 0 {
		since = time.Now().AddDate(0, 0, -job.ModifiedWithinDays)
	}

	buf := make([]byte, 0, 1<<20)
	for _, root := range job.Roots {
		root = expandRevealRoot(root)
		if root == "" {
			continue
		}
		if _, err := os.Lstat(root); err != nil {
			continue
		}
		stop := false
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if stop {
				return filepath.SkipAll
			}
			if ctx.Err() != nil || time.Now().After(deadline) || report.FilesSeen >= maxFiles || len(report.Matches) >= revealMaxMatches {
				report.Truncated = true
				stop = true
				return filepath.SkipAll
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if path != root {
					if excludeNames[strings.ToLower(d.Name())] {
						return filepath.SkipDir
					}
					lp := strings.ToLower(path)
					for _, p := range excludePrefixes {
						if strings.HasPrefix(lp, p) {
							return filepath.SkipDir
						}
					}
				}
				return nil
			}
			if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
				return nil
			}
			report.FilesSeen++
			if report.FilesSeen%200 == 0 {
				time.Sleep(3 * time.Millisecond) // be a neighbour, not a load
			}
			ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(d.Name()), "."))
			if !exts[ext] {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				report.Skipped++
				return nil
			}
			if info.Size() > maxSize || info.Size() == 0 {
				report.Skipped++
				return nil
			}
			if !since.IsZero() && info.ModTime().Before(since) {
				return nil
			}
			text, ok := revealReadText(path, ext, maxSize, &buf)
			if !ok {
				report.Skipped++
				return nil
			}
			report.FilesScanned++
			matched := false
			// Where each pattern matched, for the proximity check below.
			// Only collected when the rule asks for pairs.
			var hits map[string][][]int
			if len(job.RequirePairs) > 0 {
				hits = map[string][][]int{}
			}
			var found []proto.RevealMatch
			for _, p := range patterns {
				locs := p.Re.FindAllStringIndex(text, -1)
				if hits != nil && len(locs) > 0 {
					hits[p.ID] = locs
				}
				if len(locs) < minMatches {
					continue
				}
				m := proto.RevealMatch{Path: path, Size: info.Size(), Modified: info.ModTime().UTC().Format(time.RFC3339), PatternID: p.ID, Count: len(locs)}
				for _, loc := range locs {
					if p.Valid(text[loc[0]:loc[1]], revealContext(text, loc[0], loc[1])) {
						m.Confirmed++
						if job.Snippets && m.Snippet == "" {
							m.Snippet = reveal.Snippet(text, loc[0], loc[1], revealSnippetChars)
						}
					}
				}
				if m.Confirmed < minMatches && p.Validate != "" {
					continue // matched the shape, failed the check: not a finding
				}
				if job.Snippets && m.Snippet == "" && len(locs) > 0 {
					m.Snippet = reveal.Snippet(text, locs[0][0], locs[0][1], revealSnippetChars)
				}
				found = append(found, m)
				matched = true
			}
			// A rule with pairs reports nothing unless two of its patterns
			// turned up near each other: the shapes on their own were the
			// false positives it exists to suppress.
			if len(job.RequirePairs) > 0 && !reveal.PairsHold(job.RequirePairs, hits) {
				return nil
			}
			if matched {
				report.Matches = append(report.Matches, found...)
				report.FilesMatched++
			}
			return nil
		})
		if stop {
			break
		}
	}
}

// expandRevealRoot lets a rule say ~ for every home directory on Unix and
// %USERPROFILE%'s parent on Windows, which is where the data people care
// about actually lives.
func expandRevealRoot(root string) string {
	switch root {
	case "~", "$HOME", "%USERPROFILE%":
		if home := os.Getenv("HOME"); home != "" && home != "/" && home != "/root" {
			return home
		}
		if os.PathSeparator == '\\' {
			if d := os.Getenv("SystemDrive"); d != "" {
				return d + `\Users`
			}
			return `C:\Users`
		}
		if _, err := os.Stat("/Users"); err == nil {
			return "/Users"
		}
		return "/home"
	}
	return os.ExpandEnv(root)
}

var revealTagRe = regexp.MustCompile(`<[^>]+>`)

// revealReadText returns a file's searchable text. Plain files are read as
// they are, refused if they look binary. Office documents are zip archives
// of XML; their text is the XML with the tags stripped, which is enough for
// a pattern that is looking for a number.
func revealReadText(path, ext string, max int64, buf *[]byte) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	switch ext {
	case "docx", "xlsx", "pptx", "odt", "ods":
		st, err := f.Stat()
		if err != nil {
			return "", false
		}
		zr, err := zip.NewReader(f, st.Size())
		if err != nil {
			return "", false
		}
		var sb strings.Builder
		for _, zf := range zr.File {
			name := strings.ToLower(zf.Name)
			if !strings.HasSuffix(name, ".xml") || strings.Contains(name, "rels") || strings.Contains(name, "theme") {
				continue
			}
			rc, err := zf.Open()
			if err != nil {
				continue
			}
			data, _ := io.ReadAll(io.LimitReader(rc, max))
			rc.Close()
			sb.Write(revealTagRe.ReplaceAll(data, []byte(" ")))
			if int64(sb.Len()) > max {
				break
			}
		}
		return sb.String(), sb.Len() > 0
	}
	*buf = (*buf)[:0]
	n, err := io.ReadFull(f, (*buf)[:cap(*buf)])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", false
	}
	data := (*buf)[:n]
	if int64(n) == int64(cap(*buf)) && max > int64(n) {
		rest, _ := io.ReadAll(io.LimitReader(f, max-int64(n)))
		data = append(append([]byte{}, data...), rest...)
	}
	head := data
	if len(head) > 4096 {
		head = head[:4096]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return "", false // binary
	}
	return string(data), true
}

// revealContext is the text a validator may look at around a match: the
// same window a snippet shows, unmasked, and never leaving the endpoint.
// It stops at the line: "card" on the line above says nothing about the
// number on this one.
func revealContext(text string, start, end int) string {
	from, to := start-48, end+48
	if from < 0 {
		from = 0
	}
	if to > len(text) {
		to = len(text)
	}
	if i := strings.LastIndexByte(text[from:start], '\n'); i >= 0 {
		from += i + 1
	}
	if i := strings.IndexByte(text[end:to], '\n'); i >= 0 {
		to = end + i
	}
	return text[from:to]
}
