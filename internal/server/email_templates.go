package server

// Email templates. Every email mustra sends can be rewritten: subject, text
// and HTML, with variables and macros. Three levels, most specific first, and
// each field stands alone, so an integration can change only a subject:
//
//	a report's or integration's own template
//	Administration → Email's template for that kind of email
//	the built-in default
//
// Templates are Go templates. Subject and text use text/template; HTML uses
// html/template, so a hostile hostname or CVE summary is escaped and cannot
// add markup to an administrator's inbox. Macros are {{define}} blocks shared
// by every template. Variables are the administrator's own values.
//
// Editing one needs settings.manage, but a template still must not be able to
// stop a security alert. Templates see plain data and a short list of pure
// functions. A template calling itself is refused when saved, because
// fan-out through recursion would otherwise run for longer than the universe.
// Output and time are bounded. A template that fails anyway costs its wording,
// not the email: the default goes out, saying what happened.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"text/template/parse"
	"time"

	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
	"github.com/mustra-dev/mustra/internal/version"
)

const (
	settingEmailTemplatePrefix = "email.template."
	settingEmailShared         = "email.shared"

	emailTemplateMaxBytes = 256 << 10
	emailRenderTimeout    = 5 * time.Second
	emailNoValue          = "<no value>"

	// The keys of an integration's Config holding its own template.
	configEmailSubject = "subject_template"
	configEmailText    = "text_template"
	configEmailHTML    = "html_template"
)

// emailShared is what every template can use.
type emailShared struct {
	// Vars are your own values, used as {{.Vars.name}}.
	Vars map[string]string `json:"vars"`
	// Macros are {{define "name"}}…{{end}} blocks, used as {{template "name" .}}.
	Macros string `json:"macros"`
}

var emailVarName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

var emailEventBodyDefault = store.EmailTemplate{
	Subject: `[mustra] {{.Title}}`,
	Text:    "{{.Body}}{{if .Link}}\n\nOpen in mustra: {{.Link}}{{end}}\n",
}

// emailKind is one kind of email and what its templates can use.
type emailKind struct {
	Kind        string              `json:"kind"`
	Label       string              `json:"label"`
	Description string              `json:"description"`
	Default     store.EmailTemplate `json:"default"`
	Variables   []emailVariable     `json:"variables"`
}

type emailVariable struct {
	Name string `json:"name"`
	Desc string `json:"desc"`
}

var emailCommonVars = []emailVariable{
	{".Server.URL", "This server's public address"},
	{".Server.Version", "This server's version"},
	{".Vars.name", "One of your variables"},
	{".Now", "When the email was built; format it with date"},
}

var emailEventVars = append([]emailVariable{
	{".Title", "The one-line summary"},
	{".Body", "The details, as plain text"},
	{".Severity", "info, notice, warning, error or critical"},
	{".Link", "Where to look in the console"},
	{".Time", "When it happened; format it with date"},
	{".Detail", "What this event adds; each kind's are listed below"},
}, emailCommonVars...)

func emailKindVars(extra ...emailVariable) []emailVariable {
	return append(extra, emailEventVars...)
}

var emailKinds = []emailKind{
	{Kind: "vulnerability", Label: "New vulnerabilities", Description: "New findings after a scan, one email per severity level, and actively exploited ones from threat briefings.",
		Default: emailEventBodyDefault, Variables: emailKindVars(
			emailVariable{".Detail.kind", "new_findings or actively_exploited"},
			emailVariable{".Detail.vulnerabilities", "How many vulnerabilities (new_findings)"},
			emailVariable{".Detail.endpoints", "How many endpoints (new_findings)"},
			emailVariable{".Detail.kev", "How many are in CISA's KEV catalogue (new_findings)"},
			emailVariable{".Detail.items", "The list: each has .id .package .hosts .kev .ransomware .epss .fixed (new_findings)"},
			emailVariable{".Detail.cves", "The CVEs (actively_exploited)"},
		)},
	{Kind: "completed", Label: "Completed actions", Description: "An action you opted in to has finished: a deployment, playbook, backup, certificate renewal, scan or report.",
		Default: emailEventBodyDefault, Variables: emailKindVars(
			emailVariable{".Outcome", "succeeded, partial or failed"},
			emailVariable{".Action", "deployment, playbook, backup, certificate, vuln_scan or report"},
			emailVariable{".Target", "What it acted on"},
			emailVariable{".Detail", "Depends on the action. Deployments and playbooks have .succeeded .failed .total"},
		)},
	{Kind: "expiry", Label: "Expiry", Description: "A certificate or credential crossed an expiry threshold.",
		Default: emailEventBodyDefault, Variables: emailKindVars(
			emailVariable{".Detail.name", "What expires"},
			emailVariable{".Detail.where", "Where it lives"},
			emailVariable{".Detail.days_left", "Days left"},
			emailVariable{".Detail.expires_at", "When it expires"},
		)},
	{Kind: "alert", Label: "Alerts", Description: "Anything raised as a console notification.",
		Default: emailEventBodyDefault, Variables: emailKindVars(
			emailVariable{".Detail.source", "Which part of mustra raised it"},
			emailVariable{".Actions", "Buttons for a decision: each has .Label and .Link"},
		)},
	{Kind: "audit", Label: "Audit events", Description: "An entry in the audit log.",
		Default: emailEventBodyDefault, Variables: emailKindVars(
			emailVariable{".Action", "What was done, such as patches.deploy"},
			emailVariable{".Actor", "Who did it"},
			emailVariable{".Target", "What it was done to"},
			emailVariable{".Outcome", "How it went"},
		)},
	{Kind: "report", Label: "Reports", Description: "A report sent by email.",
		Default: store.EmailTemplate{
			Subject: `[mustra] {{.Report.Name}}`,
			Text:    "{{.Report.Summary}}",
			HTML:    "{{.Report.Document}}",
		}, Variables: append([]emailVariable{
			{".Report.Name", "The report's name"},
			{".Report.Description", "The line under its title"},
			{".Report.Summary", "The text digest"},
			{".Report.Content", "The report's sections as HTML, to place inside your own layout"},
			{".Report.Document", "The whole report as one HTML page, with its styles"},
			{".Report.Rows", "How many rows it holds"},
			{".Report.Generated", "When it was built; format it with date"},
		}, emailCommonVars...)},
	{Kind: "test", Label: "Test email", Description: "What Send test email sends.",
		Default: store.EmailTemplate{
			Subject: `[mustra] Test email`,
			Text:    "If you can read this, mustra can send email.\n",
		}, Variables: emailCommonVars},
}

func emailKindByName(name string) *emailKind {
	for i := range emailKinds {
		if emailKinds[i].Kind == name {
			return &emailKinds[i]
		}
	}
	return nil
}

// emailFunction is a function templates can call.
type emailFunction struct {
	Name    string `json:"name"`
	Example string `json:"example"`
	Desc    string `json:"desc"`
}

var emailFunctionDocs = []emailFunction{
	{"upper", `{{upper .Severity}}`, "Capitals"},
	{"lower", `{{lower .Title}}`, "Lower case"},
	{"trim", `{{trim .Body}}`, "Remove space from both ends"},
	{"truncate", `{{truncate 80 .Title}}`, "At most this many characters"},
	{"default", `{{default "none" .Target}}`, "This value when the other is empty"},
	{"join", `{{join ", " .Detail.cves}}`, "A list as one string"},
	{"replace", `{{replace "old" "new" .Title}}`, "Replace text"},
	{"contains", `{{if contains .Title "failed"}}…{{end}}`, "Whether text holds other text"},
	{"date", `{{date "2 Jan 2006 15:04" .Time}}`, "Format a time, in UTC, using this exact reference date"},
	{"percent", `{{percent .epss}}`, "0.42 as 42%"},
	{"plural", `{{plural .Detail.endpoints "endpoint" "endpoints"}}`, "The word that fits a count"},
	{"int", `{{if gt (int .Detail.kev) 0}}…{{end}}`, "A count as a whole number, for comparing with eq, lt or gt"},
}

func emailToString(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func emailToFloat(v any) float64 {
	switch t := v.(type) {
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case float64:
		return t
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	}
	return 0
}

func emailToTime(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t
	case string:
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02"} {
			if parsed, err := time.Parse(layout, t); err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}

// emailFuncs is every function a template gets. All are pure and take only
// what they are given: nothing here reads a setting, a file or the network.
var emailFuncs = map[string]any{
	"upper":    func(v any) string { return strings.ToUpper(emailToString(v)) },
	"lower":    func(v any) string { return strings.ToLower(emailToString(v)) },
	"trim":     func(v any) string { return strings.TrimSpace(emailToString(v)) },
	"truncate": func(n int, v any) string { return safeTruncate(emailToString(v), n) },
	"default": func(d, v any) any {
		if s := emailToString(v); s == "" || s == emailNoValue || s == "0" || s == "false" {
			return d
		}
		return v
	},
	"join": func(sep string, v any) string {
		switch t := v.(type) {
		case []string:
			return strings.Join(t, sep)
		case []any:
			parts := make([]string, len(t))
			for i, x := range t {
				parts[i] = emailToString(x)
			}
			return strings.Join(parts, sep)
		}
		return emailToString(v)
	},
	"replace": func(from, to string, v any) string { return strings.ReplaceAll(emailToString(v), from, to) },
	"contains": func(v any, needle string) bool {
		return strings.Contains(emailToString(v), needle)
	},
	"date": func(layout string, v any) string {
		t := emailToTime(v)
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format(layout)
	},
	"percent": func(v any) string { return fmt.Sprintf("%.0f%%", emailToFloat(v)*100) },
	"plural": func(n any, one, many string) string {
		if emailToFloat(n) == 1 {
			return one
		}
		return many
	},
	"int": func(v any) int { return int(emailToFloat(v)) },
}

// emailOver fills t's empty fields from base.
func emailOver(t, base store.EmailTemplate) store.EmailTemplate {
	if strings.TrimSpace(t.Subject) == "" {
		t.Subject = base.Subject
	}
	if strings.TrimSpace(t.Text) == "" {
		t.Text = base.Text
	}
	if strings.TrimSpace(t.HTML) == "" {
		t.HTML = base.HTML
	}
	return t
}

// checkEmailCycles refuses a template that can reach itself. Go's depth limit
// stops plain recursion, but not one that calls itself twice and fans out.
func checkEmailCycles(t *template.Template) error {
	calls := map[string][]string{}
	for _, tmpl := range t.Templates() {
		if tmpl.Tree != nil {
			calls[tmpl.Name()] = emailTemplateCalls(tmpl.Root, nil)
		}
	}
	const (
		visiting = 1
		done     = 2
	)
	state := map[string]int{}
	var visit func(string) error
	visit = func(name string) error {
		switch state[name] {
		case visiting:
			return fmt.Errorf("%q ends up calling itself", name)
		case done:
			return nil
		}
		state[name] = visiting
		for _, next := range calls[name] {
			if err := visit(next); err != nil {
				return err
			}
		}
		state[name] = done
		return nil
	}
	names := make([]string, 0, len(calls))
	for n := range calls {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := visit(n); err != nil {
			return err
		}
	}
	return nil
}

func emailTemplateCalls(node parse.Node, out []string) []string {
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return out
		}
		for _, c := range n.Nodes {
			out = emailTemplateCalls(c, out)
		}
	case *parse.TemplateNode:
		out = append(out, n.Name)
	case *parse.IfNode:
		out = emailTemplateCalls(n.ElseList, emailTemplateCalls(n.List, out))
	case *parse.RangeNode:
		out = emailTemplateCalls(n.ElseList, emailTemplateCalls(n.List, out))
	case *parse.WithNode:
		out = emailTemplateCalls(n.ElseList, emailTemplateCalls(n.List, out))
	}
	return out
}

type emailLimitWriter struct {
	buf bytes.Buffer
}

func (w *emailLimitWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > mailMaxBytes {
		return 0, errors.New("the email would be too large")
	}
	return w.buf.Write(p)
}

func parseEmailText(part, macros, source string) (*template.Template, error) {
	t := template.New("macros").Funcs(emailFuncs)
	if _, err := t.Parse(macros); err != nil {
		return nil, fmt.Errorf("macros: %w", err)
	}
	if _, err := t.New(part).Parse(source); err != nil {
		return nil, fmt.Errorf("%s: %w", part, err)
	}
	if err := checkEmailCycles(t); err != nil {
		return nil, err
	}
	return t, nil
}

func renderEmailText(part, macros, source string, data map[string]any) (string, error) {
	t, err := parseEmailText(part, macros, source)
	if err != nil {
		return "", err
	}
	var w emailLimitWriter
	if err := t.ExecuteTemplate(&w, part, data); err != nil {
		return "", fmt.Errorf("%s: %w", part, err)
	}
	// A variable a template names and this email lacks prints as nothing.
	return strings.ReplaceAll(w.buf.String(), emailNoValue, ""), nil
}

func renderEmailHTML(macros, source string, data map[string]any) (string, error) {
	if strings.TrimSpace(source) == "" {
		return "", nil
	}
	// The same source through text/template first: its parse trees are what
	// the cycle check reads, and html/template's are rewritten for escaping.
	if _, err := parseEmailText("html", macros, source); err != nil {
		return "", err
	}
	t := htmltemplate.New("macros").Funcs(emailFuncs)
	if _, err := t.Parse(macros); err != nil {
		return "", fmt.Errorf("macros: %w", err)
	}
	if _, err := t.New("html").Parse(source); err != nil {
		return "", fmt.Errorf("html: %w", err)
	}
	var w emailLimitWriter
	if err := t.ExecuteTemplate(&w, "html", data); err != nil {
		return "", fmt.Errorf("html: %w", err)
	}
	return strings.ReplaceAll(w.buf.String(), emailNoValue, ""), nil
}

type renderedEmail struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

// renderEmail renders all three parts within the time limit. A template that
// outlasts it is left to finish in the background: nothing it could reach
// matters, and the email must not wait.
func renderEmail(t store.EmailTemplate, macros string, data map[string]any) (renderedEmail, error) {
	type result struct {
		out renderedEmail
		err error
	}
	done := make(chan result, 1)
	go func() {
		var r result
		if r.out.Subject, r.err = renderEmailText("subject", macros, t.Subject, data); r.err != nil {
			done <- r
			return
		}
		if r.out.Text, r.err = renderEmailText("text", macros, t.Text, data); r.err != nil {
			done <- r
			return
		}
		r.out.HTML, r.err = renderEmailHTML(macros, t.HTML, data)
		done <- r
	}()
	select {
	case r := <-done:
		r.out.Subject = strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(r.out.Subject))
		return r.out, r.err
	case <-time.After(emailRenderTimeout):
		return renderedEmail{}, errors.New("the template took too long")
	}
}

func (s *Server) loadEmailShared(ctx context.Context) emailShared {
	var shared emailShared
	if raw, err := s.store.GetSetting(ctx, settingEmailShared); err == nil && raw != "" {
		if err := json.Unmarshal([]byte(raw), &shared); err != nil {
			s.logger.Warn("email macros and variables are unreadable", "error", err)
		}
	}
	return shared
}

func (s *Server) loadEmailTemplate(ctx context.Context, kind string) store.EmailTemplate {
	var t store.EmailTemplate
	if raw, err := s.store.GetSetting(ctx, settingEmailTemplatePrefix+kind); err == nil && raw != "" {
		if err := json.Unmarshal([]byte(raw), &t); err != nil {
			s.logger.Warn("an email template is unreadable", "kind", kind, "error", err)
		}
	}
	return t
}

// emailData is what every template sees, plus what this email adds. Vars are
// never nil, so {{.Vars.x}} is empty rather than a failure.
func (s *Server) emailData(ctx context.Context, shared emailShared, extra map[string]any) map[string]any {
	vars := shared.Vars
	if vars == nil {
		vars = map[string]string{}
	}
	base, _ := s.agentPublicURLOrEmpty(ctx)
	data := map[string]any{
		"Server": map[string]any{"URL": base, "Version": version.Current().Version},
		"Vars":   vars,
		"Now":    time.Now().UTC(),
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

// composeMail renders one email. It always answers with something to send: a
// failing custom template falls back to the default, and says so.
func (s *Server) composeMail(ctx context.Context, kind string, to []string, own store.EmailTemplate, extra map[string]any) mailMessage {
	k := emailKindByName(kind)
	if k == nil {
		k = emailKindByName("alert")
	}
	shared := s.loadEmailShared(ctx)
	chosen := emailOver(emailOver(own, s.loadEmailTemplate(ctx, k.Kind)), k.Default)
	data := s.emailData(ctx, shared, extra)
	out, err := renderEmail(chosen, shared.Macros, data)
	if err != nil {
		s.logger.Warn("a custom email template failed; sending the default", "kind", k.Kind, "error", err)
		note := "A custom email template could not be used, so this is mustra's default wording. Its error: " + err.Error() + "\n\n"
		out, err = renderEmail(k.Default, "", data)
		if err != nil { // the defaults are tested, so this is a bug here
			out = renderedEmail{Subject: "[mustra] " + k.Label, Text: "This email could not be built: " + err.Error()}
		}
		out.Text = note + out.Text
		out.HTML = ""
	}
	return mailMessage{To: to, Subject: out.Subject, Text: out.Text, HTML: out.HTML}
}

// eventEmailData is an integration event as template data. Detail goes through
// JSON, so a template only ever sees plain values with no methods to call.
func eventEmailData(ev integrationEvent, title, body, link string) map[string]any {
	detail := map[string]any{}
	if raw, err := json.Marshal(ev.Detail); err == nil {
		_ = json.Unmarshal(raw, &detail)
	}
	if detail == nil {
		detail = map[string]any{}
	}
	return map[string]any{
		"Type": ev.Type, "Title": title, "Body": body, "Severity": ev.Severity, "Link": link, "Time": ev.Time,
		"Action": ev.Action, "Actor": ev.Actor, "Target": ev.Target, "AgentID": ev.AgentID, "Outcome": ev.Outcome,
		"Detail": detail, "Actions": ev.Actions,
	}
}

func integrationEmailTemplate(in store.Integration) store.EmailTemplate {
	return store.EmailTemplate{Subject: in.Config[configEmailSubject], Text: in.Config[configEmailText], HTML: in.Config[configEmailHTML]}
}

func reportEmailData(rep store.Report, rendered renderedReport) map[string]any {
	return map[string]any{"Report": map[string]any{
		"Name": rep.Name, "Description": rep.Description, "Summary": rendered.Summary,
		// Built by reports.go, which escapes every value it places.
		"Content":   htmltemplate.HTML(rendered.HTML),
		"Document":  htmltemplate.HTML(reportDocument(rep.Name, rendered.HTML)),
		"Rows":      rendered.Rows,
		"Generated": rendered.Generated,
	}}
}

// sampleEmailData is invented data for checking and previewing a template.
func sampleEmailData(kind string) map[string]any {
	now := time.Now().UTC()
	event := func(ev integrationEvent) map[string]any {
		ev.Time = now
		return eventEmailData(ev, ev.Title, ev.Body, "https://mustra.example.com"+ev.Link)
	}
	switch kind {
	case "vulnerability":
		return event(integrationEvent{Type: "vulnerability", Severity: "critical", Link: "/risk",
			Title: "2 new critical vulnerabilities on 3 endpoints",
			Body:  "- CVE-2026-1001 in openssl on db-01, web-01: actively exploited (CISA KEV), EPSS 94%, fixed in 3.0.14\n- CVE-2026-1002 in curl on web-02: EPSS 12%, fixed in 8.9.0",
			Detail: map[string]any{"kind": "new_findings", "vulnerabilities": 2, "endpoints": 3, "kev": 1,
				"ids": []string{"CVE-2026-1001", "CVE-2026-1002"}, "cves": []string{"CVE-2026-1001", "CVE-2026-1002"},
				"items": []map[string]any{
					{"id": "CVE-2026-1001", "package": "openssl", "hosts": []string{"db-01", "web-01"}, "kev": true, "ransomware": false, "epss": 0.94, "fixed": "3.0.14"},
					{"id": "CVE-2026-1002", "package": "curl", "hosts": []string{"web-02"}, "kev": false, "ransomware": false, "epss": 0.12, "fixed": "8.9.0"},
				}}})
	case "completed":
		return event(integrationEvent{Type: "completed", Action: "deployment", Severity: "info", Outcome: "succeeded", Target: "Weekly patching", Link: "/patches#deployments",
			Title: "Deployment finished: Weekly patching", Body: "12 of 12 succeeded",
			Detail: map[string]any{"action": "deployment", "succeeded": 12, "failed": 0, "total": 12}})
	case "expiry":
		return event(integrationEvent{Type: "expiry", Severity: "warning", Link: "/certificates",
			Title: "Certificate expires in 14 days: web-01", Body: "web-01.example.com on web-01",
			Detail: map[string]any{"name": "web-01.example.com", "where": "web-01", "days_left": 14, "expires_at": now.AddDate(0, 0, 14)}})
	case "audit":
		return event(integrationEvent{Type: "audit", Action: "patches.deploy", Actor: "alice", Target: "Weekly patching", Severity: "notice", Outcome: "ok", Link: "/logs",
			Title: "patches.deploy by alice on Weekly patching", Body: `{"endpoints":12}`, Detail: map[string]any{"endpoints": 12}})
	case "report":
		content := `<section class="rpt-section"><h2>Vulnerabilities</h2><p>12 rows from findings</p></section>`
		return reportEmailData(store.Report{Name: "Weekly fleet health", Description: "For the Monday meeting"},
			renderedReport{Generated: now, HTML: content, Summary: "Weekly fleet health\n\nVulnerabilities: 12 rows", Rows: 12, Sections: 1})
	case "test":
		return map[string]any{}
	}
	return event(integrationEvent{Type: "alert", Severity: "warning", Link: "/patches",
		Title: "Patch run failed on an endpoint", Body: "apt-get exited with status 100 on web-01",
		Detail:  map[string]any{"source": "Patch"},
		Actions: []eventAction{{Label: "Open", Link: "/patches"}}})
}

// validateEmailTemplate parses a template and renders it against sample data.
// What a real email lacks prints as nothing, so this finds mistakes of syntax,
// macros and functions, and what the preview shows finds the rest.
func (s *Server) validateEmailTemplate(ctx context.Context, kind string, t store.EmailTemplate, macros string) error {
	if len(t.Subject)+len(t.Text)+len(t.HTML) > emailTemplateMaxBytes {
		return errors.New("a template can be at most 256 KB")
	}
	k := emailKindByName(kind)
	if k == nil {
		return fmt.Errorf("no such kind of email: %s", kind)
	}
	data := s.emailData(ctx, emailShared{}, sampleEmailData(k.Kind))
	_, err := renderEmail(emailOver(t, k.Default), macros, data)
	return err
}

// validateIntegrationEmail checks an integration's template against the kinds
// of event it takes. One may be written for only some of them, using what only
// those carry; on the others the default goes out, so it is refused only if it
// works for none.
func (s *Server) validateIntegrationEmail(ctx context.Context, in store.Integration) error {
	t := integrationEmailTemplate(in)
	macros := s.loadEmailShared(ctx).Macros
	var first error
	kinds := in.Events
	if len(kinds) == 0 {
		kinds = []string{"alert"}
	}
	for _, kind := range kinds {
		err := s.validateEmailTemplate(ctx, kind, t, macros)
		if err == nil {
			return nil
		}
		if first == nil {
			first = err
		}
	}
	return first
}

// validateEmailShared checks variables and macros, and that every saved
// template still works with them.
func (s *Server) validateEmailShared(ctx context.Context, shared emailShared) error {
	if len(shared.Macros) > emailTemplateMaxBytes {
		return errors.New("macros can be at most 256 KB")
	}
	for name, v := range shared.Vars {
		if !emailVarName.MatchString(name) {
			return fmt.Errorf("%q is not a usable variable name: letters, digits and _, starting with a letter", name)
		}
		if len(v) > 4096 {
			return fmt.Errorf("the value of %s is too long", name)
		}
	}
	for _, k := range emailKinds {
		if err := s.validateEmailTemplate(ctx, k.Kind, s.loadEmailTemplate(ctx, k.Kind), shared.Macros); err != nil {
			return fmt.Errorf("the %s template: %w", k.Label, err)
		}
	}
	return nil
}

// emailKindView is one kind of email as the settings page shows it.
type emailKindView struct {
	emailKind
	Custom store.EmailTemplate `json:"custom"`
}

// emailTemplatesResponse is what GET /api/admin/email-templates and its
// saves answer.
type emailTemplatesResponse struct {
	Kinds     []emailKindView `json:"kinds"`
	Shared    emailShared     `json:"shared"`
	Functions []emailFunction `json:"functions"`
}

func (s *Server) handleGetEmailTemplates(w http.ResponseWriter, r *http.Request) {
	out := emailTemplatesResponse{Shared: s.loadEmailShared(r.Context()), Functions: emailFunctionDocs}
	if out.Shared.Vars == nil {
		out.Shared.Vars = map[string]string{}
	}
	for _, k := range emailKinds {
		out.Kinds = append(out.Kinds, emailKindView{emailKind: k, Custom: s.loadEmailTemplate(r.Context(), k.Kind)})
	}
	writeJSONResponse(w, out)
}

// PUT /api/admin/email-templates/{kind} saves one kind's template. All three
// fields blank puts the default back.
func (s *Server) handleSaveEmailTemplate(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if emailKindByName(kind) == nil {
		http.Error(w, "no such kind of email", http.StatusNotFound)
		return
	}
	var t store.EmailTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if err := s.validateEmailTemplate(ctx, kind, t, s.loadEmailShared(ctx).Macros); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	value := ""
	state := "reset"
	if strings.TrimSpace(t.Subject+t.Text+t.HTML) != "" {
		raw, err := json.Marshal(t)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		value, state = string(raw), "custom"
	}
	who := auth.CurrentUser(ctx).Username
	if err := s.store.SetSetting(ctx, settingEmailTemplatePrefix+kind, value, who); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit(ctx, auditEvent{Action: "settings.email_template", Actor: who, Target: kind, Severity: "notice",
		Detail: map[string]any{"state": state}})
	s.handleGetEmailTemplates(w, r)
}

// PUT /api/admin/email-shared saves the variables and macros.
func (s *Server) handleSaveEmailShared(w http.ResponseWriter, r *http.Request) {
	var shared emailShared
	if err := json.NewDecoder(r.Body).Decode(&shared); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if err := s.validateEmailShared(ctx, shared); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := json.Marshal(shared)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	who := auth.CurrentUser(ctx).Username
	if err := s.store.SetSetting(ctx, settingEmailShared, string(raw), who); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	names := make([]string, 0, len(shared.Vars))
	for n := range shared.Vars {
		names = append(names, n)
	}
	sort.Strings(names)
	s.audit(ctx, auditEvent{Action: "settings.email_shared", Actor: who, Target: "email", Severity: "notice",
		Detail: map[string]any{"variables": names}})
	s.handleGetEmailTemplates(w, r)
}

func (s *Server) renderEmailPreview(ctx context.Context, kind string, t store.EmailTemplate) (renderedEmail, error) {
	k := emailKindByName(kind)
	if k == nil {
		return renderedEmail{}, fmt.Errorf("no such kind of email: %s", kind)
	}
	shared := s.loadEmailShared(ctx)
	return renderEmail(emailOver(t, k.Default), shared.Macros, s.emailData(ctx, shared, sampleEmailData(k.Kind)))
}

// emailPreviewResponse is what POST /api/admin/email-templates/{kind}/preview
// answers. Error is a template's own mistake, for the form to show.
type emailPreviewResponse struct {
	renderedEmail
	Error string `json:"error,omitempty"`
}

// POST /api/admin/email-templates/{kind}/preview renders what is in the form,
// saved or not, against sample data. Nothing is sent.
func (s *Server) handleEmailPreview(w http.ResponseWriter, r *http.Request) {
	var t store.EmailTemplate
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	if emailKindByName(r.PathValue("kind")) == nil {
		http.Error(w, "no such kind of email", http.StatusNotFound)
		return
	}
	out, err := s.renderEmailPreview(r.Context(), r.PathValue("kind"), t)
	resp := emailPreviewResponse{renderedEmail: out}
	if err != nil {
		resp.Error = err.Error()
	}
	writeJSONResponse(w, resp)
}

// POST /email-preview/{kind} is the preview's HTML for the form's iframe. The
// console's policy forbids inline styles, and an email's whole styling is
// inline, so it has its own: scripts and forms stay off, and "sandbox" keeps
// it away from the console.
func (s *Server) handleEmailPreviewPage(w http.ResponseWriter, r *http.Request) {
	t := store.EmailTemplate{Subject: r.FormValue("subject"), Text: r.FormValue("text"), HTML: r.FormValue("html")}
	out, err := s.renderEmailPreview(r.Context(), r.PathValue("kind"), t)
	page := out.HTML
	if err != nil {
		page = "<!doctype html><p>" + htmltemplate.HTMLEscapeString(err.Error()) + "</p>"
	} else if page == "" {
		page = `<!doctype html><pre style="font: 14px/1.5 monospace; white-space: pre-wrap; margin: 16px">` + htmltemplate.HTMLEscapeString(out.Text) + "</pre>"
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'")
	h.Set("X-Frame-Options", "SAMEORIGIN")
	_, _ = w.Write([]byte(page))
}

// emailSendTestRequest is the body of POST /api/admin/email-templates/{kind}/test.
type emailSendTestRequest struct {
	// To is who receives it: addresses separated by commas.
	To string `json:"to"`
	store.EmailTemplate
}

// POST /api/admin/email-templates/{kind}/test sends what is in the form, saved
// or not, with sample data, marked as a test.
func (s *Server) handleEmailTemplateTest(w http.ResponseWriter, r *http.Request) {
	var req emailSendTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	to, err := parseMailRecipients(req.To)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	kind := r.PathValue("kind")
	out, err := s.renderEmailPreview(ctx, kind, req.EmailTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = s.sendMail(ctx, mailMessage{To: to, Subject: "[test] " + out.Subject, Text: out.Text, HTML: out.HTML})
	s.audit(ctx, auditEvent{Action: "settings.mail_test", Actor: auth.CurrentUser(ctx).Username, Target: strings.Join(to, ", "), Severity: "notice",
		Detail: map[string]any{"sent": err == nil, "template": kind}})
	if errors.Is(err, errMailNotConfigured) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	writeJSONResponse(w, mailTestResponse{Result: "sent"})
}
