package server

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func TestEveryDefaultTemplateRendersAgainstItsSample(t *testing.T) {
	for _, k := range emailKinds {
		out, err := renderEmail(k.Default, "", sampleEmailData(k.Kind))
		if err != nil {
			t.Errorf("%s: %v", k.Kind, err)
			continue
		}
		if out.Subject == "" || strings.TrimSpace(out.Text) == "" {
			t.Errorf("%s rendered empty: %+v", k.Kind, out)
		}
		if strings.Contains(out.Subject+out.Text+out.HTML, emailNoValue) {
			t.Errorf("%s shows %s", k.Kind, emailNoValue)
		}
	}
}

func TestEventDefaultCarriesTheWholeBodyAndTheLink(t *testing.T) {
	long := strings.Repeat("- CVE line\n", 300) // past eventText's chat limit
	data := eventEmailData(integrationEvent{}, "title", long, "https://m.example.com/risk")
	out, err := renderEmail(emailEventBodyDefault, "", data)
	if err != nil {
		t.Fatal(err)
	}
	if out.Subject != "[mustra] title" || !strings.Contains(out.Text, long) || !strings.Contains(out.Text, "Open in mustra: https://m.example.com/risk") {
		t.Errorf("%+v", out.Subject)
	}
}

func TestEmailTemplateVariablesMacrosAndFunctions(t *testing.T) {
	macros := `{{define "signature"}}The {{.Vars.company}} team{{end}}`
	data := map[string]any{
		"Vars": map[string]string{"company": "Example"}, "Severity": "critical", "Title": "x",
		"Time":   time.Date(2026, 11, 4, 8, 0, 0, 0, time.UTC),
		"Detail": map[string]any{"cves": []any{"CVE-1", "CVE-2"}, "items": []any{map[string]any{"id": "CVE-1", "epss": 0.42}}, "n": float64(1)},
	}
	out, err := renderEmail(store.EmailTemplate{
		Subject: `{{upper .Severity}}: {{.Vars.company}}`,
		Text:    `{{join ", " .Detail.cves}} {{date "2 Jan" .Time}} {{range .Detail.items}}{{.id}} {{percent .epss}}{{end}} {{plural .Detail.n "host" "hosts"}} {{default "none" .Target}} {{if gt (int .Detail.n) 0}}yes{{end}} {{template "signature" .}}`,
	}, macros, data)
	if err != nil {
		t.Fatal(err)
	}
	if out.Subject != "CRITICAL: Example" {
		t.Errorf("subject %q", out.Subject)
	}
	if want := "CVE-1, CVE-2 4 Nov CVE-1 42% host none yes The Example team"; out.Text != want {
		t.Errorf("text\n got %q\nwant %q", out.Text, want)
	}
}

func TestEmailHTMLEscapesFleetDataButNotAReport(t *testing.T) {
	data := map[string]any{"Title": `<script>alert(1)</script>`, "Report": map[string]any{"Name": "<b>n</b>"}}
	out, err := renderEmail(store.EmailTemplate{Subject: "s", Text: "t", HTML: `<p>{{.Title}}</p><p>{{.Report.Name}}</p>`}, "", data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.HTML, "<script>") || strings.Contains(out.HTML, "<b>n") {
		t.Errorf("not escaped: %s", out.HTML)
	}
	rep := reportEmailData(store.Report{Name: "<b>n</b>"}, renderedReport{HTML: "<section>ok</section>"})
	out, err = renderEmail(store.EmailTemplate{Subject: "s", Text: "t", HTML: `<div>{{.Report.Content}}</div><i>{{.Report.Name}}</i>`}, "", rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.HTML, "<section>ok</section>") || strings.Contains(out.HTML, "<b>n") {
		t.Errorf("report content: %s", out.HTML)
	}
}

func TestEmailSubjectCannotBreakOutOfItsHeader(t *testing.T) {
	out, err := renderEmail(store.EmailTemplate{Subject: "{{.Title}}", Text: "t"}, "", map[string]any{"Title": "a\r\nBcc: x@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.Subject, "\r\n") {
		t.Errorf("subject %q", out.Subject)
	}
}

func TestEmailMissingValuesPrintAsNothing(t *testing.T) {
	out, err := renderEmail(store.EmailTemplate{Subject: "a{{.Nope}}b", Text: "c{{.Detail.nope}}d", HTML: "<p>{{.Nope}}</p>"}, "",
		map[string]any{"Detail": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Subject != "ab" || out.Text != "cd" || strings.Contains(out.HTML, "no value") {
		t.Errorf("%+v", out)
	}
}

func TestEmailTemplatesRefuseRunawaysAndAbuse(t *testing.T) {
	for name, c := range map[string]struct{ macros, text string }{
		"self":        {`{{define "a"}}{{template "a" .}}{{template "a" .}}{{end}}`, `{{template "a" .}}`},
		"mutual":      {`{{define "a"}}{{template "b" .}}{{end}}{{define "b"}}{{if .X}}{{template "a" .}}{{end}}{{end}}`, `{{template "a" .}}`},
		"in a range":  {`{{define "a"}}{{range .L}}{{template "a" $}}{{end}}{{end}}`, `{{template "a" .}}`},
		"bad syntax":  {"", `{{if}}`},
		"no function": {"", `{{exec "id"}}`},
		"no macro":    {"", `{{template "missing" .}}`},
		"too big":     {`{{define "x"}}` + strings.Repeat("y", 1<<16) + `{{end}}`, `{{range .L}}{{range $.L}}{{range $.L}}{{template "x"}}{{end}}{{end}}{{end}}`},
	} {
		list := make([]any, 40)
		_, err := renderEmail(store.EmailTemplate{Subject: "s", Text: c.text}, c.macros, map[string]any{"L": list})
		if err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestEmailOverIsFieldByField(t *testing.T) {
	got := emailOver(emailOver(store.EmailTemplate{Subject: "own"}, store.EmailTemplate{Text: "global"}),
		store.EmailTemplate{Subject: "d", Text: "d", HTML: "d"})
	if got.Subject != "own" || got.Text != "global" || got.HTML != "d" {
		t.Errorf("%+v", got)
	}
}

func TestCompletedEventsAreChosenByAction(t *testing.T) {
	ev := integrationEvent{Type: "completed", Action: "backup"}
	if !completedWanted("", ev) || !completedWanted("deployment,backup", ev) || completedWanted("deployment", ev) {
		t.Error("completedWanted")
	}
	if got, err := parseCompletedFilter("backup, playbook"); err != nil || got != "backup,playbook" {
		t.Errorf("%q %v", got, err)
	}
	if _, err := parseCompletedFilter("backup,nope"); err == nil {
		t.Error("unknown action accepted")
	}
	for _, c := range []struct {
		ok, bad           int
		outcome, severity string
	}{{3, 0, "succeeded", "info"}, {2, 1, "partial", "warning"}, {0, 2, "failed", "warning"}, {0, 0, "succeeded", "info"}} {
		if o, sv := completedOutcome(c.ok, c.bad); o != c.outcome || sv != c.severity {
			t.Errorf("%+v: %s %s", c, o, sv)
		}
	}
	// Failures must get past a floor of warning, and successes must not.
	if severityRank["info"] >= severityRank["warning"] {
		t.Error("the floor no longer separates success from failure")
	}
}

// Against a real database: a failing custom template still sends, each level
// overrides the one below, and a run is announced once, when it is over.
func TestEmailTemplatesAndRunCompletionAgainstTheStore(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	s := &Server{store: st, logger: slog.Default()}

	t.Cleanup(func() { _ = st.SetSetting(ctx, settingEmailTemplatePrefix+"alert", "", "test") })
	if err := st.SetSetting(ctx, settingEmailTemplatePrefix+"alert", `{"subject":"global {{.Title}}","text":"{{.Body}} from global"}`, "test"); err != nil {
		t.Fatal(err)
	}
	data := eventEmailData(integrationEvent{}, "t", "b", "")
	m := s.composeMail(ctx, "alert", []string{"a@example.com"}, store.EmailTemplate{Subject: "own {{.Title}}"}, data)
	if m.Subject != "own t" || m.Text != "b from global" {
		t.Errorf("levels: %+v", m)
	}
	// A template that fails only with real data, as validation could not see.
	bad := store.EmailTemplate{Text: `{{index .Detail.nope 3}}`}
	m = s.composeMail(ctx, "alert", []string{"a@example.com"}, bad, data)
	if !strings.Contains(m.Text, "could not be used") || !strings.Contains(m.Text, "b") || m.Subject != "[mustra] t" {
		t.Errorf("fallback: %+v", m)
	}

	rep := store.Report{ID: idgen.New("rep-"), Name: "r", UpdatedBy: "test", EmailTemplate: store.EmailTemplate{Subject: "s {{.Report.Name}}"}}
	if err := st.UpsertReport(ctx, rep, nil); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetReport(ctx, rep.ID)
	if err != nil || got == nil || got.EmailTemplate.Subject != rep.EmailTemplate.Subject {
		t.Fatalf("report round trip: %+v %v", got, err)
	}

	// A patch run of two endpoints.
	runID, a1, a2 := idgen.New("run-"), idgen.New("agt-"), idgen.New("agt-")
	for _, a := range []string{a1, a2} {
		if err := st.UpsertOnRegister(ctx, a, proto.AgentInfo{Hostname: a, OS: "linux", Arch: "amd64", Version: "1.0.0"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.RecordPatchJobRun(ctx, store.PatchJobRun{ID: runID, ScheduleName: "Weekly", TargetDesc: "all", AgentCount: 2, TriggeredBy: "test"}); err != nil {
		t.Fatal(err)
	}
	drain := func() []integrationEvent {
		var out []integrationEvent
		for {
			select {
			case ev := <-s.integrations().queue:
				out = append(out, ev)
			default:
				return out
			}
		}
	}
	s.announceRunCompleted(ctx, runID)
	if evs := drain(); len(evs) != 0 {
		t.Fatalf("announced with no actions yet: %+v", evs)
	}
	act1, act2 := idgen.New("act-"), idgen.New("act-")
	if err := st.StartAgentAction(ctx, store.AgentAction{ID: act1, AgentID: a1, RunID: runID, Kind: "patch_apply", Summary: "t", RequestedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishAgentAction(ctx, a1, act1, "succeeded", "ok"); err != nil {
		t.Fatal(err)
	}
	s.announceRunCompleted(ctx, runID)
	if evs := drain(); len(evs) != 0 {
		t.Fatalf("announced with one endpoint not recorded yet: %+v", evs)
	}
	if err := st.StartAgentAction(ctx, store.AgentAction{ID: act2, AgentID: a2, RunID: runID, Kind: "patch_apply", Summary: "t", RequestedBy: "test"}); err != nil {
		t.Fatal(err)
	}
	s.announceRunCompleted(ctx, runID)
	if evs := drain(); len(evs) != 0 {
		t.Fatalf("announced with one still running: %+v", evs)
	}
	if err := st.FinishAgentAction(ctx, a2, act2, "failed", "no"); err != nil {
		t.Fatal(err)
	}
	s.announceRunCompleted(ctx, runID)
	evs := drain()
	if len(evs) != 1 || evs[0].Type != "completed" || evs[0].Outcome != "partial" || evs[0].Severity != "warning" {
		t.Fatalf("completion: %+v", evs)
	}
	s.announceRunCompleted(ctx, runID)
	if evs := drain(); len(evs) != 0 {
		t.Fatalf("announced twice: %+v", evs)
	}
}

func TestComplianceCompletionFailsOnlyOnSilence(t *testing.T) {
	_, outcome, severity, body := complianceCompletion("CIS", 3, 3, 40)
	if outcome != "succeeded" || severity != "info" || !strings.Contains(body, "40 checks failing") {
		t.Errorf("failing checks are not a failed scan: %s %s %q", outcome, severity, body)
	}
	if _, outcome, severity, _ := complianceCompletion("CIS", 3, 2, 0); outcome != "partial" || severity != "warning" {
		t.Errorf("one silent: %s %s", outcome, severity)
	}
	if _, outcome, _, _ := complianceCompletion("CIS", 3, 0, 0); outcome != "failed" {
		t.Errorf("all silent: %s", outcome)
	}
}

func TestEnforceCompletionTreatsDriftAsNormal(t *testing.T) {
	if _, outcome, _, _ := enforceCompletion(enforceRunSummary{Policy: "p", Endpoints: 2, Drifted: 2}); outcome != "succeeded" {
		t.Errorf("drift: %s", outcome)
	}
	if _, outcome, severity, _ := enforceCompletion(enforceRunSummary{Policy: "p", Endpoints: 2, Compliant: 1, Failed: 1}); outcome != "partial" || severity != "warning" {
		t.Errorf("a failure: %s %s", outcome, severity)
	}
	if _, outcome, _, _ := enforceCompletion(enforceRunSummary{Policy: "p", Endpoints: 2, Unreached: 2}); outcome != "failed" {
		t.Errorf("unreached: %s", outcome)
	}
}

// Runs end on paths no result reports. The sweep finds them, once, and leaves
// notices and surveys alone, though they share the table.
func TestCompletionSweepAgainstTheStore(t *testing.T) {
	dsn := os.Getenv("MUSTRA_TEST_DEPLOY_DSN")
	if dsn == "" {
		t.Skip("set MUSTRA_TEST_DEPLOY_DSN to a disposable Postgres database")
	}
	ctx := context.Background()
	st, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	s := &Server{store: st, logger: slog.Default()}
	drain := func(name string) int {
		n := 0
		for {
			select {
			case ev := <-s.integrations().queue:
				if ev.Target == name {
					n++
				}
			default:
				return n
			}
		}
	}
	agent := idgen.New("agt-")
	if err := st.UpsertOnRegister(ctx, agent, proto.AgentInfo{Hostname: agent, OS: "linux", Arch: "amd64", Version: "1.0.0"}); err != nil {
		t.Fatal(err)
	}
	run := func(name, kind string) (string, string) {
		id, act := idgen.New("run-"), idgen.New("act-")
		if err := st.RecordPatchJobRun(ctx, store.PatchJobRun{ID: id, ScheduleName: name, TargetDesc: name, AgentCount: 1, TriggeredBy: "test"}); err != nil {
			t.Fatal(err)
		}
		if err := st.StartAgentAction(ctx, store.AgentAction{ID: act, AgentID: agent, RunID: id, Kind: kind, Summary: "t", RequestedBy: "test"}); err != nil {
			t.Fatal(err)
		}
		return id, act
	}
	patch := "patch-" + agent
	_, act := run(patch, "patch_apply")
	notice := "notice-" + agent
	_, noticeAct := run(notice, "notify_user")

	s.sweepRunCompletions(ctx)
	if n := drain(patch); n != 0 {
		t.Fatalf("announced while running: %d", n)
	}
	// Ends with nothing telling the server's result handling, as a held job
	// expiring does.
	if err := st.FinishAgentAction(ctx, agent, act, "expired", "the window never opened"); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishAgentAction(ctx, agent, noticeAct, "succeeded", ""); err != nil {
		t.Fatal(err)
	}
	s.sweepRunCompletions(ctx)
	evs := 0
	for done := false; !done; {
		select {
		case ev := <-s.integrations().queue:
			if ev.Target == notice {
				t.Errorf("a notice was announced: %+v", ev)
			}
			if ev.Target == patch {
				evs++
				if ev.Outcome != "failed" || ev.Severity != "warning" {
					t.Errorf("an expired job: %+v", ev)
				}
			}
		default:
			done = true
		}
	}
	if evs != 1 {
		t.Fatalf("announcements: %d", evs)
	}
	s.sweepRunCompletions(ctx)
	if n := drain(patch); n != 0 {
		t.Fatalf("announced twice: %d", n)
	}
}
