package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// The answer to a create is the exception as stored, so its created_at
// is the one the list shows, not year 1 (#102).
func TestCreateComplianceExceptionAnswersTheStoredTime(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := auth.WithUser(context.Background(), &store.User{Username: "cex-test"})

	title := "Ensure the test check " + idgen.New("") + " passes"
	body, _ := json.Marshal(map[string]any{"title": title, "reason": "regression test for #102"})
	req := httptest.NewRequest("POST", "/api/compliance/exceptions", strings.NewReader(string(body))).WithContext(ctx)
	rec := httptest.NewRecorder()
	s.handleCreateComplianceException(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rec.Code, rec.Body.String())
	}
	var got store.ComplianceException
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = st.DeleteComplianceException(context.Background(), got.ID) })

	list, err := st.ListComplianceExceptions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range list {
		if e.ID == got.ID {
			if got.CreatedAt.IsZero() || !got.CreatedAt.Equal(e.CreatedAt) {
				t.Fatalf("answered created_at %v, stored %v", got.CreatedAt, e.CreatedAt)
			}
			return
		}
	}
	t.Fatalf("exception %s was not stored", got.ID)
}

// Running a report answers with the run as stored: its generated_at is
// the time the run list shows, not year 1 (#100).
func TestRunReportAnswersTheStoredTime(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := auth.WithUser(context.Background(), &store.User{Username: "rpt-test"})

	rep := store.Report{ID: idgen.New("rep-"), Name: "timestamps " + idgen.New(""), ScheduleKind: "manual",
		Sections: json.RawMessage(`[{"id":"s1","title":"Nothing","source":"no-such-source"}]`), UpdatedBy: "rpt-test"}
	if err := st.UpsertReport(context.Background(), rep, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteReport(context.Background(), rep.ID) })

	req := httptest.NewRequest("POST", "/api/reports/"+rep.ID+"/run", nil).WithContext(ctx)
	req.SetPathValue("id", rep.ID)
	rec := httptest.NewRecorder()
	s.handleRunReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("run: %d %s", rec.Code, rec.Body.String())
	}
	var got struct{ Run store.ReportRun }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	stored, err := st.GetReportRun(context.Background(), got.Run.ID)
	if err != nil || stored == nil {
		t.Fatalf("get run %s: %v, %v", got.Run.ID, stored, err)
	}
	if got.Run.GeneratedAt.IsZero() || !got.Run.GeneratedAt.Equal(stored.GeneratedAt) {
		t.Fatalf("answered generated_at %v, stored %v", got.Run.GeneratedAt, stored.GeneratedAt)
	}
	// The stamp in the document is the same moment, to the minute.
	stamp := "Generated " + stored.GeneratedAt.UTC().Format("2 January 2006, 15:04 MST")
	if !strings.Contains(got.Run.HTML, stamp) {
		t.Fatalf("the document does not say %q", stamp)
	}
}

// Until the first rollup the inventory has not been rolled up, and says
// so with null rather than year 1; a refresh rolls it up and says when
// (#116).
func TestSoftwareInventoryRolledUpAtIsNullUntilTheFirstRollup(t *testing.T) {
	s, _ := saveRouteServer(t)
	ctx := auth.WithUser(context.Background(), &store.User{Username: "swinv-test"})

	rolledUpAt := func(rec *httptest.ResponseRecorder) any {
		t.Helper()
		if rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		var got struct{ Summary map[string]any }
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		v, ok := got.Summary["rolled_up_at"]
		if !ok {
			t.Fatal("summary leaves out rolled_up_at")
		}
		return v
	}

	rec := httptest.NewRecorder()
	s.handleSoftwareInventory(rec, httptest.NewRequest("GET", "/api/software-inventory", nil).WithContext(ctx))
	if v := rolledUpAt(rec); v != nil {
		t.Fatalf("before any rollup, rolled_up_at is %v, want null", v)
	}

	before := time.Now()
	rec = httptest.NewRecorder()
	s.handleSoftwareInventoryRefresh(rec, httptest.NewRequest("POST", "/api/software-inventory/refresh", nil).WithContext(ctx))
	v, _ := rolledUpAt(rec).(string)
	at, err := time.Parse(time.RFC3339Nano, v)
	if err != nil || at.Before(before) {
		t.Fatalf("after a refresh, rolled_up_at is %q, want a time after %v", v, before)
	}
}
