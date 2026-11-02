package backupsrc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A stand-in PBS answering as the real one did (PBS 4, one datastore).
func TestFetchPBS(t *testing.T) {
	future := time.Now().Add(90 * 24 * time.Hour).Unix()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "PBSAPIToken=mustra@pbs!status:s3cret" {
			http.Error(w, "authentication failure", http.StatusUnauthorized)
			return
		}
		data := map[string]string{
			"/api2/json/admin/datastore":        `[{"store":"backups"}]`,
			"/api2/json/status/datastore-usage": `[{"store":"backups","used":300,"total":600,"estimated-full-date":` + jsonInt(future) + `}]`,
			"/api2/json/admin/datastore/backups/groups": `[
				{"backup-type":"vm","backup-id":"120","last-backup":1792722842,"backup-count":3},
				{"backup-type":"host","backup-id":"pihole2","last-backup":1792748277,"backup-count":4},
				{"backup-type":"vm","backup-id":"117","last-backup":0,"backup-count":0}]`,
			"/api2/json/admin/datastore/backups/snapshots": `[
				{"backup-type":"vm","backup-id":"120","backup-time":1792636442,"size":10,"verification":{"state":"failed"}},
				{"backup-type":"vm","backup-id":"120","backup-time":1792722842,"size":20,"verification":{"state":"ok"}},
				{"backup-type":"host","backup-id":"pihole2","backup-time":1792748277,"size":5}]`,
			// Shapes from a PBS 4.2 server; the verify job is mid-run.
			"/api2/json/admin/verify": `[{"id":"v-3d1e","last-run-upid":"UPID:pbs:verificationjob:backups:root@pam:","next-run":1793170800,"schedule":"daily","store":"backups"},
				{"id":"v-other","last-run-state":"verification failed - please check the log for details","last-run-endtime":1793000000,"store":"backups"}]`,
			"/api2/json/admin/prune": `[{"id":"default-backups","keep-daily":3,"last-run-endtime":1793084400,"last-run-state":"OK","next-run":1793170800,"schedule":"daily","store":"backups"}]`,
			"/api2/json/admin/gc":    `[{"last-run-endtime":1793022187,"last-run-state":"OK","next-run":1793107800,"pending-bytes":57117379737,"removed-bytes":37288565911,"schedule":"06:30","store":"backups","upid":"UPID:pbs:garbage_collection:backups:root@pam:"}]`,
		}[r.URL.Path]
		if data == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"data":`+data+`}`)
	}))
	defer srv.Close()

	r, err := Fetch(context.Background(), srv.Client(), Config{Kind: "pbs", URL: srv.URL + "/", TokenID: "mustra@pbs!status", Secret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Stores) != 1 || r.Stores[0].UsedBytes != 300 || r.Stores[0].FullAt == nil {
		t.Errorf("stores %+v", r.Stores)
	}
	by := map[string]Item{}
	for _, it := range r.Items {
		by[it.Key] = it
	}
	if vm := by["backups:vm/120"]; vm.VMID != 120 || vm.Count != 3 || vm.Verified != "ok" || vm.SizeBytes != 20 || vm.LastBackup == nil {
		t.Errorf("vm 120 %+v: want the newest snapshot's size and verification", vm)
	}
	if h := by["backups:host/pihole2"]; h.Type != "host" || h.Name != "pihole2" || h.Verified != "none" {
		t.Errorf("host group %+v", h)
	}
	if e := by["backups:vm/117"]; e.LastBackup != nil || e.Count != 0 {
		t.Errorf("empty group %+v: last-backup 0 is no backup", e)
	}

	jobs := map[string]Job{}
	for _, j := range r.Jobs {
		jobs[j.Kind+"/"+j.ID] = j
	}
	if len(r.Jobs) != 4 {
		t.Errorf("jobs %+v: want verify×2, prune, gc (sync is not listed)", r.Jobs)
	}
	if v := jobs["verify/v-3d1e"]; v.State != "running" || v.Failed() || v.NextRun == nil {
		t.Errorf("running verify %+v", v)
	}
	if v := jobs["verify/v-other"]; !v.Failed() || v.LastEnd == nil {
		t.Errorf("failed verify %+v", v)
	}
	if g := jobs["gc/backups"]; g.State != "OK" || g.Failed() || !strings.Contains(g.Detail, "freed 34.7 GiB") {
		t.Errorf("gc %+v", g)
	}
	if p := jobs["prune/default-backups"]; p.State != "OK" || p.LastEnd == nil || p.Schedule != "daily" {
		t.Errorf("prune %+v", p)
	}

	if _, err := Fetch(context.Background(), srv.Client(), Config{Kind: "pbs", URL: srv.URL, TokenID: "x", Secret: "wrong"}); err == nil || !strings.Contains(err.Error(), "DatastoreAudit") {
		t.Errorf("bad token: %v, want a hint about the token's rights", err)
	}
	if _, err := Fetch(context.Background(), srv.Client(), Config{Kind: "pbs", URL: srv.URL, TokenID: "mustra@pbs!status", Secret: "s3cret", Datastore: "nope"}); err == nil {
		t.Error("an unknown datastore should be an error")
	}
}

// A stand-in Rubrik Security Cloud: client-credentials sign-in, then two
// pages of snappableConnection.
func TestFetchRubrik(t *testing.T) {
	var pages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/client_token":
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" || r.Form.Get("client_id") != "client|abc" || r.Form.Get("client_secret") != "s3cret" {
				http.Error(w, `{"message":"invalid client"}`, http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"client_id":"client|abc","access_token":"tok-1","expires_in":43200}`)
		case "/api/graphql":
			if r.Header.Get("Authorization") != "Bearer tok-1" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var q struct {
				Variables map[string]any `json:"variables"`
			}
			_ = json.NewDecoder(r.Body).Decode(&q)
			pages++
			if q.Variables["after"] == nil {
				_, _ = io.WriteString(w, `{"data":{"snappableConnection":{"edges":[
					{"node":{"id":"o-1","name":"FIN-SQL-01","objectType":"WindowsFileset","protectionStatus":"Protected","complianceStatus":"IN_COMPLIANCE","lastSnapshot":"2026-10-23T02:00:00.000Z","slaDomain":{"name":"Gold"}}}],
					"pageInfo":{"hasNextPage":true,"endCursor":"c1"}}}}`)
				return
			}
			_, _ = io.WriteString(w, `{"data":{"snappableConnection":{"edges":[
				{"node":{"id":"o-2","name":"lab-vm","objectType":"VmwareVirtualMachine","protectionStatus":"NoSla","complianceStatus":"NOT_AVAILABLE","lastSnapshot":null,"slaDomain":null}}],
				"pageInfo":{"hasNextPage":false,"endCursor":""}}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	r, err := Fetch(context.Background(), srv.Client(), Config{Kind: "rubrik", URL: srv.URL, TokenID: "client|abc", Secret: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}
	if pages != 2 || len(r.Items) != 2 {
		t.Fatalf("pages %d items %+v, want both pages read", pages, r.Items)
	}
	sql, lab := r.Items[0], r.Items[1]
	if !sql.Protected || sql.LastBackup == nil || sql.Compliance != "IN_COMPLIANCE" || sql.Type != "WindowsFileset" {
		t.Errorf("protected object %+v", sql)
	}
	if lab.Protected || lab.LastBackup != nil {
		t.Errorf("unprotected object %+v", lab)
	}
	if _, err := Fetch(context.Background(), srv.Client(), Config{Kind: "rubrik", URL: srv.URL, TokenID: "client|abc", Secret: "wrong"}); err == nil || !strings.Contains(err.Error(), "sign-in") {
		t.Errorf("bad secret: %v", err)
	}
}

func TestRubrikProtectedWordings(t *testing.T) {
	for in, want := range map[string]bool{"Protected": true, "PROTECTED": true, "NoSla": false, "DoNotProtect": false, "UNPROTECTED": false, "UNKNOWN": false} {
		if got := rubrikProtected(in, true); got != want {
			t.Errorf("%s: %v, want %v", in, got, want)
		}
	}
	if !rubrikProtected("", true) || rubrikProtected("", false) {
		t.Error("no status: an SLA domain decides")
	}
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
