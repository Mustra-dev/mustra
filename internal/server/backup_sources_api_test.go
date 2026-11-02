package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/server/backupsrc"
	"github.com/mustra-dev/mustra/internal/store"
)

// A PBS stand-in on loopback, reached only because its host is
// allowlisted and its certificate pinned: connect, read, show it on Backup
// status, keep the secret with its server, and remove it.
func TestBackupSourceLifecycle(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()
	last := time.Now().Add(-2 * time.Hour).Unix()
	pbs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.Header.Get("Authorization"), ":s3cret") {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		data := map[string]string{
			"/api2/json/admin/datastore":                   `[{"store":"backups"}]`,
			"/api2/json/status/datastore-usage":            `[{"store":"backups","used":1,"total":4}]`,
			"/api2/json/admin/datastore/backups/groups":    `[{"backup-type":"host","backup-id":"pihole-test","last-backup":` + jsonNum(last) + `,"backup-count":2}]`,
			"/api2/json/admin/datastore/backups/snapshots": `[{"backup-type":"host","backup-id":"pihole-test","backup-time":` + jsonNum(last) + `,"size":9,"verification":{"state":"failed"}}]`,
		}[r.URL.Path]
		_, _ = io.WriteString(w, `{"data":`+data+`}`)
	}))
	defer pbs.Close()
	sum := sha256.Sum256(pbs.Certificate().Raw)
	fp := hex.EncodeToString(sum[:])

	if err := st.SetSetting(ctx, settingWebhookAllowedHosts, "127.0.0.1", "t"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.SetSetting(context.Background(), settingWebhookAllowedHosts, "", "t") })

	body := `{"kind":"pbs","name":"Test PBS","url":"` + pbs.URL + `","token_id":"mustra@pbs!status","secret":"s3cret","fingerprint":"` + fp + `"}`
	w := callSave(s.handleSaveBackupSource, "POST", "/api/backup-sources", "", body)
	if w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var v backupSourceView
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	t.Cleanup(func() { _, _ = st.DeleteBackupSource(context.Background(), v.ID) })
	if v.LastError != "" || v.Items != 1 || !v.SecretSet || strings.Contains(w.Body.String(), "s3cret") {
		t.Fatalf("created %+v (%s): want read at once, one item, secret stored and not shown", v, w.Body.String())
	}

	// On Backup status, rated: the newest backup failed verification.
	systems, err := s.backupSystems(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, sys := range systems {
		if sys.ID == v.ID {
			found = len(sys.Items) == 1 && sys.Items[0].State == "verify_failed" && len(sys.Stores) == 1
		}
	}
	if !found {
		t.Fatalf("systems %+v: want the host item rated verify_failed", systems)
	}

	// The stored secret follows its server.
	moved := `{"name":"Test PBS","url":"https://elsewhere.example:8007","token_id":"mustra@pbs!status","fingerprint":"` + fp + `"}`
	if w := callSave(s.handleSaveBackupSource, "PUT", "/x", v.ID, moved); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "secret") {
		t.Errorf("moving without the secret: %d %s, want 400", w.Code, w.Body.String())
	}
	renamed := `{"name":"Renamed","url":"` + pbs.URL + `","token_id":"mustra@pbs!status","fingerprint":"` + strings.ToUpper(fp) + `"}`
	if w := callSave(s.handleSaveBackupSource, "PUT", "/x", v.ID, renamed); w.Code != http.StatusOK {
		t.Errorf("renaming keeps the secret: %d %s", w.Code, w.Body.String())
	}

	// A wrong pin is refused at the TLS handshake.
	src, _ := st.GetBackupSource(ctx, v.ID)
	src.Fingerprint = strings.Repeat("ab", 32)
	if _, err := st.SaveBackupSource(ctx, *src); err != nil {
		t.Fatal(err)
	}
	s.pollBackupSource(ctx, *src)
	if got, _ := st.GetBackupSource(ctx, v.ID); got == nil || !strings.Contains(got.LastError, "fingerprint") {
		t.Errorf("wrong pin: %+v, want a fingerprint error", got)
	}

	// Not allowlisted: an internal address is refused.
	_ = st.SetSetting(ctx, settingWebhookAllowedHosts, "", "t")
	src.Fingerprint = fp
	s.pollBackupSource(ctx, *src)
	if got, _ := st.GetBackupSource(ctx, v.ID); got == nil || !strings.Contains(got.LastError, "internal address") {
		t.Errorf("without the allowlist: %+v, want refused as internal", got)
	}

	if w := callSave(s.handleDeleteBackupSource, "DELETE", "/x", v.ID, ""); w.Code != http.StatusOK {
		t.Errorf("delete: %d", w.Code)
	}
	if w := callSave(s.handleDeleteBackupSource, "DELETE", "/x", v.ID, ""); w.Code != http.StatusNotFound {
		t.Errorf("delete again: %d, want 404", w.Code)
	}
}

func TestBackupSourceRefusals(t *testing.T) {
	s, _ := saveRouteServer(t)
	for _, c := range []struct{ body, want string }{
		{`{"kind":"veeam","name":"x","url":"https://x.example","token_id":"t","secret":"s"}`, "kind"},
		{`{"kind":"pbs","name":"x","url":"http://x.example:8007","token_id":"t","secret":"s"}`, "https"},
		{`{"kind":"pbs","name":"x","url":"https://x.example:8007/api2","token_id":"t","secret":"s"}`, "https"},
		{`{"kind":"pbs","name":"x","url":"https://x.example:8007","token_id":"t"}`, "secret"},
		{`{"kind":"pbs","name":"x","url":"https://x.example:8007","token_id":"t","secret":"s","fingerprint":"zz"}`, "fingerprint"},
	} {
		w := callSave(s.handleSaveBackupSource, "POST", "/api/backup-sources", "", c.body)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: %d %q, want 400 mentioning %s", c.body, w.Code, w.Body.String(), c.want)
		}
	}
}

func jsonNum(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// A PBS group is put to the Proxmox guest with its ID and type; one whose
// guest is gone, or whose ID a guest of the other type now has, is a
// leftover: shown as orphaned, never overdue.
func TestBackupSystemGroupsMatchGuestsByIDAndType(t *testing.T) {
	s, st := saveRouteServer(t)
	ctx := context.Background()
	src, err := st.SaveBackupSource(ctx, store.BackupSource{ID: newID("bks-"), Kind: "pbs", Name: "orphan test", URL: "https://pbs.example:8007", TokenID: "t", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = st.DeleteBackupSource(context.Background(), src.ID) })
	old := time.Now().Add(-200 * time.Hour).UTC()
	recent := time.Now().Add(-2 * time.Hour).UTC()
	res, _ := json.Marshal(backupsrc.Result{Items: []backupsrc.Item{
		{Key: "b:vm/103", Type: "vm", Name: "103", VMID: 103, LastBackup: &recent, Protected: true},
		{Key: "b:ct/103", Type: "ct", Name: "103", VMID: 103, LastBackup: &old, Protected: true},
		{Key: "b:ct/118", Type: "ct", Name: "118", VMID: 118, LastBackup: &old, Protected: true},
	}})
	if err := st.RecordBackupSourcePoll(ctx, src.ID, res, ""); err != nil {
		t.Fatal(err)
	}
	guests := []backupStatus{{BackupGuest: proto.BackupGuest{VMID: 103, Name: "ca01", Type: "qemu"}}}
	systems, err := s.backupSystems(ctx, guests)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]backupItemState{}
	for _, sys := range systems {
		if sys.ID == src.ID {
			for _, it := range sys.Items {
				got[it.Key] = it
			}
		}
	}
	if it := got["b:vm/103"]; !it.InProxmox || it.GuestName != "ca01" {
		t.Errorf("vm/103: %+v, want put to the VM ca01", it)
	}
	for _, k := range []string{"b:ct/103", "b:ct/118"} {
		if it := got[k]; it.InProxmox || it.State != "orphaned" {
			t.Errorf("%s: %+v, want orphaned (no such guest of that type)", k, it)
		}
	}
}
