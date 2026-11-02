package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// A query OSV pages is followed to the end, and only that query is sent
// again; chunks are split at batchChunkSize.
func TestQueryBatchFollowsPagesAndChunks(t *testing.T) {
	var requests []int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req querybatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, len(req.Queries))
		var resp querybatchResponse
		resp.Results = make([]struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
			NextPageToken string `json:"next_page_token"`
		}, len(req.Queries))
		for i, q := range req.Queries {
			switch {
			case q.Package.Name == "linux" && q.PageToken == "":
				resp.Results[i].Vulns = append(resp.Results[i].Vulns, struct {
					ID string `json:"id"`
				}{"CVE-1"})
				resp.Results[i].NextPageToken = "p2"
			case q.Package.Name == "linux" && q.PageToken == "p2":
				resp.Results[i].Vulns = append(resp.Results[i].Vulns, struct {
					ID string `json:"id"`
				}{"CVE-2"})
			case q.Package.Name == "openssl":
				resp.Results[i].Vulns = append(resp.Results[i].Vulns, struct {
					ID string `json:"id"`
				}{"CVE-3"})
			}
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	old := baseURL
	baseURL = srv.URL
	defer func() { baseURL = old }()

	qs := make([]PackageQuery, batchChunkSize+2)
	for i := range qs {
		qs[i] = PackageQuery{Ecosystem: "Debian", Name: "pkg", Version: "1"}
	}
	qs[0].Name = "linux"
	qs[batchChunkSize+1].Name = "openssl"
	got, err := QueryBatch(context.Background(), qs)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got[0], []string{"CVE-1", "CVE-2"}) {
		t.Errorf("paged query: %v", got[0])
	}
	if !reflect.DeepEqual(got[batchChunkSize+1], []string{"CVE-3"}) {
		t.Errorf("second chunk: %v", got[batchChunkSize+1])
	}
	if got[1] == nil || len(got[1]) != 0 {
		t.Errorf("a query with no results should be empty, not nil: %v", got[1])
	}
	// First chunk, its second page (only linux), then the second chunk.
	if want := []int{batchChunkSize, 1, 2}; !reflect.DeepEqual(requests, want) {
		t.Errorf("requests %v, want %v", requests, want)
	}
}

// An UBUNTU-CVE record's "Ubuntu" severity is Ubuntu's priority; CVSS
// still sets Severity.
func TestGetDetailsUbuntuPriority(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"id":"UBUNTU-CVE-2026-1","severity":[
			{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			{"type":"Ubuntu","score":"Medium"}]}`))
	}))
	defer srv.Close()
	old := baseURL
	baseURL = srv.URL
	defer func() { baseURL = old }()

	d, err := GetDetails(context.Background(), "UBUNTU-CVE-2026-1")
	if err != nil {
		t.Fatal(err)
	}
	if d.UbuntuPriority != "medium" || d.Severity != "critical" {
		t.Errorf("UbuntuPriority %q, Severity %q; want medium, critical", d.UbuntuPriority, d.Severity)
	}
}
