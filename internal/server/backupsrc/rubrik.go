package backupsrc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Rubrik Security Cloud: a service account (client ID and secret, a role
// with view rights is enough) trades its credentials for a bearer token at
// POST /api/client_token (form-encoded, grant_type=client_credentials),
// then pages through GraphQL at POST /api/graphql:
//
//   snappableConnection(first, after) { edges { node {
//     id name objectType protectionStatus complianceStatus lastSnapshot
//     slaDomain { name } location } } pageInfo { hasNextPage endCursor } }
//
// The enum values differ between Rubrik's own documents (IN_COMPLIANCE vs
// COMPLIANT, Protected vs PROTECTED), so they are kept as Rubrik words
// them and compared case-insensitively. Not exercised against a real
// account: written from Rubrik's API documentation and tested against a
// stand-in server.

const rubrikPageSize = 500

const rubrikQuery = `query MustraBackupStatus($first: Int, $after: String) {
  snappableConnection(first: $first, after: $after) {
    edges { node { id name objectType protectionStatus complianceStatus lastSnapshot location slaDomain { name } } }
    pageInfo { hasNextPage endCursor }
  }
}`

func fetchRubrik(ctx context.Context, client *http.Client, cfg Config) (Result, error) {
	base := strings.TrimRight(cfg.URL, "/")
	token, err := rubrikToken(ctx, client, base, cfg)
	if err != nil {
		return Result{}, err
	}
	var r Result
	after := ""
	for page := 0; page < 200; page++ {
		vars := map[string]any{"first": rubrikPageSize}
		if after != "" {
			vars["after"] = after
		}
		body, _ := json.Marshal(map[string]any{"query": rubrikQuery, "variables": vars})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/graphql", bytes.NewReader(body))
		if err != nil {
			return Result{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		var out struct {
			Data struct {
				Conn struct {
					Edges []struct {
						Node struct {
							ID               string  `json:"id"`
							Name             string  `json:"name"`
							ObjectType       string  `json:"objectType"`
							ProtectionStatus string  `json:"protectionStatus"`
							ComplianceStatus string  `json:"complianceStatus"`
							LastSnapshot     *string `json:"lastSnapshot"`
							Location         string  `json:"location"`
							SLADomain        *struct {
								Name string `json:"name"`
							} `json:"slaDomain"`
						} `json:"node"`
					} `json:"edges"`
					PageInfo struct {
						HasNextPage bool   `json:"hasNextPage"`
						EndCursor   string `json:"endCursor"`
					} `json:"pageInfo"`
				} `json:"snappableConnection"`
			} `json:"data"`
			Errors []struct {
				Message string `json:"message"`
			} `json:"errors"`
		}
		if err := doJSON(client, req, &out); err != nil {
			return Result{}, fmt.Errorf("graphql: %w", err)
		}
		if len(out.Errors) > 0 {
			return Result{}, fmt.Errorf("graphql: %s", out.Errors[0].Message)
		}
		for _, e := range out.Data.Conn.Edges {
			n := e.Node
			it := Item{Key: n.ID, Type: n.ObjectType, Name: n.Name, Compliance: n.ComplianceStatus, Location: n.Location,
				Protected: rubrikProtected(n.ProtectionStatus, n.SLADomain != nil && n.SLADomain.Name != "")}
			if n.LastSnapshot != nil && *n.LastSnapshot != "" {
				if t, err := time.Parse(time.RFC3339, *n.LastSnapshot); err == nil {
					t = t.UTC()
					it.LastBackup = &t
				}
			}
			r.Items = append(r.Items, it)
		}
		if !out.Data.Conn.PageInfo.HasNextPage || out.Data.Conn.PageInfo.EndCursor == "" {
			return r, nil
		}
		after = out.Data.Conn.PageInfo.EndCursor
	}
	return Result{}, fmt.Errorf("graphql: more than %d objects", 200*rubrikPageSize)
}

// rubrikProtected reads protectionStatus as Rubrik words it (Protected,
// PROTECTED, NoSla, DoNotProtect, UNPROTECTED…); with no status, an
// assigned SLA domain means protected.
func rubrikProtected(status string, hasSLA bool) bool {
	switch strings.ToLower(strings.ReplaceAll(status, "_", "")) {
	case "protected":
		return true
	case "":
		return hasSLA
	}
	return false
}

func rubrikToken(ctx context.Context, client *http.Client, base string, cfg Config) (string, error) {
	form := url.Values{"client_id": {cfg.TokenID}, "client_secret": {cfg.Secret}, "grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/client_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := doJSON(client, req, &out); err != nil {
		return "", fmt.Errorf("service account sign-in: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("service account sign-in: no access token in the answer")
	}
	return out.AccessToken, nil
}

func doJSON(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("%s %s", resp.Status, msg)
	}
	return json.Unmarshal(body, out)
}
