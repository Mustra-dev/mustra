package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/proto"
	"github.com/mustra-dev/mustra/internal/store"
)

func mcpCall(t *testing.T, s *Server, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/mcp", strings.NewReader(body))
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	s.handleMCP(rec, req)
	return rec
}

func mcpResult(t *testing.T, rec *httptest.ResponseRecorder) (result map[string]any, rpcErr *mcpError) {
	t.Helper()
	var resp struct {
		ID     any            `json:"id"`
		Result map[string]any `json:"result"`
		Error  *mcpError      `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("not JSON (%d): %s", rec.Code, rec.Body)
	}
	return resp.Result, resp.Error
}

func TestMCPHandshake(t *testing.T) {
	s := &Server{logger: slog.Default()}
	for _, c := range []struct{ asked, want string }{
		{"2025-06-18", "2025-06-18"},
		{"2025-03-26", "2025-03-26"},
		{"1999-01-01", mcpProtocolVersions[0]},
	} {
		res, rpcErr := mcpResult(t, mcpCall(t, s, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+c.asked+`","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`))
		if rpcErr != nil || res["protocolVersion"] != c.want {
			t.Errorf("asked %s: %v %v", c.asked, res, rpcErr)
		}
	}
	// A notification gets no body at all.
	if rec := mcpCall(t, s, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Errorf("notification: %d %q", rec.Code, rec.Body)
	}
	if res, rpcErr := mcpResult(t, mcpCall(t, s, `{"jsonrpc":"2.0","id":"a","method":"ping"}`)); rpcErr != nil || res == nil {
		t.Errorf("ping: %v %v", res, rpcErr)
	}
	if rec := mcpCall(t, s, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, "MCP-Protocol-Version", "1999-01-01"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad version header: %d", rec.Code)
	}
}

func TestMCPRefusesWhatItDoesNotServe(t *testing.T) {
	s := &Server{logger: slog.Default()}
	cases := []struct {
		name, body string
		code       int
	}{
		{"unknown method", `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`, mcpMethodNotFound},
		{"unknown tool", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_command"}}`, mcpInvalidParams},
		{"not JSON", `nope`, mcpParseError},
		{"a batch", `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, mcpParseError},
		{"wrong version", `{"jsonrpc":"1.0","id":1,"method":"ping"}`, mcpInvalidRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, rpcErr := mcpResult(t, mcpCall(t, s, c.body))
			if rpcErr == nil || rpcErr.Code != c.code {
				t.Errorf("got %+v, want code %d", rpcErr, c.code)
			}
		})
	}
	// A model's mistake comes back as something it can read and fix.
	for _, args := range []string{`{"update":"nonsense"}`, `{"limit":0}`, `{"limit":100000}`, `{"command":"rm"}`} {
		res, rpcErr := mcpResult(t, mcpCall(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_containers","arguments":`+args+`}}`))
		if rpcErr != nil || res["isError"] != true {
			t.Errorf("%s: %v %v", args, res, rpcErr)
		}
	}
}

// Every tool offered must say it only reads. Adding one that changes
// something should have to get past this test, and whoever reads it.
func TestMCPOffersOnlyReadOnlyTools(t *testing.T) {
	s := &Server{logger: slog.Default()}
	res, rpcErr := mcpResult(t, mcpCall(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if rpcErr != nil {
		t.Fatal(rpcErr)
	}
	tools := res["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("expected only list_containers, got %d tools", len(tools))
	}
	tool := tools[0].(map[string]any)
	if ann := tool["annotations"].(map[string]any); ann["readOnlyHint"] != true || ann["destructiveHint"] != false {
		t.Errorf("annotations: %v", ann)
	}
	if tool["inputSchema"].(map[string]any)["type"] != "object" {
		t.Error("input schema must be an object schema")
	}
}

func TestMCPListContainers(t *testing.T) {
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
	s := &Server{logger: slog.Default(), store: st, live: &liveConfig{}}

	host := idgen.New("mcp-")
	agentID := "agt-" + host
	if err := st.UpsertOnRegister(ctx, agentID, proto.AgentInfo{Hostname: host, OS: "linux"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.DeleteAgent(context.Background(), agentID) })
	raw, _ := json.Marshal([]proto.ContainerInfo{
		{Name: "a", Image: "a:1", Update: proto.ContainerUpToDate},
		{Name: "b", Image: "b:1", Update: proto.ContainerUpdateAvailable, NewerTag: "2"},
		{Name: "c", Image: "c:1", Update: proto.ContainerUpdateAvailable, NewerTag: "3"},
		{Name: "d", Image: "d:1"}, // an agent that sent no conclusion
	})
	if err := st.UpsertSensorData(ctx, agentID, string(proto.SensorContainers), time.Now(), raw); err != nil {
		t.Fatal(err)
	}

	call := func(args string) mcpContainers {
		t.Helper()
		res, rpcErr := mcpResult(t, mcpCall(t, s, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_containers","arguments":`+args+`}}`))
		if rpcErr != nil || res["isError"] == true {
			t.Fatalf("%v %v", res, rpcErr)
		}
		var text mcpContainers
		content := res["content"].([]any)[0].(map[string]any)["text"].(string)
		if err := json.Unmarshal([]byte(content), &text); err != nil {
			t.Fatal(err)
		}
		return text
	}
	all := call(`{"hostname":"` + strings.ToUpper(host) + `"}`)
	if all.Total != 4 || all.Truncated || all.Containers[0].Update != proto.ContainerUpdateAvailable || all.Counts[proto.ContainerNotChecked] != 1 {
		t.Errorf("all: %+v", all)
	}
	updates := call(`{"agent_id":"` + agentID + `","update":"update_available"}`)
	if updates.Total != 2 || updates.Hosts != 1 || updates.Containers[0].Name != "b" {
		t.Errorf("updates: %+v", updates)
	}
	limited := call(`{"agent_id":"` + agentID + `","limit":1}`)
	if len(limited.Containers) != 1 || !limited.Truncated || limited.Total != 4 || limited.Counts[proto.ContainerUpToDate] != 1 {
		t.Errorf("limited: %+v", limited)
	}
	if none := call(`{"hostname":"no-such-host"}`); none.Containers == nil || none.Total != 0 {
		t.Errorf("none: %+v", none)
	}
}
