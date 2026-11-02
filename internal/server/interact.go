package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/mustra-dev/mustra/internal/groups"
	"github.com/mustra-dev/mustra/internal/idgen"
	"github.com/mustra-dev/mustra/internal/server/auth"
	"github.com/mustra-dev/mustra/internal/store"
)

// Interact: query the whole fleet and act on the answer.
//
// The grammar reads the way people describe
// what they want:
//
//	get <field>[ and <field>…] from all machines[ with <field> <op> <value>]
//
// Two decisions from that design are worth keeping. First, the `from`
// clause is evaluated before anything else, so a query that targets a
// slice of the fleet costs nothing on the rest. Second — and this is the
// part that makes the results grid usable — a single-field query is
// *counting*: identical answers collapse into one row with a tally, so
// "get os from all machines" is a five-row answer across a thousand
// endpoints rather than a thousand rows to scroll. Querying more than
// one field forces one row per endpoint, because the tuple is what you
// wanted to see.
//
// Answers come from the sensor cache mustra already keeps, so a query
// returns immediately and includes endpoints that are currently offline —
// with each row carrying how stale its data is, rather than pretending
// everything is live.

type questionRequest struct {
	RecordSensor string        `json:"record_sensor,omitempty"`
	Get          []string      `json:"get" api:"required"`
	Where        []groups.Rule `json:"where,omitempty"`
	MatchAll     bool          `json:"match_all"`
	Text         string        `json:"text,omitempty"` // the raw question, for history
	// Live asks the online endpoints for the live-capable sensors the
	// question reads before answering (interact_live.go).
	Live bool `json:"live,omitempty"`
}

type questionRow struct {
	Values   []string `json:"values"`
	Count    int      `json:"count"`
	AgentIDs []string `json:"agent_ids"`
	Hostname string   `json:"hostname,omitempty"` // set only on non-counting rows
}

type questionResult struct {
	Get       []string      `json:"get"`
	Counting  bool          `json:"counting"`
	Rows      []questionRow `json:"rows"`
	Matched   int           `json:"matched"`   // endpoints that passed the from clause
	Total     int           `json:"total"`     // endpoints in inventory
	Reporting int           `json:"reporting"` // matched endpoints that had an answer
	Text      string        `json:"text"`
	Live      *liveSummary  `json:"live,omitempty"`
}

// noResult is what a device that has never reported the field answers.
// Kept distinct from an empty string so a grid can say "no result" rather
// than showing a blank cell that reads as a real, empty value.
const noResult = "[no result]"

func (s *Server) handleAskQuestion(w http.ResponseWriter, r *http.Request) {
	var req questionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if len(req.Get) == 0 {
		http.Error(w, "a query needs at least one field to get", http.StatusBadRequest)
		return
	}
	// Groups ("(A or B) and C") are checked through their conditions, and
	// value filters ("installed_apps.name[contains x]") like any other.
	leaves, err := groups.ExpandGroups(req.Where)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	bare, vf, err := parseGetFilters(req.Get)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	leaves = append(leaves, vf.all...)
	if err := s.validateCustomFields(r.Context(), bare, leaves, req.RecordSensor); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if err := s.checkSensorFields(r.Context(), bare, leaves); err != nil {
		writeSensorFieldsError(w, err)
		return
	}
	for _, rule := range leaves {
		if err := rule.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	devices, _, err := s.devicesForMatching(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var live *liveSummary
	if req.Live {
		online := 0
		for _, d := range devices {
			if d.Online {
				online++
			}
		}
		fresh, sum := s.askLive(r.Context(), liveSensorsFor(req.Get, req.Where), online)
		devices = overlayLive(devices, fresh)
		live = &sum
	}
	result := answerQuestion(devices, req)
	result.Live = live

	// Question history is the audit log: who asked what, and when. Recorded
	// after the answer so a malformed question never lands in it.
	who := auth.CurrentUser(r.Context()).Username
	if err := s.store.RecordQuestion(r.Context(), store.QuestionHistory{
		ID: idgen.New("q-"), Text: result.Text, AskedBy: who,
		Matched: result.Matched, Total: result.Total,
	}); err != nil {
		s.logger.Warn("record question history failed", "error", err)
	}
	writeJSONResponse(w, result)
}

// answerQuestion is the whole evaluation, kept free of HTTP and storage so
// it can be tested against a fixed fleet.
func answerQuestion(devices []groups.Device, req questionRequest) questionResult {
	if strings.HasPrefix(req.RecordSensor, "custom_") {
		req.Get = append([]string{}, req.Get...)
		for _, key := range []string{"_status", "_collected_at", "_last_attempt_at", "_historical", "_error"} {
			field := req.RecordSensor + "." + key
			found := false
			for _, f := range req.Get {
				if f == field {
					found = true
				}
			}
			if !found {
				req.Get = append(req.Get, field)
			}
		}
	}
	out := questionResult{
		Get:      req.Get,
		Counting: len(req.Get) == 1 && req.RecordSensor == "",
		Total:    len(devices),
		Text:     req.Text,
	}
	if out.Text == "" {
		out.Text = describeQuestion(req)
	}

	// The from clause first: a device that doesn't match contributes
	// nothing and isn't counted as reporting. Value filters then trim each
	// one to the sensor rows they match (interact_filters.go); the result
	// keeps the get entries as asked, filters and all, for its headings.
	bare, vf, _ := parseGetFilters(req.Get) // validated by the handler
	matched := devices
	if len(req.Where) > 0 || len(vf.all) > 0 {
		matched = matched[:0:0]
		for _, d := range devices {
			if len(req.Where) > 0 && !groups.Matches(d, req.Where, req.MatchAll) {
				continue
			}
			if trimmed, ok := vf.apply(d); ok {
				matched = append(matched, trimmed)
			}
		}
	}
	out.Matched = len(matched)
	if len(bare) == len(req.Get) {
		req.Get = bare
	}

	if req.RecordSensor != "" {
		out.Rows = recordQuestionRows(matched, req, &out.Reporting)
	} else if out.Counting {
		out.Rows = countingRows(matched, req.Get[0], &out.Reporting)
	} else {
		out.Rows = perDeviceRows(matched, req.Get, &out.Reporting)
	}
	return out
}

// countingRows collapses identical answers into one row with a tally —
// the single-field case. A device answering several values (every
// installed app, say) contributes to every one of them, which is what
// makes "get installed_apps.name from all machines" a software census
// rather than a list of machines.
func countingRows(devices []groups.Device, field string, reporting *int) []questionRow {
	byValue := map[string][]string{}
	for _, d := range devices {
		values := groups.Values(d, field)
		if values == nil {
			byValue[noResult] = append(byValue[noResult], d.AgentID)
			continue
		}
		*reporting++
		if len(values) == 0 {
			byValue[""] = append(byValue[""], d.AgentID)
			continue
		}
		for _, v := range values {
			byValue[v] = append(byValue[v], d.AgentID)
		}
	}

	rows := make([]questionRow, 0, len(byValue))
	for value, agents := range byValue {
		rows = append(rows, questionRow{Values: []string{value}, Count: len(agents), AgentIDs: agents})
	}
	// Commonest first, then alphabetically, so the answer is stable across
	// reloads rather than reshuffling on every map iteration.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Count != rows[j].Count {
			return rows[i].Count > rows[j].Count
		}
		return rows[i].Values[0] < rows[j].Values[0]
	})
	return rows
}

// perDeviceRows gives one row per endpoint — the multi-field case, where
// the combination is the thing being asked about.
func perDeviceRows(devices []groups.Device, fields []string, reporting *int) []questionRow {
	rows := make([]questionRow, 0, len(devices))
	for _, d := range devices {
		row := questionRow{Count: 1, AgentIDs: []string{d.AgentID}, Hostname: d.Hostname}
		answered := false
		for _, field := range fields {
			values := groups.Values(d, field)
			switch {
			case values == nil:
				row.Values = append(row.Values, noResult)
			case len(values) == 0:
				row.Values = append(row.Values, "")
				answered = true
			default:
				row.Values = append(row.Values, strings.Join(values, ", "))
				answered = true
			}
		}
		if answered {
			*reporting++
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Hostname < rows[j].Hostname })
	return rows
}

// describeQuestion renders a request back as the sentence that would have
// produced it, so history reads as questions rather than as JSON.
func describeQuestion(req questionRequest) string {
	var b strings.Builder
	b.WriteString("get ")
	b.WriteString(strings.Join(req.Get, " and "))
	b.WriteString(" from all machines")
	if len(req.Where) > 0 {
		b.WriteString(" with ")
		joiner := " or "
		if req.MatchAll {
			joiner = " and "
		}
		b.WriteString(describeRules(req.Where, joiner))
	}
	return b.String()
}

// describeRules joins conditions, a group in brackets with its own joiner.
func describeRules(rules []groups.Rule, joiner string) string {
	parts := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Op == groups.OpGroup {
			var g groups.RuleGroup
			_ = json.Unmarshal([]byte(rule.Value), &g)
			inner := " or "
			if g.All {
				inner = " and "
			}
			parts = append(parts, "("+describeRules(g.Rules, inner)+")")
			continue
		}
		parts = append(parts, rule.Field+" "+strings.ReplaceAll(rule.Op, "_", " ")+" "+rule.Value)
	}
	return strings.Join(parts, joiner)
}

// ---- saved questions and history ----

// listSavedQuestionsResponse is what GET /api/interact/saved answers.
type listSavedQuestionsResponse struct {
	Fields    []groups.FieldSpec    `json:"fields"`
	Questions []store.SavedQuestion `json:"questions"`
}

func (s *Server) handleListSavedQuestions(w http.ResponseWriter, r *http.Request) {
	saved, err := s.store.ListSavedQuestions(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Content sets: a role holding one sees only the saved questions it
	// names.
	allowed, err := s.contentFilter(r.Context(), "questions")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	kept := make([]store.SavedQuestion, 0, len(saved))
	for _, q := range saved {
		if allowed(q.ID) {
			kept = append(kept, q)
		}
	}
	saved = kept
	fields, err := s.sensorFields(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSONResponse(w, listSavedQuestionsResponse{Questions: saved, Fields: fields})
}

func (s *Server) handleSaveQuestion(w http.ResponseWriter, r *http.Request) {
	var body store.SavedQuestion
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	var rules []groups.Rule
	if len(body.Where) > 0 && json.Unmarshal(body.Where, &rules) != nil {
		http.Error(w, "invalid conditions", 400)
		return
	}
	leaves, err := groups.ExpandGroups(rules)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	bare, vf, err := parseGetFilters(body.Get)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	leaves = append(leaves, vf.all...)
	if err := s.validateCustomFields(r.Context(), bare, leaves, body.RecordSensor); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	// A saved question feeds exports, reports and dashboards, so changing
	// one changes what those send and show. The author is the server's to
	// record and the id the server's to mint; an existing question is
	// changed by its author or an administrator, as it is deleted.
	me := auth.CurrentUser(r.Context()).Username
	if body.ID != "" {
		existing, err := s.store.GetSavedQuestion(r.Context(), body.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if existing == nil {
			http.Error(w, "no such saved question", http.StatusNotFound)
			return
		}
		if existing.CreatedBy != me && !s.isAdmin(r) {
			http.Error(w, "only the author or an administrator can change this saved question", http.StatusForbidden)
			return
		}
		body.CreatedBy, body.CreatedAt = existing.CreatedBy, existing.CreatedAt
	} else {
		body.ID = idgen.New("sq-")
		body.CreatedBy = me
	}
	saved, err := s.store.UpsertSavedQuestion(r.Context(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSONResponse(w, saved)
}

func (s *Server) handleDeleteSavedQuestion(w http.ResponseWriter, r *http.Request) {
	// Saved questions are shared with everyone, so removing one is its
	// author's call or an administrator's, not any viewer's.
	q, err := s.store.GetSavedQuestion(r.Context(), r.PathValue("id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if q == nil {
		http.Error(w, "no such saved question", http.StatusNotFound)
		return
	}
	if q.CreatedBy != auth.CurrentUser(r.Context()).Username && !s.isAdmin(r) {
		http.Error(w, "only the author or an administrator can delete this saved question", http.StatusForbidden)
		return
	}
	if err := s.store.DeleteSavedQuestion(r.Context(), r.PathValue("id")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// questionHistoryResponse is what GET /api/interact/history answers.
type questionHistoryResponse struct {
	History []store.QuestionHistory `json:"history"`
}

func (s *Server) handleQuestionHistory(w http.ResponseWriter, r *http.Request) {
	history, err := s.store.ListQuestionHistory(r.Context(), 200)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if history == nil {
		history = []store.QuestionHistory{}
	}
	writeJSONResponse(w, questionHistoryResponse{History: history})
}

// Record view keeps values from one collected row together; it never joins two
// independent sensor arrays into a misleading Cartesian product.
func recordQuestionRows(devices []groups.Device, req questionRequest, reporting *int) []questionRow {
	out := []questionRow{}
	for _, d := range devices {
		records, present := d.Sensors[req.RecordSensor]
		if !present {
			records = d.HistoricalSensors[req.RecordSensor]
		}
		if present {
			*reporting++
		}
		if len(records) == 0 {
			out = append(out, perDeviceRows([]groups.Device{d}, req.Get, new(int))...)
			continue
		}
		for _, record := range records {
			row := questionRow{Count: 1, AgentIDs: []string{d.AgentID}, Hostname: d.Hostname}
			for _, field := range req.Get {
				sensor, key, ok := strings.Cut(field, ".")
				if ok && sensor == req.RecordSensor && key != "count" && !strings.HasPrefix(key, "_") {
					if v := record[key]; v != nil {
						row.Values = append(row.Values, fmt.Sprint(v))
					} else {
						row.Values = append(row.Values, "[null]")
					}
				} else {
					v := groups.Values(d, field)
					if v == nil {
						row.Values = append(row.Values, noResult)
					} else {
						row.Values = append(row.Values, strings.Join(v, ", "))
					}
				}
			}
			out = append(out, row)
		}
	}
	return out
}
