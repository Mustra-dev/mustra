package agent

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/mustra-dev/mustra/internal/proto"
)

func TestAnswerDelay(t *testing.T) {
	if d := answerDelay(5000, true); d != 0 {
		t.Errorf("a query to this agent alone waited %s", d)
	}
	if d := answerDelay(0, false); d != 0 {
		t.Errorf("no window requested, waited %s", d)
	}
	for range 1000 {
		if d := answerDelay(2000, false); d < 0 || d >= 2*time.Second {
			t.Fatalf("delay %s outside a 2 s window", d)
		}
		if d := answerDelay(int(time.Hour/time.Millisecond), false); d >= maxAnswerDelay {
			t.Fatalf("delay %s beyond the %s cap", d, maxAnswerDelay)
		}
	}
}

// Older servers send no window and older agents ignore it: the field must
// be optional in both directions.
func TestQueryEnvelopeWindowIsOptional(t *testing.T) {
	var q proto.QueryEnvelope
	if err := json.Unmarshal([]byte(`{"query_id":"q-1","kind":"facts","issued_at":"2026-01-01T00:00:00Z"}`), &q); err != nil || q.AnswerWithinMs != 0 {
		t.Fatalf("old envelope: %+v %v", q, err)
	}
	raw, _ := json.Marshal(proto.QueryEnvelope{QueryID: "q-2", Kind: proto.QueryKindFacts})
	if string(raw) != `{"query_id":"q-2","kind":"facts","issued_at":"0001-01-01T00:00:00Z"}` {
		t.Fatalf("a zero window must be omitted: %s", raw)
	}
}
