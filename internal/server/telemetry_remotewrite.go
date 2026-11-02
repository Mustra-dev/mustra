package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/klauspost/compress/snappy"
)

// Prometheus remote_write: a protobuf WriteRequest, snappy-compressed,
// POSTed with the 0.1.0 protocol headers. The message is small enough to
// encode by hand:
//
//	WriteRequest { repeated TimeSeries timeseries = 1; }
//	TimeSeries   { repeated Label labels = 1; repeated Sample samples = 2; }
//	Label        { string name = 1; string value = 2; }
//	Sample       { double value = 1; int64 timestamp = 2; }

func encodeWriteRequest(series []telemetrySeries) []byte {
	var out []byte
	for _, s := range series {
		var ts []byte
		ts = appendLabel(ts, "__name__", s.Name)
		for _, kv := range s.Labels {
			ts = appendLabel(ts, kv[0], kv[1])
		}
		var smp []byte
		smp = append(smp, 0x09) // field 1, fixed64
		smp = binary.LittleEndian.AppendUint64(smp, math.Float64bits(s.Value))
		smp = append(smp, 0x10) // field 2, varint
		smp = binary.AppendUvarint(smp, uint64(s.TimeMs))
		ts = appendBytesField(ts, 2, smp)
		out = appendBytesField(out, 1, ts)
	}
	return out
}

func appendLabel(b []byte, name, value string) []byte {
	var l []byte
	l = appendBytesField(l, 1, []byte(name))
	l = appendBytesField(l, 2, []byte(value))
	return appendBytesField(b, 1, l)
}

func appendBytesField(b []byte, field int, v []byte) []byte {
	b = binary.AppendUvarint(b, uint64(field<<3|2))
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

// remoteWriteError says whether a failed write is worth retrying: a
// server error or no answer is, a rejected request (bad samples) is not.
type remoteWriteError struct {
	status int
	msg    string
	// final: the request was never sent (a URL the allowlist refuses), so
	// retrying cannot help until the settings change.
	final bool
}

func (e remoteWriteError) Error() string {
	if e.status == 0 {
		return e.msg
	}
	return fmt.Sprintf("HTTP %d: %s", e.status, e.msg)
}

func (e remoteWriteError) retryable() bool {
	return !e.final && (e.status == 0 || e.status == 429 || e.status >= 500)
}

func (s *Server) remoteWrite(ctx context.Context, url, username, secret string, series []telemetrySeries) error {
	// The receiver is operator-configured, so it goes through the same
	// guard as webhooks: an internal host (an in-house Prometheus) must be
	// on the internal destinations allowlist, and only then may it use
	// plain http.
	client, allowed := s.webhookClient(ctx)
	if err := checkWebhookURL(url, allowed); err != nil {
		return remoteWriteError{msg: err.Error(), final: true}
	}
	body := snappy.Encode(nil, encodeWriteRequest(series))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return remoteWriteError{msg: err.Error()}
	}
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	req.Header.Set("User-Agent", "mustra")
	switch {
	case username != "":
		req.SetBasicAuth(username, secret)
	case secret != "":
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return remoteWriteError{msg: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return remoteWriteError{status: resp.StatusCode, msg: strings.TrimSpace(string(msg))}
}

// telemetrySendLoop drains the queue to remote_write: every batch that
// arrived since the last send goes in one request, as soon as one arrives.
// A write that fails for a retryable reason is retried with backoff; one
// the receiver rejects is dropped and counted.
func (s *Server) telemetrySendLoop(ctx context.Context) {
	backoff := time.Second
	for {
		h := s.telemetry
		t := s.telemetrySettings(ctx)
		on := t.Metrics.Enabled && t.RemoteWrite.Enabled && t.RemoteWrite.URL != ""
		h.mu.Lock()
		h.enabled = on
		if !on {
			h.queue = nil
		}
		batch := h.queue
		h.queue = nil
		interval := time.Duration(t.Metrics.IntervalSeconds) * time.Second
		upDue := on && time.Since(h.lastUp) >= interval
		h.mu.Unlock()
		if on && (len(batch) > 0 || upDue) {
			secret := ""
			if stored, _ := s.store.GetSetting(ctx, settingTelemetryRemoteWriteSecret); stored != "" {
				secret, _ = s.openSetting(settingTelemetryRemoteWriteSecret, stored)
			}
			endpoints := s.telemetryEndpoints(ctx, t)
			var series []telemetrySeries
			if upDue {
				series = upSeries(endpoints, h.lastReceived(), time.Now())
			}
			for _, e := range batch {
				if ep, ok := endpoints[e.AgentID]; ok && ep.InScope {
					series = append(series, expandBatch(e.Batch, ep.Labels)...)
				}
			}
			err := s.remoteWrite(ctx, t.RemoteWrite.URL, t.RemoteWrite.Username, secret, series)
			now := time.Now().UTC()
			h.mu.Lock()
			if err == nil {
				if upDue {
					h.lastUp = now
				}
				h.stats.BatchesSent += int64(len(batch))
				h.stats.SeriesSent += int64(len(series))
				h.stats.LastSentAt = &now
				backoff = time.Second
			} else {
				h.stats.LastError, h.stats.LastErrorAt = err.Error(), &now
				if rw, ok := err.(remoteWriteError); ok && rw.retryable() {
					// Back to the front of the queue, within its bound.
					h.queue = append(batch, h.queue...)
					if over := len(h.queue) - telemetryMaxQueue; over > 0 {
						h.queue = h.queue[over:]
						h.stats.BatchesDropped += int64(over)
					}
				} else {
					h.stats.BatchesDropped += int64(len(batch))
				}
			}
			h.mu.Unlock()
			if err != nil {
				if rw, ok := err.(remoteWriteError); ok && rw.retryable() {
					select {
					case <-ctx.Done():
						return
					case <-time.After(backoff):
					}
					backoff = min(backoff*2, time.Minute)
					continue
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-h.wake:
			// Let the rest of a round arrive: agents on the same interval
			// report within seconds of each other, and one request for all
			// of them beats one each.
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		case <-time.After(min(30*time.Second, time.Duration(t.Metrics.IntervalSeconds)*time.Second)):
			// Up series are due even when no endpoint reports at all.
		}
	}
}
