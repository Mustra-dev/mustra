//go:build linux

package agent

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

// buildConnectorMessage assembles what the kernel sends, so the parser is
// tested against the layout it claims to implement rather than against
// itself. A wrong offset here does not fail loudly in production — it
// produces plausible-looking PIDs — which is exactly why this exists.
func buildConnectorMessage(what uint32, pid, tgid int32) []byte {
	be := binary.NativeEndian
	payload := make([]byte, cnMsgLen+procEventHead+8)
	be.PutUint32(payload[0:], cnIdxProc)
	be.PutUint32(payload[4:], cnValProc)
	ev := payload[cnMsgLen:]
	be.PutUint32(ev[0:], what)
	be.PutUint32(ev[4:], 0) // cpu
	be.PutUint64(ev[8:], 0) // timestamp
	be.PutUint32(ev[procEventHead+0:], uint32(pid))
	be.PutUint32(ev[procEventHead+4:], uint32(tgid))

	msg := make([]byte, unix.NLMSG_HDRLEN+len(payload))
	be.PutUint32(msg[0:], uint32(len(msg)))
	be.PutUint16(msg[4:], unix.NLMSG_DONE)
	copy(msg[unix.NLMSG_HDRLEN:], payload)
	return msg
}

func TestParseExecEventReadsTheTGID(t *testing.T) {
	// pid is the thread, tgid is what /proc and every other tool call "the
	// pid". Reading the wrong one gives a number that exists and is wrong.
	msg := buildConnectorMessage(procEventExec, 4242, 4200)
	payload := walkNetlink(msg)
	if len(payload) != 1 {
		t.Fatalf("walkNetlink returned %d messages, want 1", len(payload))
	}
	got, ok := parseExecEvent(payload[0])
	if !ok {
		t.Fatal("an exec event was not recognised")
	}
	if got != 4200 {
		t.Errorf("pid = %d, want the tgid 4200", got)
	}
}

// A fork without an exec is the same program; reporting those would triple
// the feed for nothing.
func TestParseExecEventIgnoresOtherEventTypes(t *testing.T) {
	for _, what := range []uint32{0x00000001 /* fork */, 0x80000000 /* exit */, 0x00000004 /* uid */} {
		payload := walkNetlink(buildConnectorMessage(what, 1, 1))
		if _, ok := parseExecEvent(payload[0]); ok {
			t.Errorf("event type %#x was treated as an exec", what)
		}
	}
}

func TestParseExecEventRejectsShortAndForeignMessages(t *testing.T) {
	if _, ok := parseExecEvent([]byte{1, 2, 3}); ok {
		t.Error("a truncated message was parsed")
	}
	// Another connector's traffic arrives on the same socket family.
	msg := buildConnectorMessage(procEventExec, 1, 1)
	payload := walkNetlink(msg)
	binary.NativeEndian.PutUint32(payload[0][0:], 0x99) // a different cb_id.idx
	if _, ok := parseExecEvent(payload[0]); ok {
		t.Error("a message from another connector was parsed as a process event")
	}
}

func TestWalkNetlinkHandlesSeveralMessagesAndPadding(t *testing.T) {
	var buf []byte
	buf = append(buf, buildConnectorMessage(procEventExec, 1, 11)...)
	buf = append(buf, buildConnectorMessage(procEventExec, 2, 22)...)
	msgs := walkNetlink(buf)
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	for i, want := range []int32{11, 22} {
		got, ok := parseExecEvent(msgs[i])
		if !ok || got != want {
			t.Errorf("message %d = %d (ok=%v), want %d", i, got, ok, want)
		}
	}
}

// A malformed length must stop the walk rather than loop or read past the
// buffer.
func TestWalkNetlinkSurvivesALyingLength(t *testing.T) {
	msg := buildConnectorMessage(procEventExec, 1, 1)
	binary.NativeEndian.PutUint32(msg[0:], 4) // shorter than a header
	if got := walkNetlink(msg); len(got) != 0 {
		t.Fatalf("got %d messages from a malformed buffer, want 0", len(got))
	}
	binary.NativeEndian.PutUint32(msg[0:], 1<<20) // longer than the buffer
	if got := walkNetlink(msg); len(got) != 0 {
		t.Fatalf("got %d messages from an over-long length, want 0", len(got))
	}
}
