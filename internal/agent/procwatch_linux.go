//go:build linux

package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mustra-dev/mustra/internal/proto"
)

// The Linux mechanism: the kernel's process-events connector.
//
// This is the difference between "what was running when I last looked" and
// "what ran". The connector delivers an exec event from the kernel the
// moment a process image is replaced, so a command that lives for two
// milliseconds is seen — and a command that lives for two milliseconds is
// most of what somebody who should not be there runs.
//
// It is a netlink multicast group rather than a library, so the wire format
// is assembled by hand below. The layout is stable kernel ABI (it has not
// changed since 2.6.15) and is deliberately spelled out in constants rather
// than magic offsets, because a wrong offset here does not fail loudly: it
// produces plausible-looking PIDs.
//
// Two properties are worth knowing before trusting a quiet feed:
//
//	It needs CAP_NET_ADMIN, which the agent has as root and does not have
//	in an unprivileged container. The caller falls back to polling.
//
//	The event carries a PID and nothing else, so everything interesting
//	about the process is read from /proc afterwards — and a process that
//	exits first cannot be identified. Those are counted rather than
//	invented, because a box with hundreds of unidentifiable execs is
//	itself the signal.

const (
	cnIdxProc = 0x1
	cnValProc = 0x1

	procCNMcastListen = 1

	procEventExec = 0x00000002

	// connectorRecvBuffer is the socket receive buffer. Generous because
	// the cost of overflowing it is dropped exec events, and this reader
	// spends most of its time in /proc rather than in recvfrom.
	connectorRecvBuffer = 1 << 20
	// maxConnectorErrors is how many consecutive unexpected read failures
	// are tolerated before giving up on the kernel feed and telling the
	// caller to fall back to sampling. Going quiet is not an option: an
	// endpoint reporting nothing while the console counts it as kernel
	// sourced is worse than one openly sampling.
	maxConnectorErrors = 20

	// Wire layout. nlmsghdr is 16 bytes; cn_msg is {cb_id{u32,u32}, u32
	// seq, u32 ack, u16 len, u16 flags} = 20; proc_event starts with
	// {u32 what, u32 cpu, u64 timestamp} = 16 before its union.
	nlmsgHdrLen   = unix.NLMSG_HDRLEN
	cnMsgLen      = 20
	procEventHead = 16
)

// startProcessConnector subscribes to the connector and pumps exec events
// into out. The returned cancel closes the socket, which is what unblocks
// the reader.
//
// degraded is called if the feed dies after starting — the caller falls
// back to polling, because a netlink feed that has silently stopped is the
// worst state to be in: the console keeps counting the endpoint as kernel
// sourced, so an empty feed reads as a quiet machine rather than a broken
// one.
func startProcessConnector(ctx context.Context, out chan<- proto.ProcessEvent, degraded func(error)) (bool, func(), error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_CONNECTOR)
	if err != nil {
		return false, nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: cnIdxProc,
	}); err != nil {
		unix.Close(fd)
		return false, nil, fmt.Errorf("bind to the process connector (needs CAP_NET_ADMIN): %w", err)
	}
	if err := sendMcastOp(fd, procCNMcastListen); err != nil {
		unix.Close(fd)
		return false, nil, fmt.Errorf("subscribe to process events: %w", err)
	}

	// The kernel's default receive buffer is small, and this reader does
	// four /proc reads per event before returning to recvfrom. Under an exec
	// storm the socket overflows, which used to be fatal. A bigger buffer
	// makes that rarer; the ENOBUFS handling below makes it survivable.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, connectorRecvBuffer)

	done := make(chan struct{})
	// sync.Once, not a select/default guard: stop is called from the reader's
	// defer, from the context watcher, and from the caller's own defer, so
	// two goroutines could both take the default branch and close(done)
	// twice — a panic that takes the agent down. The unconditional
	// unix.Close was worse: closing an already-closed fd a second time hits
	// whatever unrelated file or socket has since been handed that number.
	var once sync.Once
	stop := func() {
		once.Do(func() {
			close(done)
			unix.Close(fd)
		})
	}
	go func() {
		defer stop()
		readConnector(ctx, fd, done, out, degraded)
	}()
	go func() {
		<-ctx.Done()
		stop()
	}()
	return true, stop, nil
}

func sendMcastOp(fd int, op uint32) error {
	buf := make([]byte, nlmsgHdrLen+cnMsgLen+4)
	be := binary.NativeEndian

	be.PutUint32(buf[0:], uint32(len(buf))) // nlmsg_len
	be.PutUint16(buf[4:], unix.NLMSG_DONE)  // nlmsg_type
	be.PutUint16(buf[6:], 0)                // nlmsg_flags
	be.PutUint32(buf[8:], 0)                // nlmsg_seq
	be.PutUint32(buf[12:], 0)               // nlmsg_pid — the kernel fills it in

	cn := buf[nlmsgHdrLen:]
	be.PutUint32(cn[0:], cnIdxProc) // cb_id.idx
	be.PutUint32(cn[4:], cnValProc) // cb_id.val
	be.PutUint32(cn[8:], 0)         // seq
	be.PutUint32(cn[12:], 0)        // ack
	be.PutUint16(cn[16:], 4)        // len — the payload below
	be.PutUint16(cn[18:], 0)        // flags
	be.PutUint32(cn[cnMsgLen:], op)

	return unix.Sendto(fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func readConnector(ctx context.Context, fd int, done <-chan struct{},
	out chan<- proto.ProcessEvent, degraded func(error)) {

	buf := make([]byte, 8192)
	consecutive := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		default:
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			// Shutting down: a closed socket is how this loop is meant to
			// end, and the error it produces is not worth reporting.
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			default:
			}
			switch err {
			case unix.EINTR:
				// Ordinary. Not a failure at all.
				continue
			case unix.ENOBUFS:
				// The kernel dropped events because we did not drain fast
				// enough. The batch we go on to publish is incomplete, and
				// saying nothing would let a busy minute read as a quiet
				// one — but it is emphatically not a reason to stop
				// listening, which is what returning here used to do.
				consecutive = 0
				degraded(nil)
				continue
			}
			// Anything else: keep trying for a while. A feed that gives up
			// on the first unexpected errno is one that dies on a transient
			// and never comes back, with the console still reporting the
			// endpoint as kernel sourced.
			consecutive++
			if consecutive >= maxConnectorErrors {
				degraded(err)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-time.After(time.Second):
			}
			continue
		}
		consecutive = 0
		for _, payload := range walkNetlink(buf[:n]) {
			pid, ok := parseExecEvent(payload)
			if !ok {
				continue
			}
			// Reading /proc here rather than in the flusher: the process may
			// be gone in five seconds, and this is the only moment it is
			// reliably there.
			ev, ok := describeProcess(ctx, pid)
			if !ok {
				// Gone before it could be identified. Counted by the caller
				// via a nameless event rather than invented.
				ev = proto.ProcessEvent{PID: pid, At: time.Now().UTC()}
			}
			select {
			case out <- ev:
			default: // full: the flusher counts what it could not take
			}
		}
	}
}

// walkNetlink splits a read into the netlink messages it contains.
//
// Written out rather than taken from syscall.ParseNetlinkMessage so the
// wire format lives in one file with the constants above, and so it can be
// tested against a synthetic buffer — a wrong offset here does not fail
// loudly, it produces plausible-looking PIDs.
func walkNetlink(buf []byte) [][]byte {
	var out [][]byte
	be := binary.NativeEndian
	for len(buf) >= nlmsgHdrLen {
		length := int(be.Uint32(buf[0:]))
		if length < nlmsgHdrLen || length > len(buf) {
			return out
		}
		out = append(out, buf[nlmsgHdrLen:length])
		// Messages are padded to a 4-byte boundary.
		advance := (length + 3) &^ 3
		if advance <= 0 || advance > len(buf) {
			return out
		}
		buf = buf[advance:]
	}
	return out
}

// parseExecEvent pulls the PID out of one connector message, ignoring the
// other event types (fork, uid change, exit) — a fork without an exec is
// the same program, and reporting it would triple the feed for nothing.
func parseExecEvent(data []byte) (int32, bool) {
	if len(data) < cnMsgLen+procEventHead+8 {
		return 0, false
	}
	be := binary.NativeEndian
	if be.Uint32(data[0:]) != cnIdxProc || be.Uint32(data[4:]) != cnValProc {
		return 0, false
	}
	ev := data[cnMsgLen:]
	if be.Uint32(ev[0:]) != procEventExec {
		return 0, false
	}
	// exec_proc_event is {process_pid, process_tgid}; the tgid is the one
	// that matches what /proc and every other tool call "the pid".
	return int32(be.Uint32(ev[procEventHead+4:])), true
}
