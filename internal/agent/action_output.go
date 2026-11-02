package agent

// actionOutput keeps draining a process after a long line or output limit. Using
// exec's copy goroutines also lets WaitDelay bound inherited pipes after exit.
type actionOutput struct {
	emit func(string)
	line []byte
	used int
	long bool
}

func (w *actionOutput) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' || b == '\r' {
			w.flush()
			continue
		}
		if w.used >= 10_000_000 || w.long {
			continue
		}
		if len(w.line) >= 65536 {
			w.line = nil
			w.long = true
			continue
		}
		w.line = append(w.line, b)
	}
	return len(p), nil
}

func (w *actionOutput) flush() {
	if w.long {
		// Do not expose a partial secret at an arbitrary long-line boundary.
		if w.used < 10_000_000 {
			w.emit("[Output line omitted: exceeded 64 KB; subsequent output retained]")
			w.used += 320
			if w.used >= 10_000_000 {
				w.emit("[Output truncated after 10 MB]")
			}
		}
	} else if len(w.line) > 0 && w.used < 10_000_000 {
		w.emit(string(w.line))
		w.used += len(w.line) + 256
		if w.used >= 10_000_000 {
			w.emit("[Output truncated after 10 MB]")
		}
	}
	w.line = w.line[:0]
	w.long = false
}
