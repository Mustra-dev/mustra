package server

import (
	"strings"
	"unicode/utf8"
)

// safeTruncate caps a string at n bytes without splitting a rune.
//
// This exists because the same bug has now been fixed five times in five
// places. Slicing a string by byte offset can cut through a multi-byte
// character, and Postgres refuses invalid UTF-8 in a text column — so the
// write fails, every call site only logs the error, and the row stays open
// for ever: an install that finished renders as running and then stalled.
// Installer output is exactly where this bites, because apt and winget
// progress bars, box-drawing characters and localized Windows text put
// non-ASCII near any cut.
//
// One implementation, used everywhere, rather than a sixth site to miss.
func safeTruncate(s string, n int) string {
	// Invalid UTF-8 anywhere in the string — not only at a truncation
	// boundary — makes the Postgres write fail. Command output, an SSH
	// transcript and an HTTP response body all reach here as raw bytes that
	// were never decoded through JSON, so a short value with an interior
	// invalid byte would otherwise be returned untouched and stall the row.
	// Coerce first, so the result is always storable and the cut below only
	// ever has to guard against splitting a rune at the boundary.
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "\n… (truncated)"
}
