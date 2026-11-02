package server

import (
	"encoding/csv"
	"io"
)

// CSV exports are opened in spreadsheets, and a spreadsheet treats a cell
// beginning with = + - @ (or a tab or carriage return before one) as a
// formula. Agent-reported values — hostnames, software names, log levels —
// end up in these cells, so an endpoint could otherwise plant
// =HYPERLINK(...) or a DDE payload in an operator's export. Such cells are
// prefixed with a single quote, which spreadsheets show as text.

type safeCSVWriter struct{ *csv.Writer }

func newSafeCSVWriter(w io.Writer) *safeCSVWriter { return &safeCSVWriter{csv.NewWriter(w)} }

func (w *safeCSVWriter) Write(rec []string) error {
	out := make([]string, len(rec))
	for i, c := range rec {
		out[i] = csvCell(c)
	}
	return w.Writer.Write(out)
}

func csvCell(c string) string {
	if c == "" {
		return c
	}
	switch c[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + c
	}
	return c
}
