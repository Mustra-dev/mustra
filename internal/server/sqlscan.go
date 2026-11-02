package server

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Screening a plain-format SQL dump before psql sees it.
//
// psql is not a SQL interpreter, it is a shell: a backslash outside a
// quoted string starts a meta-command, and \! runs a program, \copy …
// program runs one with the client's rights, \o |cmd pipes output to one,
// \i reads another file. Any of them in an uploaded "backup" is code
// execution in the server container. On the database side, COPY … PROGRAM
// runs a program as the Postgres server (the compose role is a superuser).
//
// scanDump lexes the dump the way psql does — single-quoted, E'' and
// dollar-quoted strings, quoted identifiers, -- and nested /* */ comments,
// and COPY … FROM stdin data blocks — and refuses:
//
//   - any backslash outside a string, comment or COPY data, except the two
//     lines pg_dump itself writes (\restrict KEY and \unrestrict KEY, from
//     PostgreSQL 17.6 / 16.10 on);
//   - COPY that reads or writes anything but stdin/stdout, including
//     COPY … PROGRAM.
//
// strict (used for archives this server did not sign) also refuses
// statements a mustra dump never contains and that hand the database's
// own powers to whoever wrote the file: functions, procedures, DO blocks,
// triggers, rules, languages, roles, ALTER SYSTEM, extensions, and the
// server-file functions.

var (
	allowedMetaLine = regexp.MustCompile(`^\\(restrict|unrestrict) [A-Za-z0-9]+\s*$`)
	copyAny         = regexp.MustCompile(`(?is)^\s*COPY\b`)
	// A COPY is inert only when it streams through the client: it ends in
	// FROM stdin (load) or TO stdout (dump) and names neither PROGRAM nor a
	// server file. Matched on the normalized statement, where string
	// literals are a placeholder, so a column, alias or WHERE clause named
	// "stdin" after a FROM PROGRAM cannot stand in for the real target
	// (the "COPY … FROM PROGRAM 'id' WHERE stdin …" bypass).
	copyClientStream  = regexp.MustCompile(`(?is)^\s*COPY\b.*\bFROM\s+STDIN\s*(WITH\b[^;]*)?;?\s*$|^\s*COPY\b.*\bTO\s+STDOUT\s*(WITH\b[^;]*)?;?\s*$`)
	copyProgramOrFile = regexp.MustCompile(`(?is)\bPROGRAM\b|\b(FROM|TO)\s+'`)
	// psql's lexer follows standard_conforming_strings: turned off, a
	// backslash escapes a quote inside '…', and this scanner's idea of where
	// a string ends would part company with psql's. pg_dump only ever
	// writes it on.
	conformingStrings   = regexp.MustCompile(`(?i)standard_conforming_strings`)
	conformingStringsOn = regexp.MustCompile(`(?i)^\s*SET\s+standard_conforming_strings\s*(=|TO)\s*'?on'?\s*;?\s*$`)
	// unicodeEscape is a U&'…' string or U&"…" identifier in the normalized
	// statement (where the quoted part is already a placeholder or word).
	// Its escapes can spell any name; pg_dump never writes one.
	unicodeEscape = regexp.MustCompile(`(?i)\bU&\s`)
	strictDenied  = regexp.MustCompile(`(?is)(^\s*DO\b|\bCREATE\s+(OR\s+REPLACE\s+)?(FUNCTION|PROCEDURE|TRIGGER|EVENT\s+TRIGGER|RULE|AGGREGATE|OPERATOR|CAST|(TRUSTED\s+)?(PROCEDURAL\s+)?LANGUAGE|EXTENSION|ROLE|USER|SERVER|FOREIGN|SUBSCRIPTION|PUBLICATION)\b|\bALTER\s+(SYSTEM|ROLE|USER|EXTENSION|LANGUAGE)\b|\bSECURITY\s+DEFINER\b|\b(lo_import|lo_export|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_stat_file|dblink\w*|pg_execute_server_program|pg_write_server_files|pg_read_server_files)\b|\bLOAD\s+'|\bSET\s+(SESSION\s+)?(ROLE|SESSION\s+AUTHORIZATION)\b)`)
)

// scanDump returns nil when the dump is safe to hand to psql.
func scanDump(r io.Reader, strict bool) error {
	br := bufio.NewReaderSize(r, 1<<16)
	var (
		stmt strings.Builder // current statement, each comment replaced by a space
		// norm is the same statement as psql's lexer tokenizes it: every
		// string literal is the placeholder 'S', a quoted identifier is its
		// bare (upper-cased) name, and comments are spaces. The keyword
		// screens run over it, so neither a comment ("COPY/**/t") nor
		// quoting can hide or join tokens.
		norm      strings.Builder
		identBuf  strings.Builder // contents of the current "…" identifier
		inCopy    bool
		lineNo    int
		dollarTag string // inside $tag$ … $tag$ when non-empty
		quote     byte   // ' or " when inside one
		eString   bool   // inside E'…', where backslash escapes
		block     int    // /* */ nesting depth
	)
	finish := func() error {
		text := strings.TrimSpace(stmt.String())
		normText := strings.ToUpper(strings.TrimSpace(norm.String()))
		stmt.Reset()
		norm.Reset()
		if text == "" {
			return nil
		}
		if conformingStrings.MatchString(text) && !conformingStringsOn.MatchString(text) {
			return fmt.Errorf("line %d: changing standard_conforming_strings is not allowed in a restore", lineNo)
		}
		if copyAny.MatchString(text) || copyAny.MatchString(normText) {
			if copyProgramOrFile.MatchString(normText) || !copyClientStream.MatchString(normText) {
				return fmt.Errorf("line %d: COPY that does not stream through stdin/stdout (COPY … PROGRAM or a server file) is not allowed", lineNo)
			}
			inCopy = true
		}
		if strict && unicodeEscape.MatchString(normText) {
			return fmt.Errorf("line %d: U& escapes are not something a mustra backup contains; refusing the external import", lineNo)
		}
		if strict && (strictDenied.MatchString(text) || strictDenied.MatchString(normText)) {
			m := strictDenied.FindString(normText)
			if m == "" {
				m = strictDenied.FindString(text)
			}
			return fmt.Errorf("line %d: %q is not something a mustra backup contains; refusing the external import", lineNo, strings.TrimSpace(m))
		}
		return nil
	}
	for {
		line, err := br.ReadString('\n')
		if line == "" && err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		lineNo++
		if inCopy {
			// COPY data: one row per line, until \. on its own. Its
			// backslashes are escapes inside the data, not meta-commands.
			if strings.TrimRight(line, "\r\n") == `\.` {
				inCopy = false
			}
			if err == io.EOF {
				break
			}
			continue
		}
		atLineStart := quote == 0 && dollarTag == "" && block == 0 && strings.TrimSpace(stmt.String()) == ""
		if atLineStart && strings.HasPrefix(line, `\`) {
			if allowedMetaLine.MatchString(strings.TrimRight(line, "\r\n")) {
				continue
			}
			return fmt.Errorf("line %d: psql meta-command %q is not allowed in a restore", lineNo, firstWord(line))
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			switch {
			case block > 0:
				if c == '*' && i+1 < len(line) && line[i+1] == '/' {
					block--
					i++
				} else if c == '/' && i+1 < len(line) && line[i+1] == '*' {
					block++
					i++
				}
				continue
			case dollarTag != "":
				if c == '$' && strings.HasPrefix(line[i:], dollarTag) {
					stmt.WriteString(dollarTag)
					norm.WriteString(" 'S' ")
					i += len(dollarTag) - 1
					dollarTag = ""
					continue
				}
				stmt.WriteByte(c)
				continue
			case quote != 0:
				stmt.WriteByte(c)
				if eString && c == '\\' && i+1 < len(line) {
					stmt.WriteByte(line[i+1])
					i++
					continue
				}
				if c == quote {
					if i+1 < len(line) && line[i+1] == quote { // doubled quote
						stmt.WriteByte(line[i+1])
						if quote == '"' {
							identBuf.WriteByte('"')
						}
						i++
						continue
					}
					if quote == '"' {
						// The identifier as a word of its own: a quoted
						// "pg_read_file" calls the same function.
						norm.WriteString(" " + identBuf.String() + " ")
						identBuf.Reset()
					} else {
						norm.WriteString(" 'S' ")
					}
					quote, eString = 0, false
					continue
				}
				if quote == '"' {
					identBuf.WriteByte(c)
				}
				continue
			}
			switch {
			case c == '-' && i+1 < len(line) && line[i+1] == '-':
				// The rest of the line, newline included, is a comment —
				// and, to the server's lexer, whitespace between tokens.
				stmt.WriteByte(' ')
				norm.WriteByte(' ')
				i = len(line)
			case c == '/' && i+1 < len(line) && line[i+1] == '*':
				// A comment separates tokens; dropping it would join
				// COPY/**/t into one word the screens never see.
				stmt.WriteByte(' ')
				norm.WriteByte(' ')
				block++
				i++
			case c == '\'':
				eString = i > 0 && (line[i-1] == 'E' || line[i-1] == 'e') && (i < 2 || !isIdentByte(line[i-2]))
				quote = '\''
				stmt.WriteByte(c)
				if eString {
					// The E prefix was copied as a word character; it
					// belongs to the literal.
					trimLastByte(&norm)
				}
				norm.WriteByte(' ')
			case c == '"':
				quote = '"'
				stmt.WriteByte(c)
				norm.WriteByte(' ')
			case c == '$':
				if tag := dollarQuoteTag(line[i:]); tag != "" && (i == 0 || !isIdentByte(line[i-1])) {
					dollarTag = tag
					stmt.WriteString(tag)
					norm.WriteByte(' ')
					i += len(tag) - 1
				} else {
					stmt.WriteByte(c)
					norm.WriteByte(c)
				}
			case c == '\\':
				return fmt.Errorf("line %d: a backslash outside a string starts a psql meta-command; refusing the restore", lineNo)
			case c == ';':
				stmt.WriteByte(c)
				norm.WriteByte(c)
				if err := finish(); err != nil {
					return err
				}
			default:
				stmt.WriteByte(c)
				norm.WriteByte(c)
			}
		}
		if err == io.EOF {
			break
		}
	}
	if quote != 0 || dollarTag != "" || block > 0 {
		return fmt.Errorf("the dump ends inside a string or comment")
	}
	return finish()
}

// trimLastByte drops the last byte written to b.
func trimLastByte(b *strings.Builder) {
	s := b.String()
	if s == "" {
		return
	}
	b.Reset()
	b.WriteString(s[:len(s)-1])
}

func isIdentByte(c byte) bool {
	return c == '_' || c == '$' || c >= 0x80 ||
		c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// dollarQuoteTag returns "$tag$" when s starts with a dollar-quote opener.
func dollarQuoteTag(s string) string {
	if len(s) < 2 || s[0] != '$' {
		return ""
	}
	for j := 1; j < len(s); j++ {
		if s[j] == '$' {
			return s[:j+1]
		}
		if !isIdentByte(s[j]) || (j == 1 && s[j] >= '0' && s[j] <= '9') {
			return ""
		}
	}
	return ""
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i > 0 {
		return s[:i]
	}
	return s
}
