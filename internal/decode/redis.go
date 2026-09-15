package decode

import (
	"strconv"
	"strings"
)

// RESP, both versions.
//
// RESP2 has five types and RESP3 adds nine more, which matters because every recent client
// negotiates RESP3 with HELLO at connect time. A decoder that only knows RESP2 stops producing
// anything the moment a server answers with a map or a set — it does not fail loudly, it simply
// falls silent, which is the worst way for this to be wrong.
type resp struct{ buf []byte }

func (r *resp) Feed(b []byte) []string {
	r.buf = append(r.buf, b...)
	var out []string
	for {
		s, n := parseRESP(r.buf, 0)
		if n == 0 {
			break
		}
		r.buf = r.buf[n:]
		if s != "" {
			out = append(out, s)
		}
	}
	if len(r.buf) > 1<<20 {
		r.buf = nil
	}
	return out
}

// parseRESP returns the rendered value and how many bytes it consumed, or 0 if incomplete.
//
// depth bounds the recursion: a reply can nest arbitrarily, and a malformed or hostile stream
// should not be able to walk the stack down.
func parseRESP(b []byte, depth int) (string, int) {
	if len(b) == 0 || depth > 8 {
		return "", 0
	}
	line, n := readLine(b)
	if n == 0 {
		return "", 0
	}
	switch b[0] {
	case '+': // simple string
		return line[1:], n
	case '-': // error
		return "(error) " + line[1:], n
	case ':': // integer
		return line[1:], n
	case ',': // RESP3 double
		return line[1:], n
	case '(': // RESP3 big number
		return line[1:], n
	case '#': // RESP3 boolean
		if line == "#t" {
			return "true", n
		}
		return "false", n
	case '_': // RESP3 null
		return "(nil)", n
	case '$', '=': // bulk string, RESP3 verbatim string
		size, err := strconv.Atoi(line[1:])
		if err != nil {
			return "", 0
		}
		if size < 0 {
			return "(nil)", n
		}
		if len(b) < n+size+2 {
			return "", 0
		}
		s := string(b[n : n+size])
		// A verbatim string carries a three-letter format and a colon before its content.
		if b[0] == '=' && len(s) > 4 {
			s = s[4:]
		}
		return clip(quote(s), 120), n + size + 2
	case '!': // RESP3 bulk error
		size, err := strconv.Atoi(line[1:])
		if err != nil || size < 0 || len(b) < n+size+2 {
			return "", 0
		}
		return "(error) " + string(b[n:n+size]), n + size + 2
	case '*', '~', '>': // array, RESP3 set, RESP3 push
		return parseAggregate(b, line, n, depth, 1)
	case '%': // RESP3 map: the count is of pairs
		return parseAggregate(b, line, n, depth, 2)
	}
	// An inline command: redis-cli and telnet send bare text, and so do health checks.
	if fields := strings.Fields(line); len(fields) > 0 && printable(line) {
		return strings.Join(fields, " "), n
	}
	return "", 0
}

func parseAggregate(b []byte, line string, n, depth, per int) (string, int) {
	count, err := strconv.Atoi(line[1:])
	if err != nil {
		return "", 0
	}
	if count < 0 {
		return "(nil)", n
	}
	off := n
	parts := make([]string, 0, count*per)
	for i := 0; i < count*per; i++ {
		s, used := parseRESP(b[off:], depth+1)
		if used == 0 {
			return "", 0
		}
		parts = append(parts, s)
		off += used
	}
	if len(parts) == 0 {
		return "(empty)", off
	}
	// A command is a flat array and reads best as a command line; anything nested or keyed
	// reads better bracketed.
	sep := " "
	if b[0] != '*' || per != 1 {
		sep = ", "
	}
	joined := strings.Join(parts, sep)
	if b[0] == '*' && per == 1 {
		return clip(joined, 200), off
	}
	return clip("["+joined+"]", 200), off
}

func readLine(b []byte) (string, int) {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return string(b[:i]), i + 2
		}
	}
	// An inline command may end with a bare newline.
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			return string(b[:i]), i + 1
		}
		if i > 512 {
			break
		}
	}
	return "", 0
}
