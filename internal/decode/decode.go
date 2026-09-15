// Package decode turns raw TCP and UDP byte streams into readable messages. Decoders are
// stateful: a stream arrives in arbitrary chunks, so each one buffers until it holds a whole
// protocol message.
package decode

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type Stream interface {
	Feed(b []byte) []string
}

// Frame is one complete protocol message located in a byte stream. Bytes are the exact wire bytes
// of the message — a sub-slice of the buffer passed to Frame, valid only until the next call, so a
// caller that keeps them past that (to park or replay) must copy first.
type Frame struct {
	Bytes    []byte
	Text     string // the rendered display, identical to what Feed produces for this message
	Kind     string // the message-type label, e.g. "Query", "Bind", "ErrorResponse"
	Holdable bool   // whether this message carries intent worth pausing for a verdict
}

// Framer is a decoder that can locate message boundaries, so the relay can hold, drop, edit or
// answer individual messages rather than only watch them. Not every stream can be framed — the raw
// fallback cannot, and a decodable stream stops being one the moment it upgrades to TLS.
type Framer interface {
	// Frame parses complete messages from the front of buf. The caller owns buf and retains
	// whatever is left after `consumed`. ok is false once the stream is no longer decodable (a
	// TLS upgrade, or a desync): the frames and consumed up to that point are still valid, and
	// the caller must pass everything after them through untouched.
	Frame(buf []byte) (frames []Frame, consumed int, ok bool)
}

// ProtoError is a synthetic error used to answer a held database request locally, instead of
// letting it reach the server. The fields are protocol-shaped: Code is a SQLSTATE for Postgres.
type ProtoError struct {
	Code     string
	Message  string
	Severity string
}

// SynthError builds the wire bytes that answer a held client message of kind `kind` with an error,
// so the application's driver sees a real protocol error and the request never reaches the server.
// awaitTerminator is true when answering is a multi-step exchange (the Postgres extended protocol):
// the caller must then swallow client messages until ExchangeTerminator reports one, and send
// TerminatorReply in response. reply is nil when this protocol cannot be answered this way.
func SynthError(proto, kind string, e ProtoError) (reply []byte, awaitTerminator bool) {
	switch proto {
	case "postgres":
		return pgSynthError(kind, e)
	}
	return nil, false
}

// ExchangeTerminator reports whether a message of this kind ends a request exchange that SynthError
// left open — the Postgres client's Sync. It is only meaningful when SynthError returned
// awaitTerminator.
func ExchangeTerminator(proto, kind string) bool {
	return proto == "postgres" && kind == "Sync"
}

// TerminatorReply is what to send the client once ExchangeTerminator is seen: Postgres ReadyForQuery.
func TerminatorReply(proto string) []byte {
	if proto == "postgres" {
		return pgReadyForQuery()
	}
	return nil
}

// QueryText returns the SQL a held message carries, or "" if it carries no single statement (a
// Bind or an Execute), so a UI can offer the statement for editing rather than the raw wire bytes.
func QueryText(proto, kind string, msg []byte) string {
	if proto == "postgres" {
		return pgQueryText(kind, msg)
	}
	return ""
}

// RewriteQuery rebuilds a held message around new SQL, keeping everything else about it intact. ok
// is false when the protocol or message has no single statement to rewrite, and the caller should
// fall back to replacing the raw bytes.
func RewriteQuery(proto, kind string, msg []byte, sql string) (out []byte, ok bool) {
	if proto == "postgres" {
		return pgRewriteQuery(kind, msg, sql)
	}
	return nil, false
}

// RowValues returns a held result row's column values (nil for SQL NULL), so a UI can offer each
// column for editing. ok is false when the message is not a row this protocol can pick apart.
func RowValues(proto, kind string, msg []byte) (vals []*string, ok bool) {
	if proto == "postgres" {
		return pgRowValues(kind, msg)
	}
	return nil, false
}

// RewriteRow rebuilds a result row from edited column values, a nil entry meaning SQL NULL.
func RewriteRow(proto, kind string, msg []byte, vals []*string) (out []byte, ok bool) {
	if proto == "postgres" {
		return pgRewriteRow(kind, vals)
	}
	return nil, false
}

// firstToken is the leading word of a rendered message, which the decoders make the message-type
// name ("Query select …" -> "Query"). It is what classifies a frame for holding and display.
func firstToken(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

// Codec decodes both directions of one connection.
//
// Which protocol it is may not be known when the connection opens: MySQL's server speaks first,
// and a database on an unexpected port gives nothing away until bytes flow. So a Codec is
// created immediately and decides later, from whichever side speaks first.
type Codec struct {
	Client Stream
	Server Stream

	r *resolver
}

// Protocol is what the connection turned out to be speaking. It is "raw" until enough has
// arrived to tell, so a caller labelling a flow should read it again as messages appear.
func (c *Codec) Protocol() string {
	if c.r == nil {
		return "raw"
	}
	return c.r.Protocol()
}

// Sniff prepares a codec for a connection to the given port, with whatever the client has sent
// so far — often nothing.
//
// The port is a hint, not an answer. Databases run on whatever port compose mapped them to, and a
// decoder chosen by port alone renders most real traffic as unreadable bytes. What the two sides
// actually send decides it; see sniff.go.
func Sniff(port int, first []byte) *Codec {
	r := &resolver{port: port}
	c := &Codec{r: r}
	c.Client = &side{r: r}
	c.Server = &side{r: r, server: true}
	// The port alone may settle it, and if not, whatever the client has already sent might.
	r.mu.Lock()
	r.hold(false, first)
	r.decide()
	r.heldClient = nil // the relay feeds these bytes again as it reads them
	r.mu.Unlock()
	return c
}

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

// be32le reads a little-endian int32, which is what MongoDB and MySQL use on the wire.
func be32le(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func be64(b []byte) uint64 {
	var v uint64
	for _, c := range b[:8] {
		v = v<<8 | uint64(c)
	}
	return v
}

// cstring reads one NUL-terminated string and returns what follows it.
func cstring(b []byte) (string, []byte, bool) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:], true
		}
	}
	return "", nil, false
}

// cstrings reads every printable NUL-terminated string in a payload.
func cstrings(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			if i > start {
				if s := string(b[start:i]); printable(s) {
					out = append(out, s)
				}
			}
			start = i + 1
		}
	}
	return out
}

// readInt16s reads a length-prefixed array of int16s.
func readInt16s(b []byte) ([]int16, []byte, bool) {
	if len(b) < 2 {
		return nil, b, false
	}
	n := int(be16(b))
	b = b[2:]
	if len(b) < n*2 {
		return nil, b, false
	}
	out := make([]int16, n)
	for i := range out {
		out[i] = int16(be16(b[i*2:]))
	}
	return out, b[n*2:], true
}

func trimZero(b []byte) string { return strings.TrimRight(string(b), "\x00") }

func clipBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// clip shortens a rendered value. These end up on one line beside a timestamp, so a megabyte of
// JSON in a bound parameter has to become something a person can still read past.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("… (%d bytes)", len(s))
}

// sql collapses a statement onto one line. Drivers send queries formatted across many lines, and
// a flow list is not the place for that.
func sql(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return `""`
	}
	fields := strings.Fields(q)
	return clip(strconv.Quote(strings.Join(fields, " ")), 160)
}

func quote(s string) string {
	if s == "" {
		return `""`
	}
	for _, r := range s {
		if !unicode.IsPrint(r) && r != '\n' && r != '\t' {
			return fmt.Sprintf("<%d bytes>", len(s))
		}
	}
	if strings.ContainsAny(s, " \t\"") {
		return strconv.Quote(s)
	}
	return s
}

func printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return s != ""
}

// raw is the fallback for a stream nothing recognised.
type raw struct{}

func (raw) Feed(b []byte) []string {
	s := strings.TrimRight(string(b), "\r\n\x00")
	if printable(s) && s != "" {
		return []string{s}
	}
	return []string{fmt.Sprintf("<%d bytes>", len(b))}
}

// DNS renders a UDP DNS message as its question, which is the part worth reading.
func DNS(b []byte) string {
	if len(b) < 12 {
		return ""
	}
	qd := int(b[4])<<8 | int(b[5])
	an := int(b[6])<<8 | int(b[7])
	if qd == 0 {
		return ""
	}
	i, labels := 12, []string{}
	for i < len(b) {
		n := int(b[i])
		if n == 0 {
			i++
			break
		}
		if n&0xC0 != 0 || i+1+n > len(b) {
			return ""
		}
		labels = append(labels, string(b[i+1:i+1+n]))
		i += 1 + n
	}
	if i+4 > len(b) {
		return ""
	}
	qtype := int(b[i])<<8 | int(b[i+1])
	name := strings.Join(labels, ".")
	types := map[int]string{1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
	t, ok := types[qtype]
	if !ok {
		t = strconv.Itoa(qtype)
	}
	if b[2]&0x80 != 0 {
		return fmt.Sprintf("%s %s → %d answer(s)", t, name, an)
	}
	return fmt.Sprintf("%s %s?", t, name)
}
