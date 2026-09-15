package decode

import (
	"fmt"
	"strconv"
	"strings"
)

// MongoDB's wire protocol.
//
// Everything a modern driver sends is OP_MSG carrying one BSON document, and the first key of
// that document is the command — find, insert, update, aggregate. Reading just that key and the
// collection it names turns an opaque binary stream into something recognisable, which is most
// of the value; the full document is a nested structure that does not belong on one line.
const (
	opReply = 1
	opQuery = 2004
	opMsg   = 2013
)

type mongo struct {
	buf    []byte
	client bool
}

func (m *mongo) Feed(b []byte) []string {
	m.buf = append(m.buf, b...)
	var out []string
	for {
		text, _, n, ok := m.parseOne(m.buf)
		if !ok {
			// Not a length this protocol produces; the stream is not what was assumed.
			m.buf = nil
			break
		}
		if n == 0 {
			break
		}
		m.buf = m.buf[n:]
		if text != "" {
			out = append(out, text)
		}
	}
	if len(m.buf) > 48<<20 {
		m.buf = nil
	}
	return out
}

// Frame parses complete MongoDB messages from the front of buf, which the caller owns, so a command
// can be held on its way through.
func (m *mongo) Frame(buf []byte) (frames []Frame, consumed int, ok bool) {
	for {
		text, kind, n, good := m.parseOne(buf[consumed:])
		if !good {
			return frames, consumed, false
		}
		if n == 0 {
			return frames, consumed, true
		}
		frames = append(frames, Frame{
			Bytes: buf[consumed : consumed+n], Text: text, Kind: kind, Holdable: m.holdable(kind),
		})
		consumed += n
	}
}

// parseOne reads one MongoDB message from the front of buf. ok is false when the length prefix is
// not one this protocol produces, which means the stream desynced or was never MongoDB.
func (m *mongo) parseOne(buf []byte) (text, kind string, n int, ok bool) {
	if len(buf) < 16 {
		return "", "", 0, true
	}
	ln := int(int32(be32le(buf)))
	if ln < 16 || ln > 48<<20 {
		return "", "", 0, false
	}
	if len(buf) < ln {
		return "", "", 0, true
	}
	text = m.render(buf[:ln])
	return text, firstToken(text), ln, true
}

// holdable pauses a client command; replies and everything else pass through.
func (m *mongo) holdable(kind string) bool { return m.client && kind == "OP_MSG" }

func (m *mongo) render(msg []byte) string {
	switch op := be32le(msg[12:]); op {
	case opMsg:
		return m.renderMsg(msg)
	case opQuery:
		return m.renderQuery(msg)
	case opReply:
		return "Reply"
	default:
		return fmt.Sprintf("opcode %d (%d bytes)", op, len(msg))
	}
}

// renderMsg reads OP_MSG, which is one flag word followed by sections. Section kind 0 holds the
// command document; kind 1 holds a named sequence of documents, which is how a bulk insert
// carries its rows.
func (m *mongo) renderMsg(msg []byte) string {
	body := msg[16:]
	if len(body) < 4 {
		return "OP_MSG"
	}
	body = body[4:] // flagBits
	for len(body) > 0 {
		kind := body[0]
		body = body[1:]
		if kind != 0 {
			// A document sequence: its name is the field the documents belong to.
			if name, _, ok := cstring(skipLen(body)); ok {
				return "OP_MSG " + name
			}
			return "OP_MSG"
		}
		if len(body) < 4 {
			break
		}
		size := int(int32(be32le(body)))
		if size < 5 || size > len(body) {
			break
		}
		return "OP_MSG " + bsonSummary(body[:size])
	}
	return "OP_MSG"
}

func skipLen(b []byte) []byte {
	if len(b) < 4 {
		return b
	}
	return b[4:]
}

func (m *mongo) renderQuery(msg []byte) string {
	body := msg[16:]
	if len(body) < 4 {
		return "OP_QUERY"
	}
	coll, rest, ok := cstring(body[4:])
	if !ok || len(rest) < 8 {
		return "OP_QUERY"
	}
	rest = rest[8:] // numberToSkip, numberToReturn
	if len(rest) >= 4 {
		if size := int(int32(be32le(rest))); size >= 5 && size <= len(rest) {
			return "OP_QUERY " + coll + " " + bsonSummary(rest[:size])
		}
	}
	return "OP_QUERY " + coll
}

// bsonSummary renders the command and the arguments worth reading from a BSON document.
//
// The first key of a command document is the command itself and its value is the collection —
// {find: "orders", filter: {...}} — so those two plus a handful of well-known fields say what
// the operation was against what, which is the question being asked of a flow list.
func bsonSummary(doc []byte) string {
	fields := bsonTopLevel(doc)
	if len(fields) == 0 {
		return "(document)"
	}
	var b strings.Builder
	b.WriteString(fields[0].key)
	if fields[0].val != "" {
		b.WriteString(" ")
		b.WriteString(fields[0].val)
	}
	for _, f := range fields[1:] {
		switch f.key {
		case "$db", "filter", "limit", "sort", "pipeline", "documents", "updates", "deletes",
			"key", "query", "ordered", "batchSize":
			if f.val != "" {
				fmt.Fprintf(&b, " %s=%s", f.key, f.val)
			}
		}
	}
	return clip(b.String(), 160)
}

type bsonField struct{ key, val string }

// bsonTopLevel walks a BSON document one level deep. Nested documents and arrays are reported by
// shape rather than descended into: the aim is a line someone can scan, not a dump.
func bsonTopLevel(doc []byte) []bsonField {
	if len(doc) < 5 {
		return nil
	}
	b := doc[4 : len(doc)-1] // length prefix and trailing NUL
	var out []bsonField
	for len(b) > 1 {
		t := b[0]
		name, rest, ok := cstring(b[1:])
		if !ok {
			break
		}
		val, next, ok := bsonValue(t, rest)
		if !ok {
			break
		}
		out = append(out, bsonField{key: name, val: val})
		b = next
		if len(out) > 24 {
			break
		}
	}
	return out
}

// bsonValue renders one value and returns what follows it.
func bsonValue(t byte, b []byte) (string, []byte, bool) {
	switch t {
	case 0x01: // double
		if len(b) < 8 {
			return "", nil, false
		}
		return "", b[8:], true
	case 0x02: // string
		if len(b) < 4 {
			return "", nil, false
		}
		n := int(int32(be32le(b)))
		if n < 1 || 4+n > len(b) {
			return "", nil, false
		}
		return quote(strings.TrimRight(string(b[4:4+n]), "\x00")), b[4+n:], true
	case 0x03, 0x04: // embedded document, array
		if len(b) < 4 {
			return "", nil, false
		}
		n := int(int32(be32le(b)))
		if n < 5 || n > len(b) {
			return "", nil, false
		}
		if t == 0x04 {
			return fmt.Sprintf("[%d]", len(bsonTopLevel(b[:n]))), b[n:], true
		}
		return "{…}", b[n:], true
	case 0x05: // binary
		if len(b) < 5 {
			return "", nil, false
		}
		n := int(int32(be32le(b)))
		if n < 0 || 5+n > len(b) {
			return "", nil, false
		}
		return fmt.Sprintf("<%d bytes>", n), b[5+n:], true
	case 0x07: // ObjectId
		if len(b) < 12 {
			return "", nil, false
		}
		return fmt.Sprintf("%x", b[:12]), b[12:], true
	case 0x08: // boolean
		if len(b) < 1 {
			return "", nil, false
		}
		if b[0] == 0 {
			return "false", b[1:], true
		}
		return "true", b[1:], true
	case 0x09, 0x11, 0x12: // datetime, timestamp, int64
		if len(b) < 8 {
			return "", nil, false
		}
		if t == 0x12 {
			var v int64
			for i := 7; i >= 0; i-- {
				v = v<<8 | int64(b[i])
			}
			return strconv.FormatInt(v, 10), b[8:], true
		}
		return "", b[8:], true
	case 0x0a: // null
		return "null", b, true
	case 0x10: // int32
		if len(b) < 4 {
			return "", nil, false
		}
		return strconv.Itoa(int(int32(be32le(b)))), b[4:], true
	case 0x06, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x13, 0xff, 0x7f:
		// Deprecated or rare types whose length cannot be skipped reliably; stop rather than
		// walk off the end of a document and invent fields.
		return "", nil, false
	}
	return "", nil, false
}
