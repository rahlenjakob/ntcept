package decode

import (
	"encoding/binary"
	"strings"
	"testing"
)

// pgMsg builds one backend/frontend message: type byte, int32 length, payload.
func pgMsg(typ byte, payload []byte) []byte {
	out := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)+4))
	return append(out, payload...)
}

func i16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }
func i32(v int) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(v))
	return b
}
func cstr(s string) []byte { return append([]byte(s), 0) }

// The extended query protocol is what drivers and ORMs actually use: the statement is parsed
// once with placeholders and the values arrive separately. A decoder that renders Bind as "Bind"
// shows everything except the part anyone is looking for.
func TestPostgresExtendedQueryShowsBoundValues(t *testing.T) {
	c := &pg{client: true, started: true}

	parse := append(cstr(""), cstr("select * from orders where email = $1 and total > $2")...)
	parse = append(parse, i16(0)...)
	if got := c.Feed(pgMsg('P', parse)); len(got) != 1 ||
		!strings.Contains(got[0], "select * from orders where email = $1") {
		t.Fatalf("Parse not rendered: %q", got)
	}

	// Bind: portal "", statement "", one text format, two parameters.
	bind := append(cstr(""), cstr("")...)
	bind = append(bind, i16(1)...)
	bind = append(bind, i16(0)...) // text format
	bind = append(bind, i16(2)...)
	bind = append(bind, i32(len("a@b.com"))...)
	bind = append(bind, "a@b.com"...)
	bind = append(bind, i32(2)...)
	bind = append(bind, "42"...)

	got := c.Feed(pgMsg('B', bind))
	if len(got) != 1 {
		t.Fatalf("expected one message, got %q", got)
	}
	// The values are the point, and the statement they fill in gives them meaning.
	for _, want := range []string{"$1=a@b.com", "$2=42", "select * from orders"} {
		if !strings.Contains(got[0], want) {
			t.Fatalf("Bind should carry %q: %s", want, got[0])
		}
	}
}

// A NULL parameter is a different thing from an empty one, and confusing them is how a query
// that returns nothing becomes a mystery.
func TestPostgresBindDistinguishesNullFromEmpty(t *testing.T) {
	c := &pg{client: true, started: true}
	bind := append(cstr(""), cstr("")...)
	bind = append(bind, i16(0)...) // no format codes: everything is text
	bind = append(bind, i16(2)...)
	bind = append(bind, i32(-1)...) // NULL
	bind = append(bind, i32(0)...)  // empty string
	got := c.Feed(pgMsg('B', bind))
	if len(got) != 1 || !strings.Contains(got[0], "$1=NULL") || !strings.Contains(got[0], `$2=""`) {
		t.Fatalf("NULL and empty must be told apart: %q", got)
	}
}

// Binary parameters are what a driver sends for integers and timestamps.
func TestPostgresBindReadsBinaryIntegers(t *testing.T) {
	c := &pg{client: true, started: true}
	bind := append(cstr(""), cstr("")...)
	bind = append(bind, i16(1)...)
	bind = append(bind, i16(1)...) // binary
	bind = append(bind, i16(1)...)
	bind = append(bind, i32(4)...)
	bind = append(bind, i32(4471)...)
	got := c.Feed(pgMsg('B', bind))
	if len(got) != 1 || !strings.Contains(got[0], "$1=4471") {
		t.Fatalf("a binary int4 should read as a number: %q", got)
	}
}

// An error is the thing most worth reading, and postgres sends it as a set of tagged fields
// rather than a sentence.
func TestPostgresErrorIsReadable(t *testing.T) {
	var payload []byte
	for _, f := range []struct {
		tag  byte
		text string
	}{
		{'S', "ERROR"}, {'V', "ERROR"}, {'C', "23505"},
		{'M', `duplicate key value violates unique constraint "orders_pkey"`},
		{'D', "Key (id)=(4471) already exists."},
		{'F', "nbtinsert.c"}, {'L', "664"}, {'R', "_bt_check_unique"},
	} {
		payload = append(payload, f.tag)
		payload = append(payload, cstr(f.text)...)
	}
	payload = append(payload, 0)

	got := (&pg{}).Feed(pgMsg('E', payload))
	if len(got) != 1 {
		t.Fatalf("expected one message, got %q", got)
	}
	for _, want := range []string{"ERROR", "23505", "duplicate key value", "Key (id)=(4471)"} {
		if !strings.Contains(got[0], want) {
			t.Fatalf("error should carry %q: %s", want, got[0])
		}
	}
	// postgres's own source file and line are about postgres, not about the application.
	for _, noise := range []string{"nbtinsert.c", "_bt_check_unique"} {
		if strings.Contains(got[0], noise) {
			t.Errorf("error should not carry %q: %s", noise, got[0])
		}
	}
}

func TestPostgresServerMessages(t *testing.T) {
	s := &pg{}
	// RowDescription: one column, "email", followed by 18 bytes of type information.
	rd := i16(1)
	rd = append(rd, cstr("email")...)
	rd = append(rd, make([]byte, 18)...)
	// DataRow with one value.
	dr := i16(1)
	dr = append(dr, i32(7)...)
	dr = append(dr, "a@b.com"...)

	msgs := append(pgMsg('T', rd), pgMsg('D', dr)...)
	msgs = append(msgs, pgMsg('C', cstr("SELECT 1"))...)
	msgs = append(msgs, pgMsg('Z', []byte{'I'})...)

	got := s.Feed(msgs)
	want := []string{"RowDescription email", "DataRow a@b.com", "CommandComplete SELECT 1", "ReadyForQuery (idle)"}
	if len(got) != len(want) {
		t.Fatalf("got %q want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %q, want %q", got[i], want[i])
		}
	}
}

// The same letter means different things in each direction; rendering a DataRow as "Describe"
// would be worse than not decoding it.
func TestPostgresDisambiguatesByDirection(t *testing.T) {
	dr := i16(1)
	dr = append(dr, i32(2)...)
	dr = append(dr, "hi"...)
	if got := (&pg{}).Feed(pgMsg('D', dr)); len(got) != 1 || !strings.HasPrefix(got[0], "DataRow") {
		t.Fatalf("server D is a DataRow: %q", got)
	}
	describe := append([]byte{'S'}, cstr("stmt1")...)
	if got := (&pg{client: true, started: true}).Feed(pgMsg('D', describe)); len(got) != 1 ||
		!strings.HasPrefix(got[0], "Describe") {
		t.Fatalf("client D is a Describe: %q", got)
	}
}

// A connection that turns to TLS produces nothing readable afterwards. Saying so once is far
// better than a stream of unreadable bytes with no explanation.
func TestPostgresSSLRequestSaysWhatFollows(t *testing.T) {
	msg := append(i32(8), i32(80877103)...)
	got := (&pg{client: true}).Feed(msg)
	if len(got) != 1 || !strings.Contains(got[0], "encrypted") {
		t.Fatalf("an SSLRequest should say the rest is encrypted: %q", got)
	}
}

func TestPostgresStartupNamesUserAndDatabase(t *testing.T) {
	params := append(cstr("user"), cstr("alice")...)
	params = append(params, cstr("database")...)
	params = append(params, cstr("shop")...)
	params = append(params, 0)
	msg := append(i32(8+len(params)), i32(196608)...)
	msg = append(msg, params...)

	got := (&pg{client: true}).Feed(msg)
	if len(got) != 1 || !strings.Contains(got[0], "user=alice") || !strings.Contains(got[0], "database=shop") {
		t.Fatalf("got %q", got)
	}
}

// A password must never be rendered, whatever else is.
func TestPostgresPasswordIsNotShown(t *testing.T) {
	got := (&pg{client: true, started: true}).Feed(pgMsg('p', cstr("hunter2")))
	if len(got) != 1 || strings.Contains(got[0], "hunter2") {
		t.Fatalf("a password must not be rendered: %q", got)
	}
}
