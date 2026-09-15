package decode

import (
	"strings"
	"testing"
)

// myPkt builds one MySQL packet: 3-byte little-endian length, sequence, payload.
func myPkt(seq byte, body []byte) []byte {
	n := len(body)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, body...)
}

func TestMySQLCommandsAreNamed(t *testing.T) {
	c := &mysql{client: true, seenHandshake: true}
	got := feedBytes(c,
		myPkt(0, append([]byte{0x03}, "select 1"...)),
		myPkt(0, []byte{0x0e}),
		myPkt(0, append([]byte{0x02}, "shop"...)),
		myPkt(0, []byte{0x01}),
	)
	want := []string{`Query "select 1"`, "Ping", `InitDB shop`, "Quit"}
	if len(got) != len(want) {
		t.Fatalf("got %q want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got %q, want %q", got[i], want[i])
		}
	}
}

// Prepared statements are how a driver actually talks: the SQL goes once, the id comes back, and
// every execution afterwards names only the id. Neither direction can render an execution alone.
func TestMySQLPreparedStatementCarriesItsSQLAcrossDirections(t *testing.T) {
	stmts := &stmtTable{}
	client := &mysql{client: true, stmts: stmts, seenHandshake: true}
	server := &mysql{stmts: stmts, seenHandshake: true}

	if got := feedBytes(client, myPkt(0, append([]byte{0x16}, "select * from orders where id = ?"...))); len(got) != 1 ||
		!strings.Contains(got[0], "select * from orders where id = ?") {
		t.Fatalf("Prepare not rendered: %q", got)
	}
	// The server answers with statement id 7. A prepare response is status, id, column count,
	// parameter count, a reserved byte and a warning count — twelve bytes, and it opens with
	// the same 0x00 an ordinary OK does, which is why the two are told apart by length.
	ok := []byte{0x00, 7, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0}
	if got := feedBytes(server, myPkt(1, ok)); len(got) != 1 || !strings.Contains(got[0], "#7") {
		t.Fatalf("PrepareOK not rendered: %q", got)
	}
	// Executing id 7 must now show the statement it was prepared from.
	exec := append([]byte{0x17}, 7, 0, 0, 0)
	exec = append(exec, 0, 1, 0, 0, 0)
	got := feedBytes(client, myPkt(0, exec))
	if len(got) != 1 || !strings.Contains(got[0], "select * from orders where id = ?") {
		t.Fatalf("an execution should name the statement it runs: %q", got)
	}
}

// An error is what someone is usually looking for, and MySQL sends it as a code, a SQLSTATE and
// a message rather than as a sentence.
func TestMySQLErrorIsReadable(t *testing.T) {
	body := append([]byte{0xff, 0x46, 0x04, '#'}, "23000"...)
	body = append(body, "Duplicate entry '4471' for key 'orders.PRIMARY'"...)
	got := feedBytes(&mysql{seenHandshake: true}, myPkt(1, body))
	if len(got) != 1 {
		t.Fatalf("got %q", got)
	}
	for _, want := range []string{"1094", "23000", "Duplicate entry '4471'"} {
		if !strings.Contains(got[0], want) {
			t.Fatalf("error should carry %q: %s", want, got[0])
		}
	}
}

// A write is asked how many rows it changed and what id it created.
func TestMySQLOKReportsRowsAndInsertID(t *testing.T) {
	got := feedBytes(&mysql{seenHandshake: true}, myPkt(1, []byte{0x00, 3, 42, 0x02, 0x00, 0, 0}))
	if len(got) != 1 || !strings.Contains(got[0], "3 row(s)") || !strings.Contains(got[0], "insert id 42") {
		t.Fatalf("got %q", got)
	}
}

// The server greets first, which is both how the connection starts and the only way to recognise
// MySQL on a port nobody expected.
func TestMySQLHandshakeIsRecognisedOnAnyPort(t *testing.T) {
	greeting := append([]byte{0x0a}, cstr("8.0.35")...)
	greeting = append(greeting, make([]byte, 20)...)
	pkt := myPkt(0, greeting)

	if got := feedBytes(&mysql{}, pkt); len(got) != 1 || !strings.Contains(got[0], "8.0.35") {
		t.Fatalf("handshake not rendered: %q", got)
	}
	// Detection has to work from the server's side, because the client has said nothing yet.
	if !looksMySQL(41234, pkt) {
		t.Fatal("a MySQL greeting on an arbitrary port should still be recognised")
	}
	if looksMySQL(41234, []byte("HTTP/1.1 200 OK\r\n")) {
		t.Fatal("an HTTP response is not a MySQL greeting")
	}
}

// A stream arrives in arbitrary pieces; a decoder that assumes whole packets is useless.
func TestMySQLPacketSplitAcrossChunks(t *testing.T) {
	pkt := myPkt(0, append([]byte{0x03}, "select 1"...))
	c := &mysql{client: true, seenHandshake: true}
	var got []string
	got = append(got, c.Feed(pkt[:5])...)
	got = append(got, c.Feed(pkt[5:])...)
	if len(got) != 1 || got[0] != `Query "select 1"` {
		t.Fatalf("got %q", got)
	}
}

func feedBytes(s Stream, chunks ...[]byte) []string {
	var out []string
	for _, c := range chunks {
		out = append(out, s.Feed(c)...)
	}
	return out
}
