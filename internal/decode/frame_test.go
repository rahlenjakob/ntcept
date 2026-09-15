package decode

import (
	"bytes"
	"testing"
)

// Frame must locate exact message boundaries and agree with Feed on what each message renders to.
func TestPostgresFrameSpansMatchFeed(t *testing.T) {
	q1 := pgMsg('Q', cstr("select 1"))
	q2 := pgMsg('Q', cstr("select 2"))
	stream := append(append([]byte{}, q1...), q2...)

	frames, consumed, ok := (&pg{client: true, started: true}).Frame(stream)
	if !ok || consumed != len(stream) {
		t.Fatalf("ok=%v consumed=%d, want true and %d", ok, consumed, len(stream))
	}
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if !bytes.Equal(frames[0].Bytes, q1) || !bytes.Equal(frames[1].Bytes, q2) {
		t.Fatal("frame byte spans do not match the input messages")
	}
	for _, f := range frames {
		if f.Kind != "Query" || !f.Holdable {
			t.Fatalf("Query should be a holdable frame, got kind=%q holdable=%v", f.Kind, f.Holdable)
		}
	}
	// A partial trailing message is reported as unconsumed, not misframed.
	partial := append(append([]byte{}, q1...), q2[:3]...)
	frames, consumed, ok = (&pg{client: true, started: true}).Frame(partial)
	if !ok || consumed != len(q1) || len(frames) != 1 {
		t.Fatalf("partial: ok=%v consumed=%d frames=%d, want true %d 1", ok, consumed, len(frames), len(q1))
	}
}

// Once the client asks for TLS the stream is no longer decodable, and Frame must say so rather than
// stall waiting for a message boundary that will never come.
func TestPostgresFrameStopsAtTLS(t *testing.T) {
	ssl := []byte{0, 0, 0, 8, 4, 210, 22, 47}                          // length 8, code 80877103 (SSLRequest)
	stream := append(append([]byte{}, ssl...), 0x16, 0x03, 0x01, 0x00) // then TLS handshake bytes
	frames, consumed, ok := (&pg{client: true}).Frame(stream)
	if ok {
		t.Fatal("expected ok=false once the connection goes to TLS")
	}
	if consumed != len(ssl) || len(frames) != 1 || frames[0].Kind != "SSLRequest" {
		t.Fatalf("got consumed=%d frames=%d, want the SSLRequest framed and the rest left opaque", consumed, len(frames))
	}
}

func TestPostgresSynthErrorSimpleQuery(t *testing.T) {
	reply, awaitTerminator := SynthError("postgres", "Query", ProtoError{Code: "40001", Message: "nope"})
	if awaitTerminator {
		t.Fatal("a simple Query is answered in one step, not by waiting for Sync")
	}
	if len(reply) == 0 || reply[0] != 'E' {
		t.Fatalf("expected an ErrorResponse first, got %q", reply)
	}
	if !bytes.Contains(reply, []byte("40001")) || !bytes.Contains(reply, []byte("nope")) {
		t.Fatalf("error fields missing from %q", reply)
	}
	if !bytes.HasSuffix(reply, []byte{'Z', 0, 0, 0, 5, 'I'}) {
		t.Fatalf("expected a trailing ReadyForQuery(idle), got %q", reply)
	}
}

func TestPostgresSynthErrorExtendedWaitsForSync(t *testing.T) {
	reply, awaitTerminator := SynthError("postgres", "Bind", ProtoError{Message: "denied"})
	if !awaitTerminator {
		t.Fatal("the extended protocol must wait for the client's Sync before ReadyForQuery")
	}
	if len(reply) == 0 || reply[0] != 'E' {
		t.Fatalf("expected an ErrorResponse, got %q", reply)
	}
	if bytes.Contains(reply, []byte{'Z'}) {
		t.Fatal("ReadyForQuery must not be sent until the Sync arrives")
	}
	if !ExchangeTerminator("postgres", "Sync") {
		t.Fatal("Sync should terminate the extended exchange")
	}
	if term := TerminatorReply("postgres"); len(term) == 0 || term[0] != 'Z' {
		t.Fatalf("terminator reply should be ReadyForQuery, got %q", term)
	}
}

func TestSynthErrorUnknownProtocol(t *testing.T) {
	if reply, _ := SynthError("redis", "GET", ProtoError{Message: "x"}); reply != nil {
		t.Fatal("only Postgres can be answered locally in this version")
	}
}

func TestRedisFrameHoldsClientCommandsNotReplies(t *testing.T) {
	cmd := []byte("*1\r\n$4\r\nPING\r\n")
	frames, consumed, ok := (&resp{}).Frame(cmd)
	if !ok || consumed != len(cmd) || len(frames) != 1 || !frames[0].Holdable {
		t.Fatalf("a client command should be one holdable frame: ok=%v consumed=%d frames=%d", ok, consumed, len(frames))
	}
	// The reply side holds only errors.
	reply := []byte("+PONG\r\n")
	frames, _, _ = (&resp{server: true}).Frame(reply)
	if len(frames) != 1 || frames[0].Holdable {
		t.Fatalf("a normal reply should not be held, got %+v", frames)
	}
	errReply := []byte("-ERR nope\r\n")
	frames, _, _ = (&resp{server: true}).Frame(errReply)
	if len(frames) != 1 || !frames[0].Holdable {
		t.Fatalf("an error reply should be holdable, got %+v", frames)
	}
}

func TestPostgresQueryTextAndRewrite(t *testing.T) {
	// A simple Query: the SQL is read back and can be swapped for new SQL.
	q := pgMsg('Q', cstr("select 1"))
	if got := QueryText("postgres", "Query", q); got != "select 1" {
		t.Fatalf("QueryText(Query) = %q", got)
	}
	rebuilt, ok := RewriteQuery("postgres", "Query", q, "select 2")
	if !ok {
		t.Fatal("Query should be rewritable")
	}
	if frames, _, _ := (&pg{client: true, started: true}).Frame(rebuilt); len(frames) != 1 || frames[0].Text != "Query "+sql("select 2") {
		t.Fatalf("rewritten query did not reparse: %+v", frames)
	}

	// A Parse carries the statement name and parameter OIDs around the SQL; a rewrite keeps them.
	payload := append(cstr("stmt1"), cstr("select * from t where id = $1")...)
	payload = append(payload, i16(1)...)  // one parameter
	payload = append(payload, i32(23)...) // int4 OID
	parse := pgMsg('P', payload)
	if got := QueryText("postgres", "Parse", parse); got != "select * from t where id = $1" {
		t.Fatalf("QueryText(Parse) = %q", got)
	}
	rebuilt, ok = RewriteQuery("postgres", "Parse", parse, "select * from t where id = $1 and active")
	if !ok {
		t.Fatal("Parse should be rewritable")
	}
	// The rebuilt Parse must still name stmt1 and keep the one int4 parameter.
	frames, _, _ := (&pg{client: true, started: true}).Frame(rebuilt)
	if len(frames) != 1 || frames[0].Kind != "Parse" {
		t.Fatalf("rewritten parse did not reparse: %+v", frames)
	}
	if got := QueryText("postgres", "Parse", rebuilt); got != "select * from t where id = $1 and active" {
		t.Fatalf("rewritten SQL not present: %q", got)
	}
	if !bytes.HasSuffix(rebuilt, append(i16(1), i32(23)...)) {
		t.Fatal("parameter-type list was not preserved through the rewrite")
	}

	// A Bind has no single statement, so it is edited by raw bytes, not by SQL.
	if _, ok := RewriteQuery("postgres", "Bind", pgMsg('B', nil), "x"); ok {
		t.Fatal("Bind should not be SQL-rewritable")
	}
}
