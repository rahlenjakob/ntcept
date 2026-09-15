package decode

import (
	"encoding/binary"
	"strings"
	"testing"
)

func le32(v int) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return b
}

// bsonDoc builds a BSON document from already-encoded elements.
func bsonDoc(elems ...[]byte) []byte {
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	out := append(le32(len(body)+5), body...)
	return append(out, 0)
}

func bsonStr(key, val string) []byte {
	e := append([]byte{0x02}, cstr(key)...)
	e = append(e, le32(len(val)+1)...)
	return append(append(e, val...), 0)
}

func bsonInt32(key string, v int) []byte {
	return append(append([]byte{0x10}, cstr(key)...), le32(v)...)
}

func bsonSubdoc(key string, doc []byte) []byte {
	return append(append([]byte{0x03}, cstr(key)...), doc...)
}

// opMsgFor wraps a command document in the OP_MSG framing a driver sends.
func opMsgFor(doc []byte) []byte {
	body := append(le32(0), 0) // flagBits, section kind 0
	body = append(body, doc...)
	head := append(le32(16+len(body)), le32(1)...) // length, requestID
	head = append(head, le32(0)...)                // responseTo
	head = append(head, le32(opMsg)...)
	return append(head, body...)
}

// Everything a modern driver sends is OP_MSG carrying one BSON document whose first key is the
// command and whose value is the collection. Reading just that turns an opaque binary stream
// into something recognisable.
func TestMongoOpMsgNamesTheCommandAndCollection(t *testing.T) {
	doc := bsonDoc(
		bsonStr("find", "orders"),
		bsonSubdoc("filter", bsonDoc(bsonStr("email", "a@b.com"))),
		bsonInt32("limit", 10),
		bsonStr("$db", "shop"),
	)
	got := (&mongo{client: true}).Feed(opMsgFor(doc))
	if len(got) != 1 {
		t.Fatalf("got %q", got)
	}
	for _, want := range []string{"find", "orders", "$db=shop", "limit=10"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("should carry %q: %s", want, got[0])
		}
	}
}

// A stream arrives in arbitrary pieces.
func TestMongoMessageSplitAcrossChunks(t *testing.T) {
	msg := opMsgFor(bsonDoc(bsonStr("insert", "orders"), bsonStr("$db", "shop")))
	m := &mongo{client: true}
	var got []string
	got = append(got, m.Feed(msg[:10])...)
	got = append(got, m.Feed(msg[10:])...)
	if len(got) != 1 || !strings.Contains(got[0], "insert") {
		t.Fatalf("got %q", got)
	}
}

// Detection has to work on whatever port compose happened to map.
func TestMongoIsRecognisedOnAnyPort(t *testing.T) {
	msg := opMsgFor(bsonDoc(bsonStr("ping", "1")))
	if !looksMongo(41234, msg) {
		t.Fatal("an OP_MSG on an arbitrary port should be recognised")
	}
	if looksMongo(41234, []byte("GET / HTTP/1.1\r\n\r\n")) {
		t.Fatal("an HTTP request is not an OP_MSG")
	}
}

// A truncated or hostile document must not make the decoder walk off the end and invent fields.
func TestMongoSurvivesMalformedDocuments(t *testing.T) {
	for _, bad := range [][]byte{
		opMsgFor([]byte{5, 0, 0, 0, 0}),
		opMsgFor(append(le32(99), 0x02, 'x', 0, 0xff, 0xff, 0xff, 0x7f)),
	} {
		_ = (&mongo{client: true}).Feed(bad)
	}
}
