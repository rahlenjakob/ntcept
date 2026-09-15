package decode

import "testing"

func feedAll(s Stream, chunks ...string) []string {
	var out []string
	for _, c := range chunks {
		out = append(out, s.Feed([]byte(c))...)
	}
	return out
}

func TestRedisCommandSplitAcrossChunks(t *testing.T) {
	// A stream arrives in arbitrary pieces; a decoder that assumes whole messages is useless.
	got := feedAll(&resp{}, "*3\r\n$3\r\nSET\r\n$5\r\nor", "der\r\n$4\r\nA-91\r\n")
	if len(got) != 1 || got[0] != "SET order A-91" {
		t.Fatalf("got %q", got)
	}
}

func TestRedisReplies(t *testing.T) {
	got := feedAll(&resp{}, "+OK\r\n:42\r\n-ERR nope\r\n$-1\r\n")
	want := []string{"OK", "42", "(error) ERR nope", "(nil)"}
	if len(got) != len(want) {
		t.Fatalf("got %q want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestPostgresSimpleQuery(t *testing.T) {
	q := "select 1\x00"
	msg := append([]byte{'Q'}, 0, 0, 0, byte(4+len(q)))
	msg = append(msg, q...)
	got := (&pg{client: true, started: true}).Feed(msg)
	if len(got) != 1 || got[0] != `Query "select 1"` {
		t.Fatalf("got %q", got)
	}
}

func TestSniffUsesThePortAsAHint(t *testing.T) {
	if c := Sniff(6379, nil); c.Protocol() != "redis" {
		t.Fatalf("port 6379 should be redis, got %s", c.Protocol())
	}
	if c := Sniff(5432, nil); c.Protocol() != "postgres" {
		t.Fatalf("port 5432 should be postgres, got %s", c.Protocol())
	}
	if c := Sniff(9999, []byte("*2\r\n$4\r\nPING\r\n")); c.Protocol() != "redis" {
		t.Fatalf("RESP on an odd port should still be redis, got %s", c.Protocol())
	}
	if c := Sniff(9999, []byte("\x00\x01binary")); c.Protocol() != "raw" {
		t.Fatalf("unknown traffic should read as raw until it says otherwise, got %s", c.Protocol())
	}
}

func TestDNSQuestionAndAnswer(t *testing.T) {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if got := DNS(q); got != "A example.com?" {
		t.Fatalf("got %q", got)
	}
	r := append([]byte(nil), q...)
	r[2] = 0x81
	r[6], r[7] = 0, 2
	if got := DNS(r); got != "A example.com → 2 answer(s)" {
		t.Fatalf("got %q", got)
	}
}
