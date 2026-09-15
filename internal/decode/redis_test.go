package decode

import (
	"strings"
	"testing"
)

// Every recent client negotiates RESP3 with HELLO at connect time. A decoder that only knows
// RESP2 does not fail loudly when a server answers with a map — it falls silent, which is the
// worst way for this to be wrong.
func TestRedisRESP3Types(t *testing.T) {
	for _, tc := range []struct{ wire, want string }{
		{"_\r\n", "(nil)"},
		{"#t\r\n", "true"},
		{"#f\r\n", "false"},
		{",3.25\r\n", "3.25"},
		{"(12345678901234567890\r\n", "12345678901234567890"},
		{"!7\r\nSOMEERR\r\n", "(error) SOMEERR"},
		{"=9\r\ntxt:hello\r\n", "hello"},
		{"%1\r\n$3\r\nkey\r\n$5\r\nvalue\r\n", "[key, value]"},
		{"~2\r\n$1\r\na\r\n$1\r\nb\r\n", "[a, b]"},
		{">2\r\n$7\r\nmessage\r\n$2\r\nhi\r\n", "[message, hi]"},
	} {
		got := feedAll(&resp{}, tc.wire)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%q decoded as %q, want %q", tc.wire, got, tc.want)
		}
	}
}

// A command reads best as a command line; a keyed or nested reply reads best bracketed.
func TestRedisCommandsAndRepliesReadDifferently(t *testing.T) {
	if got := feedAll(&resp{}, "*3\r\n$3\r\nSET\r\n$5\r\norder\r\n$4\r\nA-91\r\n"); got[0] != "SET order A-91" {
		t.Fatalf("a command should read as a command line: %q", got)
	}
	if got := feedAll(&resp{}, "%1\r\n$4\r\nrole\r\n$6\r\nmaster\r\n"); got[0] != "[role, master]" {
		t.Fatalf("a map should read as pairs: %q", got)
	}
}

// Health checks and redis-cli send bare text rather than a RESP array.
func TestRedisInlineCommands(t *testing.T) {
	if got := feedAll(&resp{}, "PING\r\n"); len(got) != 1 || got[0] != "PING" {
		t.Fatalf("got %q", got)
	}
	if !looksRedis(41234, []byte("PING\r\n")) {
		t.Fatal("an inline PING on an arbitrary port should still be recognised as redis")
	}
	// Most protocols look like text; only known verbs may count.
	if looksRedis(41234, []byte("GET /index.html HTTP/1.1\r\n")) {
		t.Fatal("an HTTP request is not an inline redis command")
	}
}

// A reply can nest arbitrarily, and a malformed or hostile stream must not walk the stack down.
func TestRedisNestingIsBounded(t *testing.T) {
	var deep strings.Builder
	for i := 0; i < 64; i++ {
		deep.WriteString("*1\r\n")
	}
	deep.WriteString("$2\r\nhi\r\n")
	// Whatever it decides, it must return rather than recurse to exhaustion.
	_ = feedAll(&resp{}, deep.String())
}

// A value large enough to fill a line has to be shortened, or one reply hides everything else.
func TestRedisClipsEnormousValues(t *testing.T) {
	big := strings.Repeat("x", 4000)
	got := feedAll(&resp{}, "$4000\r\n"+big+"\r\n")
	if len(got) != 1 || len(got[0]) > 200 {
		t.Fatalf("a 4000-byte value was rendered as %d characters", len(got[0]))
	}
	if !strings.Contains(got[0], "4000") {
		t.Fatalf("the real size should still be reported: %s", got[0])
	}
}
