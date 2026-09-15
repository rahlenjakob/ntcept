package netns

import (
	"net"
	"testing"
)

// Real tables, copied from a Linux host. The byte order is the whole point of this parser:
// getting it wrong produces plausible addresses rather than an error, so these pin it against
// input nobody invented.
const tcpTable = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000     0        0 24601 1 0000000000000000 100 0 0 10 0
   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000     0        0 24602 1 0000000000000000 100 0 0 10 0
   2: 020A4D0A:15B3 00000000:0000 0A 00000000:00000000 00:00000000     0        0 24603 1 0000000000000000 100 0 0 10 0
   3: 0100007F:0BB8 0100007F:C350 01 00000000:00000000 00:00000000     0        0 24604 1 0000000000000000 20 4 30 10 -1
`

const tcp6Table = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000     0        0 24700 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0BB9 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000     0        0 24701 1 0000000000000000 100 0 0 10 0
`

func TestParseListeningReadsAddressesAndPorts(t *testing.T) {
	got := parseListening(tcpTable)
	if len(got) != 3 {
		t.Fatalf("expected three listening sockets, got %d: %v", len(got), got)
	}
	// 0100007F is 127.0.0.1 with each word in host order; 0BB8 is 3000 big-endian.
	if !got[0].IP.Equal(net.ParseIP("127.0.0.1")) || got[0].Port != 3000 {
		t.Errorf("first socket parsed as %s, want 127.0.0.1:3000", got[0])
	}
	if !got[1].IP.Equal(net.ParseIP("0.0.0.0")) || got[1].Port != 8080 {
		t.Errorf("second socket parsed as %s, want 0.0.0.0:8080", got[1])
	}
	if !got[2].IP.Equal(net.ParseIP("10.77.10.2")) || got[2].Port != 5555 {
		t.Errorf("third socket parsed as %s, want 10.77.10.2:5555", got[2])
	}
}

// An established connection is not something to publish. Only LISTEN counts.
func TestParseListeningIgnoresEstablishedSockets(t *testing.T) {
	for _, l := range parseListening(tcpTable) {
		if l.Port == 50000 {
			t.Fatal("an established connection was mistaken for a listening socket")
		}
	}
}

func TestParseListeningHandlesIPv6(t *testing.T) {
	got := parseListening(tcp6Table)
	if len(got) != 2 {
		t.Fatalf("expected two sockets, got %d: %v", len(got), got)
	}
	if !got[0].IP.IsUnspecified() || got[0].Port != 8080 {
		t.Errorf("wildcard v6 parsed as %s, want [::]:8080", got[0])
	}
	if !got[1].IP.IsLoopback() || got[1].Port != 3001 {
		t.Errorf("v6 loopback parsed as %s, want [::1]:3001", got[1])
	}
}

func TestParseListeningSurvivesJunk(t *testing.T) {
	for _, in := range []string{
		"",
		"header only\n",
		"h\n   0: nonsense 00000000:0000 0A\n",
		"h\n   0: 0100007F 00000000:0000 0A x x x x x\n",
		"h\n   0: ZZZZZZZZ:0BB8 00000000:0000 0A x x x x x\n",
		"h\n   0: 0100007F:0000 00000000:0000 0A x x x x x\n", // port 0 is not a service
	} {
		if got := parseListening(in); len(got) != 0 {
			t.Errorf("parseListening(%q) invented %v", in, got)
		}
	}
}

// Where a listener is reachable inside the namespace depends on what it bound, and getting this
// wrong means a published port that connects to nothing.
func TestDialTarget(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		want string
	}{
		{"0.0.0.0", ChildIP},
		{"::", ChildIP},
		{"127.0.0.1", "127.0.0.1"},
		{"::1", "127.0.0.1"},
		{"10.77.0.2", "10.77.0.2"},
	} {
		l := Listener{IP: net.ParseIP(tc.ip), Port: 3000}
		if got := l.DialTarget(); got != tc.want {
			t.Errorf("a server bound to %s should be dialled at %s, got %s", tc.ip, tc.want, got)
		}
	}
}

// A server that binds both stacks appears twice, and must be published once.
func TestDedupePrefersTheWildcardAndOrdersByPort(t *testing.T) {
	in := []Listener{
		{IP: net.ParseIP("127.0.0.1"), Port: 8080},
		{IP: net.ParseIP("0.0.0.0"), Port: 8080},
		{IP: net.ParseIP("::"), Port: 3000},
	}
	got := dedupe(in)
	if len(got) != 2 {
		t.Fatalf("expected two ports, got %d: %v", len(got), got)
	}
	if got[0].Port != 3000 || got[1].Port != 8080 {
		t.Fatalf("ports should be ordered: %v", got)
	}
	if !got[1].IP.IsUnspecified() {
		t.Fatalf("the wildcard bind is the more useful one to publish, got %s", got[1])
	}
}

func TestPortMapKeepsTheSameNumberOnTheHost(t *testing.T) {
	// A user reads "listening on :3000" from their own app's output and opens that. Renumbering
	// would make the app's own log wrong.
	pm := portMapFor(Listener{IP: net.ParseIP("0.0.0.0"), Port: 3000})
	if pm.HostAddr != "127.0.0.1:3000" || pm.ChildPort != 3000 {
		t.Fatalf("unexpected mapping %+v", pm)
	}
}
