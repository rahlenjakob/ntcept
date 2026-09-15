package procs

import (
	"errors"
	"testing"
	"time"
)

// Real output from `netstat -anv -p tcp`. The owning process is in a positional column whose
// index depends on the header, which is why the parser looks for its shape instead of counting —
// and why this is pinned against output nobody invented.
const netstatOut = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rxbytes  txbytes  rhiwat  shiwat    process:pid    state
tcp4       0      0  127.0.0.1.18122        *.*                    LISTEN             0        0  131072  131072  python3.10:45480  00000
tcp4       0      0  127.0.0.1.52001        127.0.0.1.18122        ESTABLISHED      120      340  131072  131072        curl:45611  00000
tcp4       0      0  192.168.1.201.52002    140.82.121.6.443       ESTABLISHED     4096    12288  131072  131072        node:45700  00000
tcp6       0      0  ::1.8080               *.*                    LISTEN             0        0  131072  131072   mystery:45800  00000
`

func TestParsePortsFindsTheOwningProcess(t *testing.T) {
	got := parsePorts(netstatOut)

	// The connection is what a redirect delivers, and its source port is all ntcept has.
	if o, ok := got[52001]; !ok || o.PID != 45611 || o.Command != "curl" {
		t.Fatalf("port 52001 should belong to curl(45611), got %+v (present=%v)", o, ok)
	}
	if o, ok := got[52002]; !ok || o.PID != 45700 || o.Command != "node" {
		t.Fatalf("port 52002 should belong to node(45700), got %+v", o)
	}
	if o, ok := got[18122]; !ok || o.PID != 45480 {
		t.Fatalf("a listening socket should still be attributed, got %+v", o)
	}
	if o, ok := got[8080]; !ok || o.PID != 45800 {
		t.Fatalf("IPv6 sockets must parse too, got %+v", o)
	}
}

func TestParsePortsIgnoresJunk(t *testing.T) {
	for _, in := range []string{
		"",
		"Active Internet connections\n",
		"udp4 0 0 127.0.0.1.53 *.* something:1\n",           // not tcp
		"tcp4 0 0 noport *.* LISTEN 0 0 0 0 thing:1\n",      // no port
		"tcp4 0 0 127.0.0.1.1 *.* LISTEN 0 0 0 0 thing:x\n", // no pid
	} {
		if got := parsePorts(in); len(got) != 0 {
			t.Errorf("parsePorts(%q) invented %v", in, got)
		}
	}
}

// Real output from `ps -axo pid=,gid=`.
const psOut = `  501     20
45611  33333
45700  33333
45800     20
    1      0
`

func TestParseMarkedFindsTheSupervisedTree(t *testing.T) {
	marked := parseMarked(psOut, 33333)
	if len(marked) != 2 {
		t.Fatalf("expected two marked processes, got %d: %v", len(marked), marked)
	}
	for _, pid := range []int{45611, 45700} {
		if !marked[pid] {
			t.Errorf("pid %d runs under the marker group and should be recognised", pid)
		}
	}
	// The group is what pf matches on to divert traffic; anything else is another application
	// and its traffic must not be captured, listed or held.
	for _, pid := range []int{501, 45800, 1} {
		if marked[pid] {
			t.Errorf("pid %d is not under the marker group and must not be claimed", pid)
		}
	}
}

func TestParseMarkedIgnoresJunk(t *testing.T) {
	for _, in := range []string{"", "header\n", "notanumber alsonot\n", "123\n"} {
		if got := parseMarked(in, 33333); len(got) != 0 {
			t.Errorf("parseMarked(%q) invented %v", in, got)
		}
	}
}

func TestOwnerString(t *testing.T) {
	if got := (Owner{PID: 42, Command: "node"}).String(); got != "node (pid 42)" {
		t.Errorf("got %q", got)
	}
	if got := (Owner{PID: 42}).String(); got != "pid 42" {
		t.Errorf("got %q", got)
	}
}

// The attributor is what decides whether a connection is captured and, more importantly, whether
// it can be held. Holding a connection belonging to another application would stall something
// nobody is debugging, so "not sure" has to mean "not ours".
func TestAttributorClaimsOnlyTheSupervisedApplication(t *testing.T) {
	a := &Attributor{
		GID:    33333,
		TTL:    time.Minute,
		ports:  func() (string, error) { return netstatOut, nil },
		marked: func() (string, error) { return psOut, nil },
	}

	owner, ours := a.Owns(52001)
	if !ours || owner.Command != "curl" {
		t.Fatalf("curl runs under the marker group; it should be claimed: %+v ours=%v", owner, ours)
	}

	// Under the marker group too, so also ours.
	if _, ours := a.Owns(52002); !ours {
		t.Fatal("node runs under the marker group and should be claimed")
	}

	// A process that is not part of the run.
	if owner, ours := a.Owns(8080); ours {
		t.Fatalf("pid 45800 is not under the marker group, but was claimed as %+v", owner)
	}

	// A port nothing owns must never be claimed.
	if _, ours := a.Owns(9999); ours {
		t.Fatal("an unattributable connection must not be claimed")
	}
}

// If the kernel tables cannot be read at all, everything is foreign. Capturing on a failed
// lookup would mean recording other applications' traffic whenever a command was missing.
func TestAttributorClaimsNothingWhenItCannotLook(t *testing.T) {
	a := &Attributor{
		GID:    33333,
		TTL:    time.Minute,
		ports:  func() (string, error) { return "", errors.New("netstat: not found") },
		marked: func() (string, error) { return "", errors.New("ps: not found") },
	}
	if _, ours := a.Owns(52001); ours {
		t.Fatal("with no way to attribute a connection, it must not be claimed")
	}
}

// A connection can be newer than the cached snapshot; one refresh before answering.
func TestAttributorRefreshesForAPortItHasNotSeen(t *testing.T) {
	calls := 0
	table := "Active\nheader\n"
	a := &Attributor{
		GID: 33333,
		TTL: time.Minute,
		ports: func() (string, error) {
			calls++
			if calls > 1 {
				return netstatOut, nil
			}
			return table, nil
		},
		marked: func() (string, error) { return psOut, nil },
	}
	if _, ours := a.Owns(52001); !ours {
		t.Fatal("a connection newer than the snapshot should be found after a refresh")
	}
	if calls < 2 {
		t.Fatalf("expected a refresh on the miss, got %d lookups", calls)
	}
}

// Discovering what the application already talks to is what removes the need to list ports by
// hand. It must find only the supervised application's loopback destinations — not another
// process's, and not anything off-machine.
func TestLoopbackTargetsFindsOnlyTheApplicationsLocalServices(t *testing.T) {
	const out = `Active Internet connections
Proto Recv-Q Send-Q  Local Address        Foreign Address      (state)      rx  tx  rh  sh  process:pid  state
tcp4       0      0  127.0.0.1.52001      127.0.0.1.5432       ESTABLISHED   1   1   1   1   node:45611   00000
tcp4       0      0  127.0.0.1.52003      127.0.0.1.6379       ESTABLISHED   1   1   1   1   node:45611   00000
tcp4       0      0  127.0.0.1.52004      127.0.0.1.5984       ESTABLISHED   1   1   1   1   other:45999  00000
tcp4       0      0  192.168.1.5.52005    140.82.121.6.443     ESTABLISHED   1   1   1   1   node:45611   00000
tcp4       0      0  127.0.0.1.52006      127.0.0.1.7000       LISTEN        1   1   1   1   node:45611   00000
`
	const ps = "45611 33333\n45999    20\n"
	a := &Attributor{
		GID:    33333,
		TTL:    time.Minute,
		ports:  func() (string, error) { return out, nil },
		marked: func() (string, error) { return ps, nil },
	}

	got := a.LoopbackTargets()
	want := []int{5432, 6379}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func TestParseConnsIgnoresNonEstablished(t *testing.T) {
	const out = `h
tcp4 0 0 127.0.0.1.1 *.* LISTEN 0 0 0 0 a:1 x
`
	if got := parseConns(out); len(got) != 0 {
		t.Fatalf("a listening socket is not a connection: %v", got)
	}
}

// Pre-arming is what keeps the first connection to a database from being the one that gets away:
// every loopback service already running is armed before the command starts. Ports reachable
// only from off-machine are not loopback services, and ports in the ephemeral range can never be
// armed at all — see TestPortsInTheEphemeralRangeAreNeverArmed.
func TestPreArmTakesEveryLoopbackServiceAndNothingElse(t *testing.T) {
	const out = `Active Internet connections
Proto Recv-Q Send-Q  Local Address        Foreign Address   (state)   rx tx rh sh  process:pid  state
tcp4       0      0  127.0.0.1.5432       *.*               LISTEN     0  0  0  0  postgres:1   00000
tcp4       0      0  127.0.0.1.6379       *.*               LISTEN     0  0  0  0  redis:2      00000
tcp4       0      0  127.0.0.1.14300      *.*               LISTEN     0  0  0  0  someide:3    00000
tcp4       0      0  127.0.0.1.49156      *.*               LISTEN     0  0  0  0  daemon:4     00000
tcp4       0      0  192.168.1.5.8443     *.*               LISTEN     0  0  0  0  public:5     00000
`
	a := &Attributor{
		GID:    33333,
		TTL:    time.Minute,
		ports:  func() (string, error) { return out, nil },
		marked: func() (string, error) { return psOut, nil },
	}
	got := a.PreArm()
	want := map[int]bool{5432: true, 6379: true, 14300: true}
	if len(got) != len(want) {
		t.Fatalf("expected %d loopback services, got %v (49156 is ephemeral and must be "+
			"excluded; 8443 is not on loopback)", len(want), got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("port %d was armed but should not have been", p)
		}
	}
}

func TestParseLoopbackListenersIgnoresOffMachineAndConnections(t *testing.T) {
	const out = `h
tcp4 0 0 127.0.0.1.5432 *.* LISTEN 0 0 0 0 a:1 x
tcp4 0 0 192.168.1.5.8443 *.* LISTEN 0 0 0 0 b:2 x
tcp4 0 0 127.0.0.1.52001 127.0.0.1.5432 ESTABLISHED 0 0 0 0 c:3 x
`
	got := parseLoopbackListeners(out)
	if len(got) != 1 || got[0] != 5432 {
		t.Fatalf("expected only the loopback listener 5432, got %v", got)
	}
}

// A connection has two ends and netstat does not say which dialled. The application accepting a
// connection on its own port is not the application using a service — arming the far end there
// would install a redirect for a client's ephemeral port, which means nothing and, because
// installing one disturbs connections in flight, actively breaks the run.
func TestLoopbackTargetsIgnoresInboundConnections(t *testing.T) {
	const out = `Active
Proto Recv-Q Send-Q  Local Address      Foreign Address    (state)      rx tx rh sh  process:pid  state
tcp4       0      0  127.0.0.1.4010     *.*                LISTEN        0  0  0  0  node:45611   00000
tcp4       0      0  127.0.0.1.64366    127.0.0.1.4010     ESTABLISHED   0  0  0  0  node:45611   00000
tcp4       0      0  127.0.0.1.4010     127.0.0.1.64366    ESTABLISHED   0  0  0  0  node:45611   00000
`
	a := &Attributor{
		GID:    33333,
		TTL:    time.Minute,
		ports:  func() (string, error) { return out, nil },
		marked: func() (string, error) { return "45611 33333\n", nil },
	}
	got := a.LoopbackTargets()
	if len(got) != 1 || got[0] != 4010 {
		t.Fatalf("only the service being called should be armed, got %v — 64366 is a client's "+
			"ephemeral port on the accepting side of the same connection", got)
	}
}

// Ports in the ephemeral range must never be given a redirect rule. A rule for one also matches
// a reply travelling back to a client the kernel happened to give that port, which strands the
// connection — and ntcept's own listeners are up there, so redirecting them would loop.
func TestPortsInTheEphemeralRangeAreNeverArmed(t *testing.T) {
	const out = `Active
Proto Recv-Q Send-Q  Local Address        Foreign Address   (state)   rx tx rh sh  process:pid  state
tcp4       0      0  127.0.0.1.5432       *.*               LISTEN     0  0  0  0  postgres:1   00000
tcp4       0      0  127.0.0.1.49151      *.*               LISTEN     0  0  0  0  edge:2       00000
tcp4       0      0  127.0.0.1.49152      *.*               LISTEN     0  0  0  0  ntcept:3     00000
tcp4       0      0  127.0.0.1.58015      *.*               LISTEN     0  0  0  0  ntcept:4     00000
`
	a := &Attributor{
		GID: 33333, EphemeralFloor: 49152, TTL: time.Minute,
		ports:  func() (string, error) { return out, nil },
		marked: func() (string, error) { return psOut, nil },
	}
	got := a.PreArm()
	want := map[int]bool{5432: true, 49151: true}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("port %d is at or above the ephemeral floor and must not be armed", p)
		}
	}
}

func TestDiscoveryIgnoresEphemeralDestinations(t *testing.T) {
	const out = `Active
Proto Recv-Q Send-Q  Local Address      Foreign Address    (state)      rx tx rh sh  process:pid  state
tcp4       0      0  127.0.0.1.52001    127.0.0.1.5432     ESTABLISHED   0  0  0  0  node:45611   00000
tcp4       0      0  127.0.0.1.52002    127.0.0.1.52900    ESTABLISHED   0  0  0  0  node:45611   00000
`
	a := &Attributor{
		GID: 33333, EphemeralFloor: 49152, TTL: time.Minute,
		ports:  func() (string, error) { return out, nil },
		marked: func() (string, error) { return "45611 33333\n", nil },
	}
	got := a.LoopbackTargets()
	if len(got) != 1 || got[0] != 5432 {
		t.Fatalf("only 5432 may be armed; 52900 is in the ephemeral range: %v", got)
	}
}

// Which session supervises a process is the only question the catch-all owner has to answer to
// route a connection to the right one, and the process's group is the answer.
func TestGIDOfIdentifiesTheSupervisingSession(t *testing.T) {
	a := &Attributor{
		GID: 33333, EphemeralFloor: 49152, TTL: time.Minute,
		ports:  func() (string, error) { return netstatOut, nil },
		marked: func() (string, error) { return "45611 33333\n45700 33334\n45800    20\n", nil },
	}
	for _, tc := range []struct {
		pid, gid int
		known    bool
	}{
		{45611, 33333, true}, // this session
		{45700, 33334, true}, // another ntcept session
		{45800, 20, true},    // nothing to do with ntcept
		{99999, 0, false},    // gone
	} {
		gid, ok := a.GIDOf(tc.pid)
		if ok != tc.known || (ok && gid != tc.gid) {
			t.Errorf("GIDOf(%d) = %d,%v; want %d,%v", tc.pid, gid, ok, tc.gid, tc.known)
		}
	}
}
