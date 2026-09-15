//go:build darwin

package pftun

import (
	"os"
	"strings"
	"testing"

	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

// The pf ruleset is the whole macOS attach, and a rule that parses is not a rule that behaves —
// and a rule pf accepts is not necessarily one it applies. These pin the properties that were
// learned by measurement, so a future edit cannot quietly undo them.
func TestTheEgressRuleKeepsWhatWasLearned(t *testing.T) {
	r := ruleset{Anchor: "com.apple/ntcept-33333", Iface: "utun9", GID: 33333}
	got := r.text()

	// An address-only route-to parses but does not divert locally generated traffic.
	if !strings.Contains(got, "route-to (utun9 "+tunnel.HostIP+")") {
		t.Errorf("route-to must name the interface, not just the address:\n%s", got)
	}
	if !strings.Contains(got, "group 33333") {
		t.Errorf("the rule must be scoped to this session's group:\n%s", got)
	}
	// Diverting loopback into the utun strands the reply: it carries a loopback source on a
	// non-loopback interface and the host drops it. Loopback is redirected instead.
	if !strings.Contains(got, "! 127.0.0.0/8") {
		t.Errorf("loopback must be excluded from the egress rule:\n%s", got)
	}
	if !strings.Contains(got, "keep state") {
		t.Errorf("without keep state the return path is not matched:\n%s", got)
	}
	// Raw TCP and DNS are both claims ntcept makes.
	for _, proto := range []string{"proto tcp", "proto udp"} {
		if !strings.Contains(got, proto) {
			t.Errorf("%s is not diverted:\n%s", proto, got)
		}
	}
}

// Sessions must not be able to interfere with each other, which starts with never sharing a
// group or an anchor.
func TestEachSessionGetsItsOwnGroupAndAnchor(t *testing.T) {
	a := markerGroup{GID: markerGIDBase}
	b := markerGroup{GID: markerGIDBase + 1}
	if a.Anchor() == b.Anchor() {
		t.Fatal("two sessions share an anchor; loading one's rules would replace the other's")
	}
	for _, m := range []markerGroup{a, b} {
		if !strings.HasPrefix(m.Anchor(), AnchorPrefix) {
			t.Errorf("%s is outside the anchor point /etc/pf.conf evaluates", m.Anchor())
		}
	}
	// The rules of two sessions must differ in the group they match, or each would divert the
	// other's processes.
	ra := ruleset{Anchor: a.Anchor(), Iface: "utun8", GID: a.GID}.text()
	rb := ruleset{Anchor: b.Anchor(), Iface: "utun9", GID: b.GID}.text()
	if ra == rb {
		t.Fatal("two sessions produced identical rules")
	}
	if strings.Contains(ra, "group 33334") {
		t.Fatal("a session's rule matches another session's group")
	}
}

// A redirect at or above the ephemeral floor also matches the replies coming back to a client,
// which strands the connection. The range must stop below it.
func TestTheCatchAllStopsBelowTheEphemeralFloor(t *testing.T) {
	floor := ephemeralFloor()
	if floor < 1024 || floor > 65535 {
		t.Fatalf("implausible ephemeral floor %d", floor)
	}
	got := ruleset{Anchor: "a", Iface: "utun9", GID: 33333, CatchAll: 40000}.text()
	if !strings.Contains(got, "port 1:") {
		t.Fatalf("the catch-all must name a range:\n%s", got)
	}
	if strings.Contains(got, "port 1:65535") {
		t.Fatalf("a range reaching into the ephemeral ports also matches replies:\n%s", got)
	}
	// ntcept's own forwarding connections must be exempt, or forwarding loops back into ntcept.
	if !strings.Contains(got, "no rdr on lo0 inet proto tcp from "+ForwardIP) {
		t.Fatalf("ntcept's own forwarding source is not exempt:\n%s", got)
	}
}

// Per-port rules are what let two sessions each capture their own localhost traffic.
func TestPerPortRulesNameOnlyTheirOwnPorts(t *testing.T) {
	got := ruleset{Anchor: "a", Iface: "utun9", GID: 33333, Local: map[int]int{5432: 40001}}.text()
	if !strings.Contains(got, "port 5432 -> 127.0.0.1 port 40001") {
		t.Fatalf("the service port is not redirected to this session's listener:\n%s", got)
	}
	if strings.Contains(got, "port 1:") {
		t.Fatalf("a per-port ruleset must not contain a catch-all:\n%s", got)
	}
}

// Filter and translation rules are always written together: loading one half of an anchor
// discards the other, so a second session would otherwise wipe the first one's redirects.
func TestRulesetAlwaysCarriesBothHalves(t *testing.T) {
	got := ruleset{Anchor: "a", Iface: "utun9", GID: 33333, Local: map[int]int{5432: 40001}}.text()
	if !strings.Contains(got, "pass out quick route-to") {
		t.Fatal("a ruleset with redirects dropped the egress rule; loading it would remove it")
	}
	if !strings.Contains(got, "rdr pass on lo0") {
		t.Fatal("a ruleset with redirects dropped them")
	}
}

func TestTheAnchorIsNamespacedToNtcept(t *testing.T) {
	if !strings.Contains(AnchorPrefix, "ntcept") {
		t.Fatalf("the anchor must be identifiable as ours so cleanup cannot flush someone "+
			"else's rules: %q", AnchorPrefix)
	}
}

// pf requires its ruleset in a fixed order and rejects the whole file otherwise — translation
// before filtering. Getting it backwards left a session with no redirects and no diagnosis
// beyond "Rules must be in order".
func TestTranslationRulesComeBeforeFilterRules(t *testing.T) {
	for _, r := range []ruleset{
		{Anchor: "a", Iface: "utun9", GID: 33333, Local: map[int]int{5432: 40001}},
		{Anchor: "a", Iface: "utun9", GID: 33333, CatchAll: 40000},
	} {
		got := r.text()
		rdr := strings.Index(got, "rdr")
		pass := strings.Index(got, "pass out")
		if rdr < 0 || pass < 0 {
			t.Fatalf("expected both halves:\n%s", got)
		}
		if rdr > pass {
			t.Fatalf("pf rejects a ruleset with translation after filtering:\n%s", got)
		}
	}
}

// A lock file carries the holder's pid and may carry more beside it. Reading the whole of it as
// one number made every published lock look stale, so a second session took a group that was
// already in use and the two shared an anchor — the exact failure the groups exist to prevent.
func TestALockWithMoreThanAPIDIsStillReadable(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		content string
		want    int
	}{
		{"4242\n", 4242},
		{"4242 55902\n", 4242},
		{"4242 55902", 4242},
		{"", 0},
		{"nonsense\n", 0},
	} {
		path := dir + "/lock"
		if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := readLockPID(path); got != tc.want {
			t.Errorf("readLockPID(%q) = %d, want %d", tc.content, got, tc.want)
		}
	}
}
