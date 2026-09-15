//go:build darwin

package pftun

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

// ruleset is everything one session asks pf to do. It is emitted as a whole every time any part
// of it changes, because loading an anchor's filter rules discards its translation rules —
// measured: a second session starting wiped the first session's redirects without touching its
// own. One anchor per session, one load, no interaction between the two halves.
type ruleset struct {
	Anchor string
	Iface  string // the utun this session's egress is steered into
	GID    int    // the group this session's processes run under
	// Local maps a loopback port the application talks to onto the port this session accepts
	// it on. Empty when loopback is not being captured.
	Local map[int]int
	// CatchAll, when set, redirects every loopback port below the ephemeral floor to it,
	// instead of naming ports. Only a session that is alone on the machine may use it: the rule
	// cannot be scoped to a process, so two of them would fight over every connection.
	CatchAll int
}

// text renders the ruleset.
//
// route-to names the interface explicitly. An address-only form parses and does not divert
// locally generated traffic, which fails silently as an application that never connects.
//
// Loopback is excluded from the egress rule for a subtle reason: pf will divert a
// loopback packet into the utun, but ntcept's reply carries a loopback source address on a
// non-loopback interface and XNU discards it before the process sees it. Loopback is handled by
// redirect instead, below.
func (r ruleset) text() string {
	var b strings.Builder
	// Translation rules come first. pf requires its ruleset in a fixed order — options,
	// normalization, queueing, translation, filtering — and rejects the whole file otherwise,
	// with every rule after the first misplaced one reported as out of order.
	if r.CatchAll > 0 || len(r.Local) > 0 {
		// ntcept's own connection to the service it is intercepting must not be redirected
		// back into ntcept, which would be an endless loop. A source address is the only thing
		// a redirect rule can match on for that: pf allows user and group on filter rules only.
		fmt.Fprintf(&b, "no rdr on lo0 inet proto tcp from %s to any\n", ForwardIP)
	}
	switch {
	case r.CatchAll > 0:
		// The range stops below the ephemeral floor deliberately. A redirect covering every
		// port also matches the replies — loopback carries a packet past the filter in both
		// directions — so the answer travelling back to the client's ephemeral port is
		// redirected a second time and the connection is stranded. Measured, as a rule pf
		// accepts and holds while every connection through it times out.
		fmt.Fprintf(&b, "rdr pass on lo0 inet proto tcp from ! %s to 127.0.0.0/8 "+
			"port 1:%d -> 127.0.0.1 port %d\n", ForwardIP, ephemeralFloor()-1, r.CatchAll)
	default:
		for _, from := range sortedKeys(r.Local) {
			fmt.Fprintf(&b, "rdr pass on lo0 inet proto tcp from ! %s to 127.0.0.0/8 "+
				"port %d -> 127.0.0.1 port %d\n", ForwardIP, from, r.Local[from])
		}
	}
	for _, proto := range []string{"tcp", "udp"} {
		fmt.Fprintf(&b, "pass out quick route-to (%s %s) inet proto %s "+
			"from any to ! 127.0.0.0/8 group %d keep state\n", r.Iface, tunnel.HostIP, proto, r.GID)
	}
	return b.String()
}

// apply loads the ruleset, replacing whatever this session had before.
func (r ruleset) apply() error {
	if r.CatchAll > 0 || len(r.Local) > 0 {
		if err := addForwardAlias(); err != nil {
			return err
		}
	}
	cmd := exec.Command("pfctl", "-a", r.Anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(r.text())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("loading pf rules: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// Loading is not behaving: pfctl can accept a rule that pf does not actually hold, which
	// surfaces as an application whose connections simply hang. Read it back and confirm.
	out, err := exec.Command("pfctl", "-a", r.Anchor, "-s", "rules").Output()
	if err != nil {
		return fmt.Errorf("reading back the pf anchor: %w", err)
	}
	if !strings.Contains(string(out), r.Iface) {
		return fmt.Errorf("pf accepted the rules but is not holding them (anchor %s is %q)",
			r.Anchor, strings.TrimSpace(string(out)))
	}
	return nil
}

// ForwardIP is the address ntcept makes its own forwarding connections from, so a pf rule can
// tell them apart from the application's. It is an alias on lo0 that the helper adds; macOS,
// unlike Linux, does not treat the whole of 127/8 as local until told to.
const ForwardIP = "127.0.0.2"

func sortedKeys(m map[int]int) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

// addForwardAlias gives lo0 the address ntcept forwards from.
func addForwardAlias() error {
	out, err := exec.Command("ifconfig", "lo0", "alias", ForwardIP, "netmask", "255.255.255.255").
		CombinedOutput()
	if err != nil {
		return fmt.Errorf("adding %s to lo0: %w: %s", ForwardIP, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ephemeralFloor is the lowest port the kernel hands out to a client that did not ask for a
// particular one. Nothing at or above it may be redirected: a rule there would also match a
// reply travelling back to a client the kernel gave that port, and ntcept's own listeners live
// in that range.
func ephemeralFloor() int {
	const fallback = 49152
	out, err := exec.Command("sysctl", "-n", "net.inet.ip.portrange.first").Output()
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || n < 1024 || n > 65535 {
		return fallback
	}
	return n
}

var tokenRe = regexp.MustCompile(`Token\s*:\s*(\d+)`)

// enable turns pf on and returns its reference token. pf counts enable requests, so releasing
// the token later leaves pf exactly as it was found.
func enable() (string, error) {
	out, err := exec.Command("pfctl", "-E").CombinedOutput()
	if err != nil && !bytes.Contains(out, []byte("Token")) {
		return "", fmt.Errorf("enabling pf: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if m := tokenRe.FindSubmatch(out); m != nil {
		return string(m[1]), nil
	}
	return "", nil
}

func release(token string) {
	if token != "" {
		_ = exec.Command("pfctl", "-X", token).Run()
	}
}

func ifconfigUp(iface string) error {
	out, err := exec.Command("ifconfig", iface, tunnel.PeerIP, tunnel.HostIP, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("configuring %s: %w: %s", iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// flushAnchorFor removes every rule one session added. Nothing else in pf is touched, which is
// what lets a session be killed without disturbing another one.
func flushAnchorFor(anchor string) {
	_ = exec.Command("pfctl", "-a", anchor, "-F", "all").Run()
}

// removeForwardAlias takes the forwarding address back off lo0, once no session needs it.
func removeForwardAlias() {
	_ = exec.Command("ifconfig", "lo0", "-alias", ForwardIP).Run()
}
