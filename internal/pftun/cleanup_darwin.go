//go:build darwin

package pftun

import (
	"os/exec"
	"strings"
)

// Cleanup flushes ntcept's pf anchor and reports how many rules it removed. Safe to run at any
// time: it touches nothing outside the anchor.
// Cleanup removes what a crashed run left behind: the anchors of sessions that are no longer
// running, and the forwarding alias if nothing is using it. A live session's rules are left
// alone, so cleaning up after one crash does not take down a run that is working.
func Cleanup() (int, error) {
	// pfctl needs root, and under `sudo ntcept cleanup` the lock files still belong to the
	// invoking user — read them under that identity, not root's, or staleAnchors finds nothing.
	if uid, _, err := SudoUID(); err == nil {
		UseLocksOf(uid)
	}
	removed := 0
	for _, anchor := range staleAnchors() {
		out, err := exec.Command("pfctl", "-a", anchor, "-s", "rules").Output()
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if strings.TrimSpace(line) != "" {
					removed++
				}
			}
		}
		flushAnchorFor(anchor)
	}
	// The alias belongs to whichever sessions are capturing loopback; only take it away when
	// none are left. Checked without acquiring, so cleanup leaves no lock file of its own behind.
	if _, held := loopbackHeld(); !held {
		removeForwardAlias()
	}
	return removed, nil
}
