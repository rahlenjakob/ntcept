//go:build darwin

package pftun

import (
	"fmt"
	"os"
)

// Each ntcept gets its own marker group and its own pf anchor.
//
// Sharing them was silently wrong. Every supervised process ran under one group and every rule
// lived in one anchor, so a second `ntcept run` replaced the first one's rules and then claimed
// its traffic: measured, with one session's requests appearing in the other session's buffer and
// nothing in its own. Traffic attributed to the wrong application is worse than traffic not
// captured, and it is the kind of wrong a person would act on.
//
// A group per session makes the pf rule match only that session's processes, and gives
// attribution something to tell them apart by. An anchor per session means neither session can
// load rules over the other's, and — the part that matters when something goes wrong — a session
// that dies flushes only its own.
const (
	// markerGIDBase is where the per-session groups start. The range is deliberately in the
	// space macOS leaves free for local use.
	markerGIDBase = 33333
	markerGIDSpan = 64
)

// markerGroup is one session's reservation of a group id.
type markerGroup struct {
	GID  int
	lock *loopbackLock
}

// Anchor is where this session's rules live. Naming it after the group keeps the two impossible
// to get out of step, and `com.apple/*` in the stock /etc/pf.conf evaluates it without ntcept
// touching that file.
func (m markerGroup) Anchor() string {
	return fmt.Sprintf("%s-%d", AnchorPrefix, m.GID)
}

// acquireMarkerGroup reserves a group nobody else is using.
func acquireMarkerGroup() (markerGroup, bool) {
	for i := 0; i < markerGIDSpan; i++ {
		gid := markerGIDBase + i
		lock, _, ok := acquireNamedLock(fmt.Sprintf("gid-%d", gid))
		if ok {
			return markerGroup{GID: gid, lock: lock}, true
		}
	}
	return markerGroup{}, false
}

func (m markerGroup) release() { m.lock.release() }

// staleAnchors names the anchors of sessions that are no longer running, so a crash does not
// leave rules behind that outlive it. The group's lock file is the evidence: it holds the pid.
func staleAnchors() []string {
	var out []string
	for i := 0; i < markerGIDSpan; i++ {
		gid := markerGIDBase + i
		path := namedLockPath(fmt.Sprintf("gid-%d", gid))
		if _, err := os.Stat(path); err != nil {
			continue
		}
		if pid := readLockPID(path); pid == 0 || !processAlive(pid) {
			out = append(out, fmt.Sprintf("%s-%d", AnchorPrefix, gid))
			_ = os.Remove(path)
		}
	}
	return out
}
