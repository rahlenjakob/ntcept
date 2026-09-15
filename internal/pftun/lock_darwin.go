//go:build darwin

package pftun

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Loopback capture is held by one ntcept at a time, machine-wide.
//
// It has to be. The redirect rules live in a pf anchor that is a property of the machine, not of
// a session: loading them replaces whatever was there, so a second ntcept silently takes the
// first one's rules away. Worse, every supervised process runs under the same marker group, so
// the second session cannot tell the first session's application from its own — measured, and it
// captured the other session's traffic as if it were its own. Traffic attributed to the wrong
// application is a worse failure than traffic not captured at all.
//
// So the second session does without. Its egress interception is unaffected, which is the larger
// half of what ntcept does; only its view of localhost is given up, and it is told so.
//
// The lock is per user, because the anchor is shared but a lock in a shared directory should not
// be something another account can hold against you.
type loopbackLock struct{ path string }

// lockUID is whose locks these are. It is the invoking user, not necessarily the process's own
// uid: the privileged helper runs as root and has to read the same files ntcept wrote as the
// user, and looking under root's identity meant it found none of them — so it never noticed a dead
// session's rules and never flushed them.
var lockUID = os.Getuid()

// UseLocksOf points the lock paths at a particular user. The helper (running as root) and
// `sudo ntcept cleanup` both call it with the invoking user's uid.
func UseLocksOf(uid int) { lockUID = uid }

// lockDir is where the coordination files live.
//
// It is derived from the invoking user's home directory, looked up by uid — deliberately NOT from
// os.TempDir(). On macOS launchd sets $TMPDIR per-user, and sudo does not preserve it, so the root
// helper's os.TempDir() is not the user's. The lock files coordinate the user's ntcept processes
// with the root helper, and if the two read different directories the helper never sees a dead
// session's lock and never reaps its pf anchor. Looking the home up by uid gives both sides the
// same answer regardless of environment.
//
// ~/.ntcept is 0700 and user-owned, so no other user can read a token or forge a lock, and root
// can still read and remove them.
func lockDir() string {
	if u, err := user.LookupId(strconv.Itoa(lockUID)); err == nil && u.HomeDir != "" {
		return filepath.Join(u.HomeDir, ".ntcept", "run")
	}
	// A uid with no home entry is not something a laptop hits; the fallback still avoids
	// $TMPDIR so both sides agree, at the cost of living under world-writable /tmp.
	return filepath.Join("/tmp", fmt.Sprintf("ntcept-run-%d", lockUID))
}

func namedLockPath(name string) string {
	return filepath.Join(lockDir(), name+".lock")
}

// acquireLoopbackLock takes the lock on loopback capture, or reports who holds it.
func acquireLoopbackLock() (*loopbackLock, int, bool) {
	return acquireNamedLock("loopback")
}

// acquireNamedLock takes a machine-wide lock, or reports the live process holding it.
func acquireNamedLock(name string) (*loopbackLock, int, bool) {
	_ = os.MkdirAll(lockDir(), 0o700)
	path := namedLockPath(name)
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n", os.Getpid())
			f.Close()
			return &loopbackLock{path: path}, 0, true
		}
		holder := readLockPID(path)
		// A session killed hard leaves the file behind. The pid in it is the only way to tell
		// that from a session that is still running.
		if holder == 0 || !processAlive(holder) {
			_ = os.Remove(path)
			continue
		}
		return nil, holder, false
	}
	return nil, 0, false
}

func (l *loopbackLock) release() {
	if l == nil {
		return
	}
	// Only remove it if it is still ours, so a session that took over after a crash is not
	// robbed of it.
	if readLockPID(l.path) == os.Getpid() {
		_ = os.Remove(l.path)
	}
}

// readLockPID reads the holder's pid, which is the first field. The file may carry more — a
// session also advertises where it can be handed connections — and reading the whole of it as
// one number made every published lock look stale, so the next session took a group that was
// already in use and the two shared an anchor again.
func readLockPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	n, err := strconv.Atoi(f[0])
	if err != nil {
		return 0
	}
	return n
}

// loopbackHeld reports whether a live session holds the loopback-capture lock, without acquiring
// it. Cleanup used to test this by acquiring the lock and discarding it, which left a stale lock
// file behind carrying cleanup's own, now-exiting, pid.
func loopbackHeld() (int, bool) {
	pid := readLockPID(namedLockPath("loopback"))
	if pid != 0 && processAlive(pid) {
		return pid, true
	}
	return 0, false
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
