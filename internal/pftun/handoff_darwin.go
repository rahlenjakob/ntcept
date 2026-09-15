//go:build darwin

package pftun

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Handing a connection to the session it belongs to.
//
// One redirect rule covering every loopback port is what captures a service from its first
// connection, without anyone naming ports in advance. It has one consequence that has to be
// dealt with rather than lived with: pf cannot scope a redirect to a process — user and group
// are filter options and the redirect grammar has no room for them — so a single listener
// receives every loopback connection on the machine, whoever made it.
//
// Attribution already says which process that was, and each session runs its processes under a
// group of its own, so the group says which session. A connection belonging to another session
// is handed to it: the receiving session captures it as its own, in its own buffer, subject to
// its own holds. Without this the second session would see nothing, because the first one's rule
// had already taken the traffic.
//
// The header is one line so the receiving end needs no framing beyond what bufio gives it.
const handoffMagic = "ntcept-handoff"

// intake publishes where this session can be handed connections that belong to it.
type intake struct {
	ln   net.Listener
	port int
}

func (lc *localCapture) startIntake() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("opening the handoff intake: %w", err)
	}
	lc.mu.Lock()
	lc.intake = &intake{ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
	lc.listeners = append(lc.listeners, ln)
	lc.mu.Unlock()
	go lc.serveIntake(ln)
	return publishIntake(lc.gid, ln.Addr().(*net.TCPAddr).Port, lc.token)
}

// handoffToken returns an unguessable value for a session to prove a handoff is genuinely from
// this user. It is written only into a 0700 directory, so reading it back is the proof.
func handoffToken() int64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read does not fail in practice; a weak fallback still beats no token.
		return time.Now().UnixNano()
	}
	v := int64(binary.LittleEndian.Uint64(b[:]))
	if v < 0 {
		v = -v
	}
	return v
}

func (lc *localCapture) serveIntake(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go lc.acceptHandoff(c)
	}
}

// acceptHandoff reads the destination the other session recovered from pf, then treats the
// connection exactly as one that had arrived here directly.
//
// The header carries a token this session wrote into its own 0700 intake file; a connector that
// presents it has proved it could read that file and so is the same user. Anything else is
// refused, because the intake port is reachable by every local process.
func (lc *localCapture) acceptHandoff(c net.Conn) {
	// A genuine handoff is one short line; do not read unboundedly from a port any local
	// process can reach.
	br := bufio.NewReader(io.LimitReader(c, 512))
	line, err := br.ReadString('\n')
	if err != nil {
		c.Close()
		return
	}
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) != 4 || f[0] != handoffMagic {
		if dbgLocal {
			lc.say("[diag] intake got an unrecognised header %q", strings.TrimSpace(line))
		}
		c.Close()
		return
	}
	token, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil || token != lc.token {
		if dbgLocal {
			lc.say("[diag] intake rejected a handoff with the wrong token")
		}
		c.Close()
		return
	}
	host := f[2]
	if !isLoopbackHost(host) {
		// The only legitimate handoff target is loopback; refuse to be pointed elsewhere.
		c.Close()
		return
	}
	port, err := strconv.Atoi(f[3])
	if err != nil || port <= 0 || port > 65535 {
		c.Close()
		return
	}
	if dbgLocal {
		lc.say("[diag] intake received %s:%d", host, port)
	}
	// The reader may hold bytes the client already sent; hand them on with the connection. The
	// header read was bounded to 512 bytes; the rest of the stream is not, so reads continue
	// from the raw connection once that buffer is drained.
	lc.proxy.HandleTransparent(&bufferedConn{Conn: c, r: &drainThen{br: br, c: c}}, host, port)
}

func isLoopbackHost(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// drainThen returns the bytes already buffered while reading the header, then reads the rest
// straight from the connection. The header was read through a bounded reader, so it cannot be
// read past here — but the payload that follows must not be.
type drainThen struct {
	br *bufio.Reader
	c  net.Conn
}

func (d *drainThen) Read(p []byte) (int, error) {
	if d.br != nil && d.br.Buffered() > 0 {
		return d.br.Read(p)
	}
	return d.c.Read(p)
}

// forwardToSession connects to another session's intake and relays the connection into it. The
// token comes from that session's intake file, which only this user can read — presenting it is
// how the receiving session knows the handoff is genuine.
func (lc *localCapture) forwardToSession(c net.Conn, gid int, host string, port int) bool {
	intakePort, token, ok := readIntake(gid)
	if !ok {
		if dbgLocal {
			lc.say("[diag] no intake advertised for group %d", gid)
		}
		return false
	}
	up, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(intakePort)))
	if err != nil {
		if dbgLocal {
			lc.say("[diag] intake %d for group %d unreachable: %v", intakePort, gid, err)
		}
		return false
	}
	if _, err := fmt.Fprintf(up, "%s %d %s %d\n", handoffMagic, token, host, port); err != nil {
		up.Close()
		if dbgLocal {
			lc.say("[diag] handoff header to group %d failed: %v", gid, err)
		}
		return false
	}
	if dbgLocal {
		lc.say("[diag] handed %s:%d to group %d at intake %d", host, port, gid, intakePort)
	}
	go func() {
		defer c.Close()
		defer up.Close()
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
		<-done
	}()
	return true
}

// bufferedConn hands on bytes already read from the wire along with the connection.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// publishIntake records where this session can be handed connections, beside the lock that
// reserves its group. One file, so a session that dies takes its advertisement with it.
func publishIntake(gid, port int, token int64) error {
	_ = os.MkdirAll(lockDir(), 0o700)
	path := namedLockPath(fmt.Sprintf("gid-%d", gid))
	return os.WriteFile(path, []byte(fmt.Sprintf("%d %d %d\n", os.Getpid(), port, token)), 0o600)
}

// readIntake finds where a session accepts handed-off connections and the token that authorises
// one, if it is still running.
func readIntake(gid int) (port int, token int64, ok bool) {
	b, err := os.ReadFile(namedLockPath(fmt.Sprintf("gid-%d", gid)))
	if err != nil {
		return 0, 0, false
	}
	pid, port, token, ok := parseIntake(b)
	if !ok || !processAlive(pid) {
		return 0, 0, false
	}
	return port, token, true
}

// parseIntake reads the "pid port token" an intake file carries. A file with only "pid port" is
// from a session before tokens existed and is refused — a handoff without a token cannot be
// authenticated, so there is nothing to hand it.
func parseIntake(b []byte) (pid, port int, token int64, ok bool) {
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return 0, 0, 0, false
	}
	pid, err := strconv.Atoi(f[0])
	if err != nil {
		return 0, 0, 0, false
	}
	port, err = strconv.Atoi(f[1])
	if err != nil || port <= 0 || port > 65535 {
		return 0, 0, 0, false
	}
	token, err = strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return 0, 0, 0, false
	}
	return pid, port, token, true
}

// watchForOwnership takes over the loopback redirect if the session holding it goes away.
//
// Only one session installs the redirect, so when that one dies the others would otherwise lose
// their view of localhost for the rest of their run — and a session killed outright leaves its
// rules behind, pointing at a listener that is gone, so localhost would be worse than
// uncaptured. Whoever notices first takes the lock and installs its own.
func (lc *localCapture) watchForOwnership(ctx context.Context, helper *helperClient) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if lc.owner {
			return
		}
		lock, _, got := acquireLoopbackLock()
		if !got {
			continue
		}
		lc.owner = true
		lc.takeOver(helper)
		// The lock is held for the rest of the run; releasing it is the process exiting.
		_ = lock
		return
	}
}

// takeOver installs this session's own redirect, the same way it would have at startup.
func (lc *localCapture) takeOver(helper *helperClient) {
	probeRule, probing := lc.prepareProbe()
	if !probing {
		return
	}
	if err := helper.tell(handover{CaptureLocal: probeRule}); err != nil {
		return
	}
	catchLn, catchPort, ok := lc.prove()
	if !ok {
		return
	}
	if err := helper.tell(handover{CatchAll: catchPort}); err != nil || !lc.confirmCatchAll(catchLn) {
		catchLn.Close()
		return
	}
	lc.startCatchAll(catchLn)
	lc.say("the ntcept that was redirecting localhost has gone; this session has taken it on")
}
