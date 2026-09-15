//go:build darwin

package pftun

import (
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rahlenjakob/ntcept/internal/pfnat"
	"github.com/rahlenjakob/ntcept/internal/procs"
	"github.com/rahlenjakob/ntcept/internal/proxy"
)

// localCapture is the macOS answer to seeing an application talk to a service on this machine —
// a local database, or another service the user started.
//
// The tunnel cannot carry that traffic. pf will divert a loopback packet into the utun, but
// ntcept's reply has source 127.0.0.1 and arrives back on a utun, and the host's own stack drops
// it before the process sees it; a packet trace confirms it. A pf redirect never
// leaves lo0, so the question does not arise — at the cost that a redirect cannot be scoped to a
// process, because pf allows user and group only on filter rules.
//
// So the scoping happens here instead. Every connection is attributed to the process that opened
// it, and one that is not part of the supervised application is spliced straight through without
// being captured, listed, or — the part that matters most — held. Holding a stranger's database
// query would stall an application nobody is debugging.
var dbgLocal = os.Getenv("NTCEPT_DEBUG") != ""

type localCapture struct {
	proxy *proxy.Server
	attr  *procs.Attributor
	out   io.Writer

	// helper answers what a redirected connection was originally aimed at. Until that is
	// proved to work, ntcept relies on one listener per port instead — see checkNatlook.
	helper      *helperClient
	catchAll    net.Listener
	probe       net.Listener
	probeTarget int
	natlookOK   atomic.Bool

	gid    int
	intake *intake
	// token authenticates a handoff. It is written into the session's intake file, which lives
	// in a 0700 user-owned directory, so only the same user can read it — a connector that
	// presents it has proved it could read that file, i.e. is this user. Without it the intake
	// port (bound to 127.0.0.1, reachable by every local user) would accept a connection from
	// anyone and dial wherever they named.
	token int64
	// owner says this session installed the loopback redirect. Only one session on the machine
	// can: a redirect cannot be scoped to a process, so a second rule would simply compete for
	// the same connections. The others install nothing and are handed the connections that
	// belong to them.
	owner bool

	mu        sync.Mutex
	listeners []net.Listener
	portLocks []*loopbackLock
	// Ports maps the port the application dials to the port ntcept accepts it on. It is what
	// the helper turns into redirect rules.
	Ports map[int]int
}

// newLocalCapture takes a listener for each port, before the helper is told to redirect
// anything: a redirect pointing at a port nothing is accepting on would black-hole the user's
// own database connections.
func newLocalCapture(px *proxy.Server, ports []int, helper *helperClient, gid int, out io.Writer) (*localCapture, error) {
	lc := &localCapture{
		proxy:  px,
		attr:   procs.NewAttributor(gid),
		out:    out,
		helper: helper,
		gid:    gid,
		token:  handoffToken(),
		Ports:  map[int]int{},
	}
	// Only what this session is told to capture, and later what its own application is seen to
	// talk to. Arming every service already listening on the machine was worse than it sounds:
	// two sessions each claimed all of them, and since a port can only be redirected to one
	// listener, whichever loaded its rules first received the other session's traffic too —
	// which its attribution then correctly refused to capture, so the second session saw
	// nothing at all. Claiming only what you use is what lets two sessions coexist.
	if err := lc.add(ports); err != nil {
		lc.Close()
		return nil, err
	}
	return lc, nil
}

// add opens a listener for each port not already covered, and reports whether anything changed.
func (lc *localCapture) add(ports []int) error {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	for _, p := range ports {
		if _, have := lc.Ports[p]; have || p <= 0 {
			continue
		}
		// One session per loopback port, machine-wide. A port can only be redirected to one
		// listener, so two sessions claiming the same service would send one session's traffic
		// to the other, where attribution refuses it — correctly, and silently.
		lock, holder, got := acquireNamedLock(fmt.Sprintf("port-%d", p))
		if !got {
			lc.say("localhost:%d is already being captured by another ntcept (pid %d); this "+
				"run leaves it alone", p, holder)
			continue
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			lock.release()
			return fmt.Errorf("listening for redirected port %d: %w", p, err)
		}
		lc.listeners = append(lc.listeners, ln)
		lc.portLocks = append(lc.portLocks, lock)
		lc.Ports[p] = ln.Addr().(*net.TCPAddr).Port
		go lc.serve(ln, p)
	}
	return nil
}

func (lc *localCapture) portMap() map[int]int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	out := make(map[int]int, len(lc.Ports))
	for k, v := range lc.Ports {
		out[k] = v
	}
	return out
}

// watch notices the local services the application talks to and starts capturing them, so that
// nobody has to name a port in advance.
//
// It can only learn a port from a connection that already happened, so the first connection to
// each service is carried without being captured and everything after it is seen. That is the
// price of not interposing on every loopback port on the machine, which is what redirecting
// blindly would mean — pf cannot scope a redirect to a process, so a rule for a port is a rule
// for every process using it.
func (lc *localCapture) watch(ctx context.Context, reload func(map[int]int) error) {
	tick := time.NewTicker(700 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		found := lc.attr.LoopbackTargets()
		if len(found) == 0 {
			continue
		}
		before := lc.portMap()
		var fresh []int
		for _, p := range found {
			if _, had := before[p]; !had {
				fresh = append(fresh, p)
			}
		}
		if len(fresh) == 0 {
			continue
		}
		if err := lc.add(fresh); err != nil {
			continue
		}
		if err := reload(lc.portMap()); err != nil {
			fmt.Fprintf(lc.out, "ntcept: could not extend the loopback capture: %v\n", err)
			continue
		}
		lc.announceNew(fresh)
	}
}

func (lc *localCapture) announceNew(ports []int) {
	for _, p := range ports {
		fmt.Fprintf(lc.out, "ntcept: now capturing localhost:%d — the first connection to it "+
			"was carried but not recorded\n", p)
	}
}

func (lc *localCapture) serve(ln net.Listener, original int) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go lc.handle(c, original)
	}
}

func (lc *localCapture) handle(c net.Conn, original int) {
	src, _ := c.RemoteAddr().(*net.TCPAddr)
	if src == nil {
		c.Close()
		return
	}
	if original == 0 {
		// Arrived on the catch-all, so only pf knows where it was going.
		local, _ := c.LocalAddr().(*net.TCPAddr)
		got, err := lc.helper.natlook(NatlookReq{
			SrcIP: src.IP.String(), SrcPort: src.Port,
			DstIP: local.IP.String(), DstPort: local.Port,
		})
		if err == nil {
			err = pfnat.Plausible(got, local.Port)
		}
		if err != nil {
			// Without the original destination there is nowhere to forward to, so the
			// connection cannot be saved. Say so rather than dropping it in silence, which
			// is how this last went wrong: two sessions, no traffic, and no explanation.
			if dbgLocal {
				lc.say("[diag] could not recover the destination of a redirected "+
					"connection from %s: %v", src, err)
			}
			c.Close()
			return
		}
		original = got.Port
	}
	// The owner and the group it runs under come from one snapshot: the processes this has to
	// attribute are often gone a moment later, and asking twice reported every one of them as
	// ownerless.
	owner, gid, ours := lc.attr.Attribute(src.Port)
	if dbgLocal {
		lc.say("[diag] dst=%d src=%d owner=%v gid=%d ours=%v mine=%d",
			original, src.Port, owner, gid, ours, lc.gid)
	}
	if !ours {
		// Every loopback connection on the machine arrives here, because pf cannot scope a
		// redirect to a process. One belonging to another ntcept session is handed to it, so
		// that session sees its own traffic rather than losing it to this rule. Anything else
		// is none of ntcept's business: carried through, and nothing about it recorded.
		if gid >= markerGIDBase && gid < markerGIDBase+markerGIDSpan && gid != lc.gid {
			if lc.forwardToSession(c, gid, "127.0.0.1", original) {
				return
			}
		}
		lc.splice(c, original)
		return
	}
	_ = owner
	// From here it is an ordinary intercepted connection, and takes the same path as one that
	// arrived over the tunnel: decoded, captured, and holdable.
	lc.proxy.HandleTransparent(c, "127.0.0.1", original)
}

// Prove establishes, before the command starts, whether pf can report what a redirected
// connection was originally aimed at — and if it can, installs one catch-all redirect instead of
// one rule per port, so a service that starts later is captured from its first connection too.
//
// It has to happen here, with no real traffic in flight. Replacing pf's translation ruleset
// discards the NAT state of connections it already translated, so swapping rules while the
// application is using one kills that connection: verifying on a live connection would break
// the very request used to verify it.
//
// The proof is a connection ntcept makes to itself. A rule is loaded for a port nothing is
// listening on; ntcept connects to it, and the connection can only arrive at the probe listener
// if pf redirected it. Asking pf where it was going then has a known right answer, which is the
// only way to check a struct layout reconstructed from a kernel-private header.
// freeLowPort finds a port nothing is listening on, below the ephemeral floor.
//
// It has to be below the floor because that is where the catch-all redirect stops — a probe
// aimed above it would be testing a port the rule deliberately does not cover, and would report
// the mechanism broken when it is working. Found by binding: a port that binds is free, and
// releasing it immediately leaves it free for the redirect to be the only thing that answers.
func freeLowPort() (int, bool) {
	floor := ephemeralFloor()
	const low = 20000
	if floor <= low {
		return 0, false
	}
	for i := 0; i < 40; i++ {
		port := low + rand.IntN(floor-low)
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		ln.Close()
		return port, true
	}
	return 0, false
}

func (lc *localCapture) prepareProbe() (map[int]int, bool) {
	if lc.helper == nil {
		return nil, false
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, false
	}
	// A destination nothing is listening on: reserved to be sure it is free, then released, so
	// the connection below can only succeed by having been redirected.
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		probe.Close()
		return nil, false
	}
	target := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()

	lc.probe = probe
	lc.probeTarget = target
	return map[int]int{target: probe.Addr().(*net.TCPAddr).Port}, true
}

// prove runs the check once the probe rule is loaded, and on success opens the catch-all
// listener and returns its port.
func (lc *localCapture) prove() (net.Listener, int, bool) {
	if lc.probe == nil {
		return nil, 0, false
	}
	defer func() {
		lc.probe.Close()
		lc.probe = nil
	}()

	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		c, err := lc.probe.Accept()
		accepted <- result{c, err}
	}()

	// The rule is loaded by the helper a moment after it reads the handover, so a refusal here
	// means "not yet" as often as it means "never". Nothing is listening on the target, so the
	// first connection that succeeds is necessarily one pf redirected.
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	addr := fmt.Sprintf("127.0.0.1:%d", lc.probeTarget)
	var out net.Conn
	var err error
	deadline := time.Now().Add(4 * time.Second)
	for {
		if out, err = dialer.Dial("tcp", addr); err == nil {
			break
		}
		if time.Now().After(deadline) {
			lc.say("pf did not redirect a loopback connection (%v)", err)
			return nil, 0, false
		}
		time.Sleep(75 * time.Millisecond)
	}
	defer out.Close()

	var got result
	select {
	case got = <-accepted:
	case <-time.After(3 * time.Second):
		lc.say("a redirected loopback connection never arrived")
		return nil, 0, false
	}
	if got.err != nil {
		return nil, 0, false
	}
	defer got.conn.Close()

	src, _ := got.conn.RemoteAddr().(*net.TCPAddr)
	local, _ := got.conn.LocalAddr().(*net.TCPAddr)
	if src == nil || local == nil {
		return nil, 0, false
	}
	answer, err := lc.helper.natlook(NatlookReq{
		SrcIP: src.IP.String(), SrcPort: src.Port,
		DstIP: local.IP.String(), DstPort: local.Port,
	})
	if err != nil {
		lc.say("pf cannot report original destinations (%v)", err)
		return nil, 0, false
	}
	if err := pfnat.Plausible(answer, local.Port); err != nil {
		lc.say("pf's answer is unusable (%v)", err)
		return nil, 0, false
	}
	if answer.Port != lc.probeTarget {
		lc.say("pf reported the original destination as %d but it was %d; the lookup cannot "+
			"be trusted", answer.Port, lc.probeTarget)
		return nil, 0, false
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, false
	}
	return ln, ln.Addr().(*net.TCPAddr).Port, true
}

// confirmCatchAll checks that the catch-all rule really does redirect, before anything depends
// on it.
//
// Proving the lookup is not the same as proving the rule. A redirect written without a port
// range loads, is held by pf, and matches nothing — connections to the port it should catch get
// no answer at all. Rather than trust the rule text, ntcept connects to a port nothing is
// listening on and requires the connection to arrive here. If it does not, the per-port rules
// stand and the run is unaffected.
// diagnoseCatchAll reports which destination ports a catch-all redirect actually delivers.
// Enabled with NTCEPT_DEBUG; it exists to answer why a rule pf accepts can match nothing.
func (lc *localCapture) diagnoseCatchAll(ln net.Listener) {
	arrived := make(chan int, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if la, ok := c.LocalAddr().(*net.TCPAddr); ok {
				arrived <- la.Port
			}
			c.Close()
		}
	}()
	unused, _ := freeLowPort()
	for _, port := range []int{1, 80, 1024, 5432, unused} {
		if port == 0 {
			continue
		}
		d := &net.Dialer{Timeout: 1200 * time.Millisecond}
		c, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		got := "no"
		select {
		case <-arrived:
			got = "YES"
		case <-time.After(250 * time.Millisecond):
		}
		status := "connected"
		if err != nil {
			status = err.Error()
		} else {
			c.Close()
		}
		fmt.Fprintf(lc.out, "ntcept: [diag] dst=%-6d arrived-at-catch-all=%-3s dial=%s\n",
			port, got, status)
	}
}

func (lc *localCapture) confirmCatchAll(ln net.Listener) bool {
	if os.Getenv("NTCEPT_DEBUG") != "" {
		lc.diagnoseCatchAll(ln)
	}
	target, ok := freeLowPort()
	if !ok {
		return false
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
		close(accepted)
	}()

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	addr := fmt.Sprintf("127.0.0.1:%d", target)
	var out net.Conn
	var derr error
	deadline := time.Now().Add(4 * time.Second)
	for {
		if out, derr = dialer.Dial("tcp", addr); derr == nil {
			break
		}
		if time.Now().After(deadline) {
			lc.say("the catch-all redirect does not match (%v); each loopback service is "+
				"captured from its second connection instead", derr)
			return false
		}
		time.Sleep(75 * time.Millisecond)
	}
	defer out.Close()

	select {
	case c, ok := <-accepted:
		if !ok {
			return false
		}
		c.Close()
		return true
	case <-time.After(3 * time.Second):
		lc.say("a connection to an unused loopback port did not arrive at the catch-all; " +
			"each loopback service is captured from its second connection instead")
		return false
	}
}

// startCatchAll begins serving once the rule has been shown to work.
func (lc *localCapture) startCatchAll(ln net.Listener) {
	lc.mu.Lock()
	lc.catchAll = ln
	lc.listeners = append(lc.listeners, ln)
	lc.mu.Unlock()
	go lc.serve(ln, 0) // 0: the destination comes from pf, per connection
	lc.natlookOK.Store(true)
}

func (lc *localCapture) say(format string, args ...any) {
	fmt.Fprintf(lc.out, "ntcept: "+format+"\n", args...)
}

// splice carries a connection ntcept was not asked to watch, recording nothing about it.
func (lc *localCapture) splice(c net.Conn, original int) {
	defer c.Close()
	up, err := dialLocalService(context.Background(), original)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// dialLocalService reaches the real service, from the address the redirect rule exempts. Without
// that source address ntcept's own connection would be redirected straight back into ntcept.
func dialLocalService(ctx context.Context, port int) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   20 * time.Second,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(ForwardIP)},
	}
	return d.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
}

func (lc *localCapture) Close() {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	for _, ln := range lc.listeners {
		_ = ln.Close()
	}
	lc.listeners = nil
	for _, lock := range lc.portLocks {
		lock.release()
	}
	lc.portLocks = nil
}

func (lc *localCapture) announce() {
	if !lc.owner {
		lc.say("capturing this command's calls to services on localhost, handed over by the\n" +
			"        ntcept that holds the redirect")
		return
	}
	if lc.natlookOK.Load() {
		lc.say("capturing every localhost service this command calls, from the first\n" +
			"        connection; other processes using them are carried through untouched")
		return
	}
	lc.say("capturing this command's calls to services on localhost as it makes them;\n" +
		"        each is captured from its second connection, or its first with --capture-local")
}
