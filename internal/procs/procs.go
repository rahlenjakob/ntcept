// Package procs answers "which process opened this connection", so that traffic ntcept is
// carrying but was not asked to watch can be left alone.
//
// It exists for one case. On macOS a loopback redirect cannot be scoped to a process: pf's
// grammar allows user and group only on filter rules, never on a redirect, so a rule that
// catches the supervised application's connection to a local database catches every other
// process's connection to it too. Those still have to work, but they are not the user's to
// inspect — they must not be captured, must not appear in `ntcept ls`, and above all must not be
// held, because holding someone else's database query stalls an application nobody is debugging.
//
// The answer comes from the kernel's own tables rather than from anything ntcept tracks, because
// the connection arrives with nothing on it but a source port.
package procs

import (
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ephemeralFloor asks the kernel where its ephemeral range starts.
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

// redirectable reports whether a port may be given a redirect rule at all.
func (a *Attributor) redirectable(port int) bool {
	floor := a.EphemeralFloor
	if floor == 0 {
		floor = 49152
	}
	return port > 0 && port < floor
}

// Owner is the process holding a local socket.
type Owner struct {
	PID     int
	Command string
}

// parsePorts reads `netstat -anv -p tcp`, whose "process:pid" column names the owner of each
// socket. The column is positional and its index varies with the header, so it is found by
// shape — "name:digits" — rather than by counting.
func parsePorts(out string) map[int]Owner {
	ports := map[int]Owner{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.HasPrefix(f[0], "tcp") {
			continue
		}
		port, ok := localPort(f[3])
		if !ok {
			continue
		}
		owner, ok := ownerField(f)
		if !ok {
			continue
		}
		// A listening socket and a connection can share a local port; the connection is what a
		// redirect delivers, so it wins.
		if _, seen := ports[port]; !seen || !strings.Contains(line, "LISTEN") {
			ports[port] = owner
		}
	}
	return ports
}

// localPort reads the port off netstat's "address.port" form, which uses a dot rather than a
// colon and may carry an IPv6 scope.
func localPort(addr string) (int, bool) {
	i := strings.LastIndex(addr, ".")
	if i < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(addr[i+1:])
	if err != nil || n <= 0 || n > 65535 {
		return 0, false
	}
	return n, true
}

func ownerField(fields []string) (Owner, bool) {
	for _, f := range fields[4:] {
		name, pid, ok := strings.Cut(f, ":")
		if !ok || name == "" {
			continue
		}
		n, err := strconv.Atoi(pid)
		if err != nil || n <= 0 {
			continue
		}
		return Owner{PID: n, Command: name}, true
	}
	return Owner{}, false
}

// parseMarked reads `ps -axo pid=,gid=` and returns the processes running under gid.
//
// The group is how the supervised process is already recognised — pf matches on it to divert
// traffic in the first place — and it is inherited, so every descendant an application spawns is
// included without ntcept tracking any of them.
func parseMarked(out string, gid int) map[int]bool {
	marked := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		g, err := strconv.Atoi(f[1])
		if err != nil || g != gid {
			continue
		}
		marked[pid] = true
	}
	return marked
}

func (o Owner) String() string {
	if o.Command == "" {
		return fmt.Sprintf("pid %d", o.PID)
	}
	return fmt.Sprintf("%s (pid %d)", o.Command, o.PID)
}

// Attributor answers whether a local port belongs to the supervised application.
//
// It shells out to the kernel's own tables, which is cheap enough at the rate local service
// connections actually arrive, and caches for a moment so a burst costs one lookup rather than
// one each. A miss refreshes once before giving up, because a connection can be newer than the
// snapshot — and a wrong "not ours" would silently drop traffic out of the capture buffer.
type Attributor struct {
	// GID is the group the supervised process and its descendants run under.
	GID int
	// EphemeralFloor is the lowest port the kernel hands out to a client that did not ask for
	// a particular one. Ports at or above it are never redirected: a rule for one would also
	// match a reply travelling back to a client that happened to be given it, which strands
	// the connection. ntcept's own listeners live up there too. Zero means 49152.
	EphemeralFloor int
	// TTL is how long a snapshot is trusted.
	TTL time.Duration
	// ports and marked are swapped out for test doubles.
	ports  func() (string, error)
	marked func() (string, error)

	mu       sync.Mutex
	portsAt  time.Time
	portMap  map[int]Owner
	markedAt time.Time
	gidMap   map[int]int
}

func NewAttributor(gid int) *Attributor {
	return &Attributor{
		GID:            gid,
		EphemeralFloor: ephemeralFloor(),
		TTL:            250 * time.Millisecond,
		ports: func() (string, error) {
			out, err := exec.Command("netstat", "-anv", "-p", "tcp").Output()
			return string(out), err
		},
		marked: func() (string, error) {
			out, err := exec.Command("ps", "-axo", "pid=,gid=").Output()
			return string(out), err
		},
	}
}

// Owns reports whether the process holding localPort is part of the supervised application, and
// who it is. An unattributable connection is reported as not ours: ntcept would rather carry a
// connection it cannot account for than record one it has no right to.
func (a *Attributor) Owns(localPort int) (Owner, bool) {
	owner, _, ours := a.Attribute(localPort)
	return owner, ours
}

// Attribute names the process behind a connection, the session supervising it, and whether that
// session is this one.
//
// The group is read from the same snapshot that identified the process, which is the whole point
// of answering both here. Asking separately took a second snapshot, and the processes this has to
// attribute are often gone by then — a `curl` lives milliseconds — so the owner was identified
// and its group immediately reported as unknown. That silently disabled handing a connection to
// the session it belonged to.
func (a *Attributor) Attribute(localPort int) (Owner, int, bool) {
	owner, found := a.lookup(localPort, false)
	if !found {
		// Newer than the snapshot; one refresh, then accept the answer.
		owner, found = a.lookup(localPort, true)
	}
	if !found || owner.PID == 0 {
		return Owner{}, 0, false
	}
	gid, known := a.GIDOf(owner.PID)
	if !known {
		// The process has already gone. Nothing may be claimed on a guess.
		return owner, 0, false
	}
	return owner, gid, gid == a.GID
}

func (a *Attributor) lookup(localPort int, force bool) (Owner, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if force || a.portMap == nil || time.Since(a.portsAt) > a.TTL {
		if out, err := a.ports(); err == nil {
			a.portMap, a.portsAt = parsePorts(out), time.Now()
		}
	}
	o, ok := a.portMap[localPort]
	return o, ok
}

// GIDOf returns the group a process is running under, which is what says which ntcept session
// supervises it. Every session runs its processes under a group of its own, so this is the only
// question that has to be answered to route a connection to the right one.
func (a *Attributor) GIDOf(pid int) (int, bool) {
	if gid, ok := a.gidFrom(pid, false); ok {
		return gid, true
	}
	// A process younger than the snapshot: one forced refresh before giving up, the same way a
	// connection younger than the socket table gets one. Without it a command that starts,
	// connects and exits inside the cache window is never attributed to anyone.
	return a.gidFrom(pid, true)
}

func (a *Attributor) gidFrom(pid int, force bool) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if force || a.gidMap == nil || time.Since(a.markedAt) > a.TTL {
		if out, err := a.marked(); err == nil {
			next := parseGIDs(out)
			// Processes do not change group, and the ones being attributed here are often
			// gone before they can be asked about twice. Remembering what was seen is what
			// lets a connection from a command that has already exited still be placed.
			for k, v := range a.gidMap {
				if _, ok := next[k]; !ok {
					next[k] = v
				}
			}
			a.gidMap, a.markedAt = next, time.Now()
		}
	}
	gid, ok := a.gidMap[pid]
	return gid, ok
}

// parseGIDs reads `ps -axo pid=,gid=` into a map of every process's group.
func parseGIDs(out string) map[int]int {
	gids := map[int]int{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		gid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		gids[pid] = gid
	}
	return gids
}

// isMarked reports whether a process belongs to this session.
func (a *Attributor) isMarked(pid int) bool {
	gid, ok := a.GIDOf(pid)
	return ok && gid == a.GID
}

// Conn is one established connection and who owns it.
type Conn struct {
	Owner      Owner
	LocalPort  int
	RemoteIP   string
	RemotePort int
}

// parseConns reads established connections out of `netstat -anv -p tcp`, including where each
// one is going. Knowing what the supervised application is *already* talking to on loopback is
// what lets ntcept redirect those ports without being told them.
func parseConns(out string) []Conn {
	var conns []Conn
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.HasPrefix(f[0], "tcp") || !strings.Contains(line, "ESTABLISHED") {
			continue
		}
		local, ok := localPort(f[3])
		if !ok {
			continue
		}
		ip, remote, ok := splitAddr(f[4])
		if !ok {
			continue
		}
		owner, ok := ownerField(f)
		if !ok {
			continue
		}
		conns = append(conns, Conn{Owner: owner, LocalPort: local, RemoteIP: ip, RemotePort: remote})
	}
	return conns
}

// splitAddr reads netstat's "address.port", where the separator is a dot rather than a colon.
func splitAddr(s string) (string, int, bool) {
	i := strings.LastIndex(s, ".")
	if i < 0 {
		return "", 0, false
	}
	n, err := strconv.Atoi(s[i+1:])
	if err != nil || n <= 0 || n > 65535 {
		return "", 0, false
	}
	return s[:i], n, true
}

// LoopbackTargets returns the loopback ports the supervised application is talking to right now.
//
// This is how ntcept learns which local services to intercept without the user listing them. It
// is deliberately narrow: only ports this application actually uses are redirected, so nothing
// else on the machine is interposed on. The cost is that the connection which revealed a port
// was itself not captured — the first one to each service is missed, and everything after it is
// seen.
func (a *Attributor) LoopbackTargets() []int {
	out, err := a.ports()
	if err != nil {
		return nil
	}
	// A connection has two ends and netstat does not say which one dialled. The application
	// accepting a connection on its own port is not the application talking to a service: the
	// far end there is a client's ephemeral port, and arming it would install a redirect for a
	// port number that means nothing and will never be used again.
	//
	// Which end is which is recoverable: if the local port is one something is listening on,
	// this process is the server and the connection came to it.
	listening := map[int]bool{}
	for _, p := range parseLoopbackListeners(out) {
		listening[p] = true
	}

	seen := map[int]bool{}
	var targets []int
	for _, c := range parseConns(out) {
		if !isLoopbackIP(c.RemoteIP) || seen[c.RemotePort] {
			continue
		}
		if listening[c.LocalPort] || !a.redirectable(c.RemotePort) {
			continue // inbound, or a port no rule may safely be written for
		}
		if !a.isMarked(c.Owner.PID) {
			continue
		}
		seen[c.RemotePort] = true
		targets = append(targets, c.RemotePort)
	}
	sort.Ints(targets)
	return targets
}

func isLoopbackIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}

// parseLoopbackListeners returns the ports accepting connections on this machine's loopback.
func parseLoopbackListeners(out string) []int {
	var ports []int
	seen := map[int]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.HasPrefix(f[0], "tcp") || !strings.Contains(line, "LISTEN") {
			continue
		}
		ip, port, ok := splitAddr(f[3])
		if !ok || seen[port] {
			continue
		}
		// A service on the wildcard is reachable on loopback too.
		if !isLoopbackIP(ip) && ip != "*" && ip != "" {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

// PreArm returns the loopback ports to intercept from the outset: every one something is
// already accepting on.
//
// Arming in advance is what keeps the *first* connection to a service from being the one that
// gets away. ntcept can discover what an application talks to by watching, but only from a
// connection that already happened, and the first query to a database is often the interesting
// one. Every listening loopback port is the honest set to arm: it needs no list of what ports
// databases conventionally use, which would be arbitrary and wrong for somebody.
//
// What it does not cover is a service that starts after ntcept does. Those are picked up by
// watching, and lose their first connection. Closing that last gap needs one catch-all redirect
// plus pf's own DIOCNATLOOK to recover the original destination.
//
// Breadth is safe here only because of attribution: a redirect cannot be scoped to a process, so
// other processes' connections to these ports arrive here too, and are spliced straight through
// without being captured, listed or held.
func (a *Attributor) PreArm() []int {
	out, err := a.ports()
	if err != nil {
		return nil
	}
	var arm []int
	for _, p := range parseLoopbackListeners(out) {
		if a.redirectable(p) {
			arm = append(arm, p)
		}
	}
	return arm
}
