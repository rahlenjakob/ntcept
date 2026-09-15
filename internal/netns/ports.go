package netns

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

// Watching what the child binds is what keeps the two attaches behaving the same. On macOS the
// supervised process is still on the host's network, so a port it binds is reachable without
// anyone asking for it. On Linux the namespace hides it, and requiring `--publish` for every
// port would leave a difference the user did not cause and has to remember. So ntcept reads the
// namespace's own socket table and publishes what appears.
//
// The table is the kernel's, read through /proc/<pid>/net/tcp — which, for a process in another
// network namespace, is that namespace's table rather than the host's. No privilege is needed
// beyond being the process's parent.

// Listener is one socket the supervised process has open for connections.
type Listener struct {
	IP   net.IP
	Port int
}

// tcpListen is the st column for TCP_LISTEN.
const tcpListen = "0A"

// parseListening pulls the listening sockets out of a /proc/net/tcp or tcp6 table.
func parseListening(table string) []Listener {
	var out []Listener
	for i, line := range strings.Split(table, "\n") {
		if i == 0 {
			continue // the column header
		}
		f := strings.Fields(line)
		if len(f) < 4 || f[3] != tcpListen {
			continue
		}
		ip, port, ok := parseHexAddr(f[1])
		if !ok {
			continue
		}
		out = append(out, Listener{IP: ip, Port: port})
	}
	return out
}

// parseHexAddr reads the kernel's "ADDRESS:PORT" form. The address is hex, and each four-byte
// word of it is in host byte order — little-endian on every platform ntcept supports — while the
// port is big-endian. Getting that backwards yields plausible-looking nonsense rather than an
// error, which is why it is parsed here rather than eyeballed.
func parseHexAddr(s string) (net.IP, int, bool) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil || port == 0 {
		return nil, 0, false
	}
	raw, err := hex.DecodeString(h)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return ip, int(port), true
}

// DialTarget is the address inside the namespace that reaches this listener.
//
// A server bound to the wildcard is reachable at the child's own address. One bound to loopback
// is only reachable at 127.0.0.1, which a packet arriving on the TUN can carry because the
// helper sets route_localnet on it — and loopback is what most dev servers bind by default, so
// this is the common case rather than the exotic one.
func (l Listener) DialTarget() string {
	switch {
	case l.IP.IsUnspecified():
		return ChildIP
	case l.IP.IsLoopback():
		return "127.0.0.1"
	default:
		return l.IP.String()
	}
}

func (l Listener) String() string { return net.JoinHostPort(l.IP.String(), strconv.Itoa(l.Port)) }

// listening reads every port the process's network namespace is accepting on.
func listening(pid int) ([]Listener, error) {
	var out []Listener
	var firstErr error
	for _, name := range []string{"tcp", "tcp6"} {
		b, err := os.ReadFile(fmt.Sprintf("/proc/%d/net/%s", pid, name))
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		out = append(out, parseListening(string(b))...)
	}
	if out == nil && firstErr != nil {
		return nil, firstErr
	}
	return dedupe(out), nil
}

// dedupe collapses the same port appearing on several addresses, and orders the result so the
// announcement a user reads is stable between runs.
func dedupe(in []Listener) []Listener {
	best := map[int]Listener{}
	for _, l := range in {
		cur, seen := best[l.Port]
		// A wildcard bind is the most useful form, so it wins over a specific address.
		if !seen || (l.IP.IsUnspecified() && !cur.IP.IsUnspecified()) {
			best[l.Port] = l
		}
	}
	out := make([]Listener, 0, len(best))
	for _, l := range best {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// portMapFor turns a discovered listener into the publication that exposes it, keeping the same
// port number on the host so a printed URL matches what the app logged about itself.
func portMapFor(l Listener) tunnel.PortMap {
	return tunnel.PortMap{
		HostAddr:  net.JoinHostPort("127.0.0.1", strconv.Itoa(l.Port)),
		ChildAddr: l.DialTarget(),
		ChildPort: l.Port,
	}
}
