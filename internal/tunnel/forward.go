package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

// Forwarding exists because the interception is one-way and a supervised process is not only a
// client. On Linux the child lives in its own network namespace, so a dev server it binds is
// reachable from nothing at all — `ntcept run -- npm run dev` gives you a captured app you
// cannot open in a browser. macOS has no such problem, because pf only diverts egress and the
// child is still on the host's network.
//
// That asymmetry is the single largest behavioural difference between the two attaches, and it
// is closed here rather than by giving up the namespace: the engine already terminates one end
// of a link into the namespace, so it can dial in as easily as it accepts out.

// DialChild opens a connection to a port inside the supervised process, from ntcept's side of
// the link. The packets it produces leave through the same device the child's own traffic
// arrives on, so this needs no cooperation from the child and no privilege beyond what the
// namespace already granted.
func (st *Stack) DialChild(ctx context.Context, ip string, port int) (net.Conn, error) {
	if ip == "" {
		ip = PeerIP
	}
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return nil, fmt.Errorf("dialling the supervised process: %q is not an IPv4 address", ip)
	}
	addr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(v4),
		Port: uint16(port),
	}
	return gonet.DialContextTCP(ctx, st.s, addr, ipv4.ProtocolNumber)
}

// Publication is a host port standing in for one inside the namespace.
type Publication struct {
	// HostAddr is where it is reachable on this machine, after any :0 was resolved.
	HostAddr string
	// To is the socket inside the namespace that connections are relayed to.
	To PortMap

	ln     net.Listener
	closed chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

// Publish accepts on the host and relays every connection into the supervised process.
//
// It binds loopback by default. A dev server is not a thing to put on the network by accident,
// and the reason to want this at all is opening it in a browser on the same machine.
func (st *Stack) Publish(pm PortMap) (*Publication, error) {
	ln, err := net.Listen("tcp", pm.HostAddr)
	if err != nil {
		return nil, fmt.Errorf("publishing port %d: %w", pm.ChildPort, err)
	}
	p := &Publication{
		HostAddr: ln.Addr().String(),
		To:       pm,
		ln:       ln,
		closed:   make(chan struct{}),
	}
	p.wg.Add(1)
	go p.serve(st)
	return p, nil
}

func (p *Publication) serve(st *Stack) {
	defer p.wg.Done()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.relay(st, c)
		}()
	}
}

func (p *Publication) relay(st *Stack, host net.Conn) {
	defer host.Close()

	// The child may not have bound yet — a dev server takes a moment to start, and the
	// publication is opened before the command runs so the port is held from the outset.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child, err := st.DialChild(ctx, p.To.ChildAddr, p.To.ChildPort)
	if err != nil {
		return
	}
	defer child.Close()

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(child, host); halfClose(child); done <- struct{}{} }()
	go func() { _, _ = io.Copy(host, child); halfClose(host); done <- struct{}{} }()
	select {
	case <-done:
	case <-p.closed:
	}
}

// halfClose tells the far end no more is coming without tearing down the other direction, which
// is what a request-then-read protocol needs.
func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func (p *Publication) Close() error {
	p.once.Do(func() {
		close(p.closed)
		_ = p.ln.Close()
	})
	p.wg.Wait()
	return nil
}

func (p *Publication) String() string {
	return fmt.Sprintf("%s → :%d in the namespace", p.HostAddr, p.To.ChildPort)
}

// PortMap is one publication, resolved: where to listen on this machine and which socket inside
// the supervised process to relay it to.
type PortMap struct {
	HostAddr string
	// ChildAddr is the address inside the namespace. Empty means the child's own address, which
	// is right for a server bound to the wildcard; a server bound to loopback has to be dialled
	// at 127.0.0.1 instead, and that is the more common default among dev servers.
	ChildAddr string
	ChildPort int
}

// ParsePublish reads a --publish value. "3000" publishes the child's 3000 on the host's 3000;
// "8080:3000" maps them; "0:3000" lets the host side pick a free port.
func ParsePublish(spec string) (PortMap, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return PortMap{}, fmt.Errorf("empty --publish")
	}
	hostPart, childPart, mapped := strings.Cut(spec, ":")
	if !mapped {
		childPart = hostPart
	}
	child, err := strconv.Atoi(childPart)
	if err != nil || child < 1 || child > 65535 {
		return PortMap{}, fmt.Errorf("--publish %q: %q is not a port", spec, childPart)
	}
	host, err := strconv.Atoi(hostPart)
	if err != nil || host < 0 || host > 65535 {
		return PortMap{}, fmt.Errorf("--publish %q: %q is not a port", spec, hostPart)
	}
	return PortMap{HostAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(host)), ChildPort: child}, nil
}
