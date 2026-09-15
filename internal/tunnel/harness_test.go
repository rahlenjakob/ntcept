package tunnel

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/rahlenjakob/ntcept/internal/capture"
)

// The attach layer is the part of ntcept that has never had a test, because on Linux it needs a
// network namespace and on macOS it needs a utun and root. Neither is true of the engine itself:
// what a TUN or a utun hands the stack is bare IP packets, and a second gvisor stack can produce
// those from a real socket call. So the peer below stands in for the supervised process, and
// everything between its connect() and the upstream server is the code that actually ships.

// link is a two-ended packet pipe. One end satisfies Device — the shape both platforms hand the
// engine — and the other feeds a stack that plays the supervised process.
type link struct {
	toEngine   chan []byte
	fromEngine chan []byte
	closed     chan struct{}
	once       sync.Once
}

func newLink() *link {
	return &link{
		toEngine:   make(chan []byte, 256),
		fromEngine: make(chan []byte, 256),
		closed:     make(chan struct{}),
	}
}

var errLinkClosed = errors.New("link closed")

func (l *link) ReadPacket(buf []byte) (int, error) {
	select {
	case pkt := <-l.toEngine:
		return copy(buf, pkt), nil
	case <-l.closed:
		return 0, errLinkClosed
	}
}

func (l *link) WritePacket(pkt []byte) error {
	cp := append([]byte(nil), pkt...)
	select {
	case l.fromEngine <- cp:
		return nil
	case <-l.closed:
		return errLinkClosed
	}
}

func (l *link) Name() string { return "ntcept-test0" }

func (l *link) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

// peer is the supervised process's side: a real TCP/IP stack whose default route is the link, so
// a dial to any address in the world leaves as packets the engine has to deal with.
type peer struct {
	s  *stack.Stack
	ep *channel.Endpoint
}

func newPeer(t testing.TB, l *link) *peer {
	t.Helper()
	ep := channel.New(512, MTU, "")
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := s.CreateNIC(nicID, ep); err != nil {
		t.Fatalf("peer nic: %v", err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(net.ParseIP(PeerIP).To4()),
			PrefixLen: Prefix,
		},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("peer address: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for {
			pkt := ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			view := pkt.ToView()
			select {
			case l.toEngine <- append([]byte(nil), view.AsSlice()...):
			case <-l.closed:
				view.Release()
				pkt.DecRef()
				return
			}
			view.Release()
			pkt.DecRef()
		}
	}()
	go func() {
		for {
			select {
			case raw := <-l.fromEngine:
				if len(raw) == 0 || raw[0]>>4 != 4 {
					continue
				}
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(raw),
				})
				ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
				pkt.DecRef()
			case <-ctx.Done():
				return
			case <-l.closed:
				return
			}
		}
	}()

	t.Cleanup(func() { ep.Close(); s.Close(); s.Wait() })
	return &peer{s: s, ep: ep}
}

// Dial makes the supervised process open a connection to an address on the internet. Nothing
// resolves and nothing routes: the engine is the only thing on the other side.
func (p *peer) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	return gonet.DialContextTCP(ctx, p.s, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(net.ParseIP(host).To4()),
		Port: uint16(port),
	}, ipv4.ProtocolNumber)
}

func (p *peer) DialUDP(host string, port int) (net.Conn, error) {
	addr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(net.ParseIP(host).To4()),
		Port: uint16(port),
	}
	return gonet.DialUDP(p.s, nil, &addr, ipv4.ProtocolNumber)
}

// recorder is a Handler that notes the original destination and hands the connection to fn. The
// destination is the whole point of the engine: the app dialled an address, and by the time the
// connection surfaces here it has been terminated locally with that address preserved.
type recorder struct {
	mu    sync.Mutex
	seen  []string
	serve func(net.Conn, string, int)
}

func (r *recorder) HandleTransparent(c net.Conn, host string, port int) {
	r.mu.Lock()
	r.seen = append(r.seen, net.JoinHostPort(host, strconv.Itoa(port)))
	r.mu.Unlock()
	if r.serve != nil {
		r.serve(c, host, port)
		return
	}
	c.Close()
}

func (r *recorder) targets() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// engine stands up the real Stack over the link, with the given handler.
func engine(t testing.TB, h Handler, resolver string) (*link, *peer, *capture.Store) {
	t.Helper()
	l := newLink()
	store := capture.NewStore(64<<20, 1<<20)
	st, err := New(Options{Device: l, Handler: h, Store: store, Resolver: resolver})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(st.Close)
	return l, newPeer(t, l), store
}

func deadlineCtx(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}
