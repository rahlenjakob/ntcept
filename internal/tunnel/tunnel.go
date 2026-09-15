// Package tunnel is the interception engine both platforms share: a userspace TCP/IP stack that
// terminates every connection a supervised process opens and re-originates it from ntcept.
//
// Linux feeds it packets from a TUN inside the child's network namespace; macOS feeds it from a
// utun that pf steers the child's traffic into. The stack above that point is identical, and no
// language runtime has to cooperate — interception happens below the socket API.
package tunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/decode"
)

// dbg turns on a per-packet trace. It exists because the only way to tell a packet that never
// arrived from one that arrived and was answered unroutably is to watch both ends of the link —
// which distinguishes a packet that never arrived from one answered unroutably. Set
// NTCEPT_TUNNEL_DEBUG=1.
var dbg = os.Getenv("NTCEPT_TUNNEL_DEBUG") != ""

// describe renders an IPv4 packet header for the trace.
func describe(b []byte) string {
	if len(b) < 20 || b[0]>>4 != 4 {
		return fmt.Sprintf("non-ipv4 (%d bytes)", len(b))
	}
	h := header.IPv4(b)
	src, dstA := h.SourceAddress(), h.DestinationAddress()
	proto := h.Protocol()
	out := fmt.Sprintf("%s -> %s proto=%d", src, dstA, proto)
	if proto == uint8(tcp.ProtocolNumber) && len(b) >= int(h.HeaderLength())+20 {
		t := header.TCP(b[h.HeaderLength():])
		out += fmt.Sprintf(" %d->%d flags=%s", t.SourcePort(), t.DestinationPort(), t.Flags())
	}
	return out
}

const (
	// The point-to-point link between ntcept and the supervised process.
	HostIP  = "10.77.0.1"
	PeerIP  = "10.77.0.2"
	Prefix  = 30
	MTU     = 1500
	nicID   = 1
	udpIdle = 30 * time.Second
)

// Device is one end of a packet pipe carrying bare IP packets — no link header and no platform
// framing, which each implementation is responsible for stripping.
type Device interface {
	ReadPacket(buf []byte) (int, error)
	WritePacket(pkt []byte) error
	Name() string
	Close() error
}

// Handler receives connections whose original destination is already known.
type Handler interface {
	HandleTransparent(c net.Conn, host string, port int)
}

type Options struct {
	Device   Device
	Handler  Handler
	Store    *capture.Store
	Resolver string // where the supervised process's DNS queries are really sent
}

type Stack struct {
	s    *stack.Stack
	ep   *channel.Endpoint
	opts Options

	cancel context.CancelFunc
}

func New(opts Options) (*Stack, error) {
	if opts.Device == nil || opts.Handler == nil || opts.Store == nil {
		return nil, fmt.Errorf("tunnel: device, handler and store are all required")
	}
	ep := channel.New(512, MTU, "")
	// Accept packets carrying a loopback address. The stack drops them by default, on the
	// reasoning that a packet from or to 127.0.0.0/8 arriving on a real link is forged — but
	// this link is not a real one. On Linux the supervised process routes 127.0.0.0/8 out over
	// it deliberately, so that "localhost" means the same thing it does on macOS: the machine,
	// not the namespace. Without this those packets would be dropped before anything saw them.
	//
	// It does not make loopback interceptable on macOS. There, pf can divert such a packet in
	// but the reply — source 127.0.0.1, written to a utun — is dropped by the host's own stack
	// before it reaches the process, so route-to cannot intercept loopback there.
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocolWithOptions(ipv4.Options{AllowExternalLoopbackTraffic: true}),
			ipv6.NewProtocolWithOptions(ipv6.Options{AllowExternalLoopbackTraffic: true}),
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6,
		},
	})
	if terr := s.CreateNIC(nicID, ep); terr != nil {
		return nil, fmt.Errorf("creating nic: %v", terr)
	}
	if terr := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(net.ParseIP(HostIP).To4()),
			PrefixLen: Prefix,
		},
	}, stack.AddressProperties{}); terr != nil {
		return nil, fmt.Errorf("addressing nic: %v", terr)
	}

	// The supervised process dials real addresses all over the internet. Promiscuous mode makes
	// the stack accept those packets; spoofing lets it answer as whatever address was dialled.
	if terr := s.SetPromiscuousMode(nicID, true); terr != nil {
		return nil, fmt.Errorf("promiscuous mode: %v", terr)
	}
	if terr := s.SetSpoofing(nicID, true); terr != nil {
		return nil, fmt.Errorf("spoofing: %v", terr)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	st := &Stack{s: s, ep: ep, opts: opts}

	tcpFwd := tcp.NewForwarder(s, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		tep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, tep)
		go opts.Handler.HandleTransparent(conn, id.LocalAddress.String(), int(id.LocalPort))
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		id := r.ID()
		var wq waiter.Queue
		uep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			return false
		}
		go st.handleUDP(gonet.NewUDPConn(&wq, uep), id.LocalAddress.String(), int(id.LocalPort))
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	ctx, cancel := context.WithCancel(context.Background())
	st.cancel = cancel
	go st.pumpIn()
	go st.pumpOut(ctx)
	return st, nil
}

func (st *Stack) Close() {
	st.cancel()
	st.ep.Close()
	st.s.Close()
	st.s.Wait()
	_ = st.opts.Device.Close()
}

// pumpIn moves packets from the device into the stack.
func (st *Stack) pumpIn() {
	buf := make([]byte, MTU+128)
	for {
		n, err := st.opts.Device.ReadPacket(buf)
		if err != nil {
			return
		}
		if n < 1 {
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch buf[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			continue
		}
		if dbg {
			fmt.Fprintf(os.Stderr, "[tun] IN  %s\n", describe(buf[:n]))
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(append([]byte(nil), buf[:n]...)),
		})
		st.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
	}
}

// pumpOut moves packets the stack produced back to the device.
func (st *Stack) pumpOut(ctx context.Context) {
	for {
		pkt := st.ep.ReadContext(ctx)
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		if dbg {
			fmt.Fprintf(os.Stderr, "[tun] OUT %s\n", describe(view.AsSlice()))
		}
		err := st.opts.Device.WritePacket(view.AsSlice())
		view.Release()
		pkt.DecRef()
		if err != nil {
			return
		}
	}
}

// handleUDP relays a datagram conversation. DNS is the interesting case: the supervised process
// resolves through us, so every name it looks up is visible.
func (st *Stack) handleUDP(conn *gonet.UDPConn, host string, port int) {
	defer conn.Close()

	upstream := net.JoinHostPort(host, fmt.Sprint(port))
	if port == 53 {
		upstream = st.opts.Resolver
	}
	up, err := net.DialTimeout("udp", upstream, 10*time.Second)
	if err != nil {
		return
	}
	defer up.Close()

	f := st.opts.Store.Begin(capture.KindUDP, host, port)
	st.opts.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.Proto, f.Via = capture.ProtoUDP, capture.ViaTun
		if port == 53 {
			f.Path = "dns"
		}
	})
	defer st.opts.Store.Finish(f, nil)

	done := make(chan struct{}, 2)
	relay := func(src, dst net.Conn, dir capture.Dir) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 64*1024)
		for {
			_ = src.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := src.Read(buf)
			if n > 0 {
				payload := append([]byte(nil), buf[:n]...)
				msg := capture.Message{T: time.Now(), Dir: dir, Data: payload}
				if port == 53 {
					msg.Decoded = decode.DNS(payload)
				}
				st.opts.Store.Append(f, msg)
				if _, werr := dst.Write(payload); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	go relay(conn, up, capture.Out)
	go relay(up, conn, capture.In)
	<-done
}
