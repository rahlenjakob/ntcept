//go:build darwin

// Package pfnat asks pf what a redirected connection was originally aimed at.
//
// It is what lets one redirect rule cover every port. Without it, ntcept has to name each port
// it wants to intercept in advance and recover the destination from which listener accepted —
// which means a service nobody named loses its first connection. With it, a single catch-all
// rule works and the first connection to anything is captured.
//
// The mechanism is DIOCNATLOOK, the same one BSD transparent proxies have always used. It needs
// a descriptor for /dev/pf, which is root-only; ntcept's privileged helper opens it and passes
// it over the unix socket it already uses for the utun, so the unprivileged half can ask without
// being privileged itself.
package pfnat

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The layout of struct pfioc_natlook, from XNU's bsd/net/pfvar.h.
//
// This header is kernel-private and ships with no SDK, so the offsets here are reconstructed
// rather than compiled against. A wrong offset would not fail — it would return a plausible
// port, and ntcept would attribute a connection to the wrong service in silence. Which is why
// nothing relies on this until prove() (see local_darwin.go) has checked it end to end against a
// connection whose real destination is already known, and Plausible() rejects an answer that
// cannot be right.
//
// Verified against: macOS 15 (Sequoia) / Darwin 24, and Darwin 25.x. This is the most
// version-fragile code in the tree — if a future XNU reorders the struct, prove() is the
// trip-wire and the code falls back to per-port rules rather than trusting a bad answer. The
// layout has been stable since the pf import from OpenBSD, so drift is unlikely but not
// impossible; treat a prove() failure on a new macOS as "recheck these offsets", not "pf broke".
const (
	addrLen   = 16 // struct pf_addr: a union over in_addr and in6_addr
	xportLen  = 4  // union pf_state_xport: a union over u_int16_t port and u_int32_t spi
	natlookSz = 4*addrLen + 4*xportLen + 4

	offSaddr   = 0
	offDaddr   = addrLen
	offRsaddr  = 2 * addrLen
	offRdaddr  = 3 * addrLen
	offSxport  = 4 * addrLen
	offDxport  = offSxport + xportLen
	offRdxport = offSxport + 3*xportLen
	offAF      = 4*addrLen + 4*xportLen
	offProto   = offAF + 1

	// direction is the last byte; PF_OUT is what a redirected connection is looked up as.
	offDirection = offAF + 3
	pfOut        = 2
)

// diocNatlook is _IOWR('D', 23, struct pfioc_natlook).
const diocNatlook = 0xC0000000 | (natlookSz << 16) | ('D' << 8) | 23

// Lookup asks pf what remote address the connection now arriving from client on local was
// originally aimed at, before the redirect rewrote it.
func Lookup(pf *os.File, client, local *net.TCPAddr) (*net.TCPAddr, error) {
	if pf == nil {
		return nil, fmt.Errorf("no /dev/pf descriptor")
	}
	src, dst := client.IP.To4(), local.IP.To4()
	if src == nil || dst == nil {
		return nil, fmt.Errorf("pf lookup is IPv4 only")
	}

	var buf [natlookSz]byte
	copy(buf[offSaddr:], src)
	copy(buf[offDaddr:], dst)
	// Ports travel in network order inside the union's first two bytes.
	binary.BigEndian.PutUint16(buf[offSxport:], uint16(client.Port))
	binary.BigEndian.PutUint16(buf[offDxport:], uint16(local.Port))
	buf[offAF] = unix.AF_INET
	buf[offProto] = unix.IPPROTO_TCP
	buf[offDirection] = pfOut

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, pf.Fd(), uintptr(diocNatlook),
		uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return nil, fmt.Errorf("pf natlook: %w", errno)
	}

	ip := net.IPv4(buf[offRdaddr], buf[offRdaddr+1], buf[offRdaddr+2], buf[offRdaddr+3])
	port := int(binary.BigEndian.Uint16(buf[offRdxport:]))
	if port == 0 {
		return nil, fmt.Errorf("pf natlook returned no port")
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}

// Plausible rejects an answer that cannot be right. A reconstructed struct layout fails by
// returning nonsense rather than by failing, so the answer is checked rather than trusted.
func Plausible(got *net.TCPAddr, listener int) error {
	switch {
	case got == nil:
		return fmt.Errorf("no answer")
	case !got.IP.IsLoopback():
		return fmt.Errorf("original destination %s is not loopback", got.IP)
	case got.Port <= 0 || got.Port > 65535:
		return fmt.Errorf("original port %d is out of range", got.Port)
	case got.Port == listener:
		// The pre-translation destination is what was asked for. Getting the post-translation
		// one back means the wrong field was read.
		return fmt.Errorf("original port is the redirect target (%d); the layout is wrong", listener)
	}
	return nil
}

// Request is the shape a caller across a privilege boundary sends.
type Request struct {
	SrcIP   string
	SrcPort int
	DstIP   string
	DstPort int
}

// LookupFor answers a Request. It is what the privileged helper calls on ntcept's behalf.
func LookupFor(pf *os.File, r interface {
	Tuple() (srcIP string, srcPort int, dstIP string, dstPort int)
}) (*net.TCPAddr, error) {
	sIP, sPort, dIP, dPort := r.Tuple()
	return Lookup(pf,
		&net.TCPAddr{IP: net.ParseIP(sIP), Port: sPort},
		&net.TCPAddr{IP: net.ParseIP(dIP), Port: dPort})
}
