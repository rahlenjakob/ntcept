//go:build darwin

package pftun

import (
	"encoding/binary"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

const (
	sysprotoControl = 2
	utunOptIfName   = 2
	utunControlName = "com.apple.net.utun_control"
)

// utunDevice is a macOS utun. Unlike a Linux TUN it prefixes every packet with a 4-byte address
// family in network order, which is stripped here so the engine above sees bare IP.
type utunDevice struct {
	f    *os.File
	name string
}

// openUTUN claims the first free utun unit.
func openUTUN() (*utunDevice, error) {
	var lastErr error
	for unit := 8; unit < 64; unit++ {
		fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
		if err != nil {
			return nil, fmt.Errorf("opening the system control socket: %w", err)
		}
		info := &unix.CtlInfo{}
		copy(info.Name[:], utunControlName)
		if err := unix.IoctlCtlInfo(fd, info); err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("resolving %s: %w", utunControlName, err)
		}
		// Unit n exposes itself as utun(n-1).
		if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: uint32(unit + 1)}); err != nil {
			unix.Close(fd)
			lastErr = err
			continue
		}
		name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfName)
		if err != nil {
			unix.Close(fd)
			return nil, fmt.Errorf("reading the utun name: %w", err)
		}
		return &utunDevice{f: os.NewFile(uintptr(fd), name), name: name}, nil
	}
	return nil, fmt.Errorf("no free utun unit: %v", lastErr)
}

func (d *utunDevice) ReadPacket(buf []byte) (int, error) {
	scratch := make([]byte, len(buf)+4)
	n, err := d.f.Read(scratch)
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil
	}
	return copy(buf, scratch[4:n]), nil
}

func (d *utunDevice) WritePacket(pkt []byte) error {
	if len(pkt) == 0 {
		return nil
	}
	family := uint32(unix.AF_INET)
	if pkt[0]>>4 == 6 {
		family = uint32(unix.AF_INET6)
	}
	out := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(out[:4], family)
	copy(out[4:], pkt)
	_, err := d.f.Write(out)
	return err
}

func (d *utunDevice) Name() string   { return d.name }
func (d *utunDevice) Close() error   { return d.f.Close() }
func (d *utunDevice) String() string { return d.name }

var _ tunnel.Device = (*utunDevice)(nil)

// adoptUTUN wraps a utun descriptor received from the privileged helper.
func adoptUTUN(fd int) tunnel.Device {
	return &utunDevice{f: os.NewFile(uintptr(fd), "utun"), name: "utun"}
}
