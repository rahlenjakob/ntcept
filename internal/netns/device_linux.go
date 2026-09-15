//go:build linux

package netns

import (
	"os"

	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

// tunDevice is the child namespace's TUN, created with IFF_NO_PI so the descriptor carries bare
// IP packets with no framing of its own.
type tunDevice struct {
	f *os.File
}

func newTunDevice(fd int) tunnel.Device {
	return &tunDevice{f: os.NewFile(uintptr(fd), IfName)}
}

func (d *tunDevice) ReadPacket(buf []byte) (int, error) { return d.f.Read(buf) }
func (d *tunDevice) WritePacket(pkt []byte) error       { _, err := d.f.Write(pkt); return err }
func (d *tunDevice) Name() string                       { return IfName }
func (d *tunDevice) Close() error                       { return d.f.Close() }
