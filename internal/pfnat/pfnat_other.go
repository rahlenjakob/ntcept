//go:build !darwin

package pfnat

import (
	"fmt"
	"net"
	"os"
)

func Lookup(*os.File, *net.TCPAddr, *net.TCPAddr) (*net.TCPAddr, error) {
	return nil, fmt.Errorf("pf is macOS-only")
}

func Plausible(*net.TCPAddr, int) error { return fmt.Errorf("pf is macOS-only") }
