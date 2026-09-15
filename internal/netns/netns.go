// Package netns runs a command inside its own network namespace whose only route is a TUN
// device ntcept holds the other end of.
//
// This is not a container. The child keeps the same filesystem, the same libraries, the same
// binaries — only its network namespace differs. Nothing is installed, no image is built, and
// no language runtime needs to cooperate: interception happens below the socket API, so it works
// for anything that opens a connection.
package netns

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"strings"

	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/proxy"
	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

// Options is declared here rather than beside each implementation so there is exactly one of
// it. Two copies behind build tags drift the moment a field is added to one — which is the
// class of difference between the platforms worth removing wherever it appears.
type Options struct {
	Args     []string
	Proxy    *proxy.Server
	Store    *capture.Store
	Resolver string   // where to send the child's DNS queries, taken from the host's own config
	Env      []string // the child's environment; nil means inherit ntcept's

	// Publish are ports to expose on the host before the command starts.
	Publish []tunnel.PortMap
	// AutoPublish watches what the child binds and exposes it without being asked, so that a
	// server started under ntcept on Linux is reachable exactly as it is on macOS.
	AutoPublish bool
	// Out is where publications are announced. nil means os.Stderr.
	Out io.Writer
}

// ErrUnsupported is returned on platforms with no network namespaces. macOS has no rootless
// equivalent: Network Extensions require a signed, user-approved system extension, and pf needs
// root and cannot be scoped to one process.
var ErrUnsupported = errors.New("network namespaces are Linux-only")

const (
	// HostIP is ntcept's address inside the namespace, and the resolver the child is pointed at.
	HostIP  = tunnel.HostIP
	ChildIP = tunnel.PeerIP
	Prefix  = tunnel.Prefix
	MTU     = tunnel.MTU
	IfName  = "ntcept0"

	// HelperArg re-enters this binary inside the new namespace.
	HelperArg = "__ns-helper"
)

// HostResolver reads the machine's own resolver, so a child's lookups resolve exactly as they
// would have without ntcept. A loopback resolver belongs to the host's namespace and is
// unreachable from the child's, so it is skipped.
func HostResolver() string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "1.1.1.1:53"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ip := net.ParseIP(fields[1]); ip != nil && !ip.IsLoopback() {
				return net.JoinHostPort(fields[1], "53")
			}
		}
	}
	return "1.1.1.1:53"
}
