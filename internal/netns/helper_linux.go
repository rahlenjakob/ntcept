//go:build linux

package netns

import (
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// RunHelper executes inside the freshly created namespaces. It builds the TUN, points the
// namespace's default route and resolver at ntcept, hands the descriptor back, and then becomes
// the user's command.
func RunHelper(args []string) int {
	sock := os.NewFile(3, "ns-sock")
	if sock == nil {
		fmt.Fprintln(os.Stderr, "ntcept: helper started without its control socket")
		return 1
	}
	if len(args) == 0 {
		reportErr(sock, fmt.Errorf("nothing to run"))
		return 1
	}

	tunFD, err := setup()
	if err != nil {
		reportErr(sock, err)
		return 1
	}
	if err := sendFD(sock, tunFD); err != nil {
		reportErr(sock, err)
		return 1
	}
	// Wait until ntcept says the stack is attached, or the first packet is lost.
	if _, err := sock.Read(make([]byte, 1)); err != nil {
		return 1
	}
	_ = unix.Close(tunFD)
	_ = sock.Close()

	path, err := lookPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "ntcept: %v\n", err)
		return 127
	}
	if err := unix.Exec(path, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "ntcept: exec %s: %v\n", args[0], err)
		return 126
	}
	return 0
}

func setup() (int, error) {
	if lo, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(lo)
	}

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("opening /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(IfName)
	if err != nil {
		return 0, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		return 0, fmt.Errorf("creating tun device: %w", err)
	}

	link, err := netlink.LinkByName(IfName)
	if err != nil {
		return 0, fmt.Errorf("finding %s: %w", IfName, err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{
		IP:   net.ParseIP(ChildIP),
		Mask: net.CIDRMask(Prefix, 32),
	}}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return 0, fmt.Errorf("addressing %s: %w", IfName, err)
	}
	if err := netlink.LinkSetMTU(link, MTU); err != nil {
		return 0, err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return 0, err
	}
	// Everything the child does leaves through ntcept.
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        net.ParseIP(HostIP),
		Dst:       nil,
	}); err != nil {
		return 0, fmt.Errorf("default route: %w", err)
	}

	allowLoopbackOverTheLink()
	if err := routeLoopbackOut(link); err != nil {
		return 0, err
	}

	if err := pointResolver(); err != nil {
		return 0, err
	}
	return fd, nil
}

// routeLoopbackOut sends 127.0.0.0/8 over the link instead of to the namespace's own loopback.
//
// This is what makes "localhost" mean the same thing under both attaches. On macOS the command
// shares the machine's network, so 127.0.0.1 is the machine: a database the user started, and
// equally a service the command started itself. In a namespace 127.0.0.1 would otherwise be a
// private loopback reachable by nothing and reaching nothing, so a command that talks to a local
// Postgres simply fails, and two services started under ntcept cannot see each other.
//
// Sending it over the link hands both cases to the engine, which resolves them the way macOS
// does — the command's own loopback first, the machine second — and captures the traffic on the
// way past, which macOS cannot do at all.
//
// The /8 is deliberate: services bind 127.0.0.2 and friends more often than one would like.
func routeLoopbackOut(link netlink.Link) error {
	_, loopback, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		return err
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Gw:        net.ParseIP(HostIP),
		Dst:       loopback,
	}); err != nil {
		return fmt.Errorf("routing loopback over %s: %w", IfName, err)
	}
	return nil
}

// allowLoopbackOverTheLink lets a packet arriving on the TUN carry a loopback address. Without
// it the kernel discards such a packet as a martian, which is the right default on a real
// interface and the wrong one here: most dev servers bind 127.0.0.1 only, and reaching one from
// outside the namespace means delivering a packet addressed to it.
//
// This is a sysctl in the namespace's own /proc, so it changes nothing on the host and is undone
// when the namespace goes away. Best-effort: a kernel that refuses it leaves loopback-bound
// servers unpublishable, which is what the situation was before, rather than a failed run.
func allowLoopbackOverTheLink() {
	for _, path := range []string{
		"/proc/sys/net/ipv4/conf/" + IfName + "/route_localnet",
		"/proc/sys/net/ipv4/conf/all/route_localnet",
	} {
		_ = os.WriteFile(path, []byte("1\n"), 0o644)
	}
}

// pointResolver replaces /etc/resolv.conf for this mount namespace only. The host's file is
// untouched; the bind mount disappears with the process.
func pointResolver() error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("making mounts private: %w", err)
	}
	tmp, err := os.CreateTemp("", "ntcept-resolv-*")
	if err != nil {
		return err
	}
	defer tmp.Close()
	if _, err := fmt.Fprintf(tmp, "nameserver %s\noptions ndots:0\n", HostIP); err != nil {
		return err
	}
	if err := unix.Mount(tmp.Name(), "/etc/resolv.conf", "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("pointing resolv.conf at ntcept: %w", err)
	}
	return nil
}

func sendFD(sock *os.File, fd int) error {
	rights := unix.UnixRights(fd)
	return unix.Sendmsg(int(sock.Fd()), []byte{'K'}, rights, nil, 0)
}

func reportErr(sock *os.File, err error) {
	_, _ = sock.Write(append([]byte{'E'}, []byte(err.Error())...))
	fmt.Fprintf(os.Stderr, "ntcept: %v\n", err)
}

func lookPath(name string) (string, error) {
	if len(name) > 0 && (name[0] == '/' || name[0] == '.') {
		return name, nil
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s: not found in PATH", name)
	}
	return p, nil
}
