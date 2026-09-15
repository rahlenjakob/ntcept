//go:build linux

package netns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

// Available reports whether this kernel will let this process build the namespace and, crucially,
// create the TUN inside it. Both have to hold: on Ubuntu 24.04 the namespace is allowed but its
// capabilities are stripped, so CLONE_NEWUSER succeeds and TUNSETIFF then fails with EPERM.
// Reporting that as available would mean `ntcept run` starts and the child dies mid-launch instead
// of being refused with a reason.
func Available() bool {
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return false
	}
	if os.Geteuid() == 0 {
		return true
	}
	// Debian/older Ubuntu: unprivileged userns can be switched off wholesale.
	if b, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil &&
		len(b) > 0 && b[0] == '0' {
		return false
	}
	// Ubuntu 24.04+: the userns is created but AppArmor strips CAP_NET_ADMIN inside it unless a
	// profile grants it, so the TUN cannot be created. Treat that as unavailable and let the
	// caller say "try sudo" rather than fail obscurely at launch.
	if b, err := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); err == nil &&
		len(b) > 0 && b[0] == '1' {
		return false
	}
	return true
}

// Launch starts the command in a new user, network and mount namespace and returns its exit
// code. The TUN device the child routes through is created inside that namespace and its
// descriptor handed back here, so every packet the child emits arrives in this process.
func Launch(opts Options) (int, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 1, fmt.Errorf("socketpair: %w", err)
	}
	parent := os.NewFile(uintptr(pair[0]), "ns-parent")
	child := os.NewFile(uintptr(pair[1]), "ns-child")
	defer parent.Close()

	self, err := os.Executable()
	if err != nil {
		return 1, err
	}

	cmd := exec.Command(self, append([]string{HelperArg}, opts.Args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = opts.Env
	if cmd.Env == nil {
		cmd.Env = os.Environ()
	}
	cmd.ExtraFiles = []*os.File{child} // becomes fd 3 in the helper
	cmd.SysProcAttr = sysProcAttr()

	if err := cmd.Start(); err != nil {
		child.Close()
		return 1, fmt.Errorf("creating namespace: %w", err)
	}
	child.Close()

	tunFD, err := recvFD(parent)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 1, fmt.Errorf("receiving tun from the namespace: %w", err)
	}

	stk, err := tunnel.New(tunnel.Options{
		Device:   newTunDevice(tunFD),
		Handler:  opts.Proxy,
		Store:    opts.Store,
		Resolver: opts.Resolver,
	})
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 1, fmt.Errorf("userspace network stack: %w", err)
	}
	defer stk.Close()

	// The namespace routes 127.0.0.0/8 over the link, so every loopback connection the command
	// makes arrives here. Teach the proxy how to reach back in, so a service the command
	// started itself still answers its own calls — as it would if it shared the machine.
	opts.Proxy.SetLoopbackDialer(func(ctx context.Context, port int) (net.Conn, error) {
		return stk.DialChild(ctx, "127.0.0.1", port)
	})
	defer opts.Proxy.SetLoopbackDialer(nil)

	out := opts.Out
	if out == nil {
		out = os.Stderr
	}
	pub := newPublisher(stk, out)
	defer pub.closeAll()
	for _, pm := range opts.Publish {
		if err := pub.add(pm); err != nil {
			return 1, err
		}
	}

	// The stack is up; release the helper so it can exec the real command.
	if _, err := parent.Write([]byte{1}); err != nil {
		return 1, err
	}

	// Only now is there anything to discover: the child has been released and is about to bind.
	if opts.AutoPublish {
		watch, stop := context.WithCancel(context.Background())
		defer stop()
		go pub.watch(watch, cmd.Process.Pid)
	}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		for sig := range sigs {
			if s, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(-cmd.Process.Pid, s)
			}
		}
	}()

	err = cmd.Wait()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	default:
		return 1, err
	}
}

// sysProcAttr asks for the namespaces this process is actually allowed to create. Root already
// holds CAP_SYS_ADMIN, so it needs no user namespace — and asking for one is what trips
// container seccomp policies that block CLONE_NEWUSER.
func sysProcAttr() *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWNS,
		Setpgid:    true,
	}
	if os.Geteuid() != 0 {
		attr.Cloneflags |= syscall.CLONE_NEWUSER
		attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
		attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
		attr.GidMappingsEnableSetgroups = false
	}
	return attr
}

func recvFD(sock *os.File) (int, error) {
	buf := make([]byte, 256)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(int(sock.Fd()), buf, oob, 0)
	if err != nil {
		return 0, err
	}
	if n > 0 && buf[0] == 'E' {
		return 0, fmt.Errorf("%s", string(buf[1:n]))
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		return 0, fmt.Errorf("no descriptor received: %v", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		return 0, fmt.Errorf("no descriptor in message: %v", err)
	}
	return fds[0], nil
}
