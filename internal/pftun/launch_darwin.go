//go:build darwin

package pftun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

// Available reports whether this machine will accept the pf attach, and why not if it will not.
func Available() (bool, string) {
	if _, err := exec.LookPath("pfctl"); err != nil {
		return false, "pfctl is not on PATH"
	}
	if os.Geteuid() == 0 {
		return true, ""
	}
	if ok, why := InstallState(); ok {
		return true, ""
	} else {
		return false, why + " — run `sudo ntcept install` once, then never again"
	}
}

// Launch runs the command with its outbound traffic diverted into ntcept's utun. The privileged
// work happens in the helper; this process stays unprivileged and owns the packet stack.
func Launch(opts Options) (int, error) {
	if len(opts.Args) == 0 {
		return 1, errors.New("nothing to run")
	}
	if ok, why := Available(); !ok {
		return 1, errors.New(why)
	}

	// A group of this session's own, and with it an anchor of its own. Without them a second
	// ntcept loads its rules over the first one's, claims the first one's traffic as its own,
	// and takes the rules away again when it exits.
	group, ok := acquireMarkerGroup()
	if !ok {
		return 1, errors.New("too many ntcept sessions are running on this machine")
	}
	defer group.release()

	dir, err := os.MkdirTemp("", "ntcept-")
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return 1, err
	}
	sock := filepath.Join(dir, "fd.sock")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return 1, err
	}
	defer ln.Close()

	cmd := helperCommand(sock, group.GID, opts.Args)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("starting the privileged helper: %w", err)
	}

	tunFD, pfFD, conn, err := acceptFD(ln)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 1, err
	}
	defer conn.Close()

	stk, err := tunnel.New(tunnel.Options{
		Device:   adoptUTUN(tunFD),
		Handler:  opts.Proxy,
		Store:    opts.Store,
		Resolver: opts.Resolver,
	})
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 1, err
	}
	defer stk.Close()

	// Accept on every redirected port before the helper is told to redirect anything: a rule
	// pointing at a port nothing is listening on would black-hole the user's own connections.
	out := opts.Out
	if out == nil {
		out = os.Stderr
	}
	// The descriptor the helper opened is closed here: XNU refuses DIOCNATLOOK to an
	// unprivileged caller whatever descriptor it holds, so the lookup is asked of the helper
	// instead and this copy would only be a loose file.
	if pfFD > 0 {
		_ = unix.Close(pfFD)
	}
	helper := newHelperClient(conn)

	// Loopback capture: one redirect rule covering every loopback port, so a service is
	// captured from its first connection and nobody has to name a port in advance.
	//
	// Exactly one session on the machine installs that rule. A redirect cannot be scoped to a
	// process — pf allows user and group on filter rules only — so a second rule would compete
	// for the same connections rather than add anything, and both sessions would end up
	// capturing less than one of them would alone. The session holding the rule receives every
	// loopback connection on the machine and sorts them out by who made them: its own are
	// captured, another session's are handed to that session (handoff_darwin.go), and the rest
	// are carried through without being captured, listed or held.
	var local *localCapture
	if !opts.NoCaptureLocal {
		local, err = newLocalCapture(opts.Proxy, opts.CaptureLocal, helper, group.GID, out)
		if err != nil {
			return 1, err
		}
		defer local.Close()
		// The intake comes first, so that a session which is about to take the rule can start
		// handing connections here immediately.
		if err := local.startIntake(); err != nil {
			fmt.Fprintf(out, "ntcept: %v\n", err)
		}
		lock, holder, got := acquireLoopbackLock()
		if got {
			defer lock.release()
			local.owner = true
		} else {
			fmt.Fprintf(out, "ntcept: localhost is being redirected by another ntcept "+
				"(pid %d);\n        this session's own localhost traffic is handed to it "+
				"from there\n", holder)
		}
		// ntcept's own connection to the service it is intercepting must not be redirected
		// back into itself, which the rules exempt by source address.
		opts.Proxy.SetLoopbackDialer(func(ctx context.Context, port int) (net.Conn, error) {
			return dialLocalService(ctx, port)
		})
		defer opts.Proxy.SetLoopbackDialer(nil)
	}

	// The stack is attached; hand over the environment and let the helper start the command.
	cwd, _ := os.Getwd()
	env := opts.Env
	if env == nil {
		env = os.Environ()
	}
	// The first message the helper reads is the handover, and reading it is what releases the
	// command. Everything pf needs is settled before that: installing translation rules
	// discards the NAT state of connections pf has already translated, so deciding any of it
	// afterwards would break whatever the application had in flight.
	over := handover{Env: env, Dir: cwd}
	probing := false
	if local != nil && local.owner {
		var probeRule map[int]int
		probeRule, probing = local.prepareProbe()
		over.CaptureLocal = probeRule
	}
	if err := helper.tell(over); err != nil {
		return 1, err
	}

	final := handover{Start: true}
	if local != nil && local.owner {
		final.CaptureLocal = local.Ports
		if probing {
			if catchLn, catchPort, ok := local.prove(); ok {
				if err := helper.tell(handover{CatchAll: catchPort}); err == nil &&
					local.confirmCatchAll(catchLn) {
					local.startCatchAll(catchLn)
					final = handover{Start: true, CatchAll: catchPort}
				} else {
					catchLn.Close()
				}
			}
		}
	}
	if local != nil {
		local.announce()
	}
	if err := helper.tell(final); err != nil {
		return 1, err
	}

	if local != nil && !local.owner {
		takeoverCtx, stopTakeover := context.WithCancel(context.Background())
		defer stopTakeover()
		go local.watchForOwnership(takeoverCtx, helper)
	}

	// From here ntcept watches what the application talks to on loopback and extends the
	// redirect as it goes, so no port has to be named in advance.
	if local != nil {
		watchCtx, stopWatch := context.WithCancel(context.Background())
		defer stopWatch()
		go local.watch(watchCtx, func(ports map[int]int) error {
			// Once pf can report original destinations, one catch-all rule covers every port
			// and there is nothing left to discover.
			if local.natlookOK.Load() {
				return nil
			}
			return helper.tell(handover{CaptureLocal: ports})
		})
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

// helperCommand prefers the installed helper through its sudoers grant, which needs no password.
// Running as root already, it re-enters this binary directly.
func helperCommand(sock string, gid int, args []string) *exec.Cmd {
	argv := []string{HelperArg}
	// sudo resets the environment, so this cannot travel as a variable.
	if os.Getenv("NTCEPT_DEBUG") != "" {
		argv = append(argv, "--debug")
	}
	argv = append(argv, "--gid", strconv.Itoa(gid), sock, "--")
	argv = append(argv, args...)
	if os.Geteuid() == 0 {
		self, err := os.Executable()
		if err == nil {
			return exec.Command(self, argv...)
		}
	}
	return exec.Command("sudo", append([]string{"-n", HelperPath}, argv...)...)
}

// acceptFD takes the descriptors the helper hands over: the utun, and — where the helper could
// open it — /dev/pf. A helper that sent only the utun is not an error; loopback capture falls
// back to naming ports.
func acceptFD(ln *net.UnixListener) (tun int, pf int, _ *net.UnixConn, _ error) {
	_ = ln.SetDeadline(time.Now().Add(30 * time.Second))
	conn, err := ln.AcceptUnix()
	if err != nil {
		return 0, 0, nil, fmt.Errorf("the privileged helper did not report back: %w", err)
	}
	buf := make([]byte, 256)
	oob := make([]byte, unix.CmsgSpace(8))
	n, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		conn.Close()
		return 0, 0, nil, err
	}
	if n > 0 && buf[0] == 'E' {
		conn.Close()
		return 0, 0, nil, fmt.Errorf("%s", string(buf[1:n]))
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil || len(msgs) == 0 {
		conn.Close()
		return 0, 0, nil, fmt.Errorf("no utun descriptor received: %v", err)
	}
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) == 0 {
		conn.Close()
		return 0, 0, nil, fmt.Errorf("no utun descriptor in message: %v", err)
	}
	if len(fds) > 1 {
		pf = fds[1]
	}
	return fds[0], pf, conn, nil
}
