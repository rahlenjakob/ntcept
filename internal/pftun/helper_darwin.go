//go:build darwin

package pftun

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rahlenjakob/ntcept/internal/pfnat"
	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

// RunHelper is the privileged half, reached either through the sudoers grant or directly when
// ntcept is already root. It does exactly three privileged things — create a utun, configure it,
// and load a fixed pf anchor — none of which take their shape from its arguments.
//
// It then runs the supervised command as the invoking user, never as root.
func RunHelper(args []string) int {
	if len(args) == 1 && args[0] == "--check" {
		fmt.Printf("ntcept-helper protocol %d\n", HelperProtocol)
		return 0
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "ntcept: the helper must run as root")
		return 1
	}
	debug := false
	if len(args) > 0 && args[0] == "--debug" {
		debug, args = true, args[1:]
	}
	// The group this session's processes run under, and with it the anchor its rules live in.
	// Each session gets its own so that neither can load rules over the other's, claim the
	// other's traffic, or take the other's rules away by exiting.
	gid := markerGIDBase
	if len(args) > 1 && args[0] == "--gid" {
		n, err := strconv.Atoi(args[1])
		if err != nil || n < markerGIDBase || n >= markerGIDBase+markerGIDSpan {
			fmt.Fprintf(os.Stderr, "ntcept: helper: %q is not a marker group\n", args[1])
			return 2
		}
		gid, args = n, args[2:]
	}
	if len(args) < 3 || args[1] != "--" {
		fmt.Fprintln(os.Stderr, "ntcept: helper usage: __mac-helper [--gid n] <socket> -- <command>")
		return 2
	}
	sock, cmdArgs := args[0], args[2:]
	anchor := fmt.Sprintf("%s-%d", AnchorPrefix, gid)
	// The locks that say which sessions are alive belong to the invoking user, and this runs
	// as root; without this the helper reads none of them.
	if uid, _, err := SudoUID(); err == nil {
		UseLocksOf(uid)
	}

	conn, err := net.DialTimeout("unix", sock, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ntcept: helper cannot reach ntcept: %v\n", err)
		return 1
	}
	defer conn.Close()
	uc := conn.(*net.UnixConn)

	// Only hand a utun descriptor to a process owned by the account the grant was issued for.
	// This does not make the grant unconditional-safe (see Install), but it stops the
	// descriptor from reaching another user on a shared machine.
	if err := verifyPeer(uc); err != nil {
		fmt.Fprintf(os.Stderr, "ntcept: %v\n", err)
		return 1
	}

	dev, pfToken, err := prepare(anchor, gid, debug)
	if err != nil {
		_, _ = uc.Write(append([]byte{'E'}, []byte(err.Error())...))
		fmt.Fprintf(os.Stderr, "ntcept: %v\n", err)
		return 1
	}
	// Give pf's enable reference back on exit, leaving it exactly as it was found. Registered
	// before the anchor flush below so it runs after it: rules gone, then the enable released.
	defer release(pfToken)

	// /dev/pf travels with the utun. It is how the unprivileged half asks pf what a redirected
	// connection was originally aimed at, which is what lets one rule cover every port instead
	// of ntcept naming each one in advance. Opening it is the only privileged part.
	fds := []int{int(dev.f.Fd())}
	pfDev, pfErr := os.OpenFile("/dev/pf", os.O_RDWR, 0)
	if pfErr == nil {
		defer pfDev.Close()
		fds = append(fds, int(pfDev.Fd()))
	}
	rights := unix.UnixRights(fds...)
	if _, _, err := uc.WriteMsgUnix([]byte{'K'}, rights, nil); err != nil {
		fmt.Fprintf(os.Stderr, "ntcept: handing over the utun: %v\n", err)
		return 1
	}
	if pfErr != nil && debug {
		fmt.Fprintf(os.Stderr, "ntcept: /dev/pf unavailable (%v); loopback capture will name "+
			"ports instead of asking pf\n", pfErr)
	}
	// Wait until ntcept has the stack attached, or the first packets are lost. The same message
	// carries the environment the command should run with.
	reader := bufio.NewReader(uc)
	over, err := readHandover(reader)
	if err != nil {
		return 1
	}
	// ntcept owns the device now; this copy is no longer needed.
	dev.Close()
	// The rules name a utun that dies with this run, so they must not outlive it. Only this
	// session's anchor is touched, which is what lets another session survive this one.
	defer flushAnchorFor(anchor)

	rs := ruleset{Anchor: anchor, Iface: dev.Name(), GID: gid}
	// A redirect that will not load costs visibility of loopback traffic. It must not cost the
	// run: the application is what the user came for.
	if err := applyFrom(&rs, over); err != nil {
		fmt.Fprintf(os.Stderr, "ntcept: %v; localhost stays uncaptured\n", err)
	}

	// Hold the command until ntcept says the interception is ready.
	//
	// Everything pf needs is decided before there is an application to disturb: the rules are
	// probed, the result decided, and the final ruleset installed, all while nothing is
	// connecting. Installing translation rules discards the NAT state of connections pf has
	// already translated, so doing any of it afterwards would break whatever was in flight —
	// installing them afterwards would disturb it.
	enc := json.NewEncoder(uc)
	for {
		msg, err := readHandover(reader)
		if err != nil {
			return 1
		}
		if msg.Natlook != nil {
			reply := NatlookReply{}
			got, lerr := pfnat.LookupFor(pfDev, msg.Natlook)
			if lerr != nil {
				reply.Err = lerr.Error()
			} else {
				reply.OK, reply.IP, reply.Port = true, got.IP.String(), got.Port
			}
			_ = enc.Encode(reply)
			continue
		}
		if err := applyFrom(&rs, msg); err != nil {
			fmt.Fprintf(os.Stderr, "ntcept: %v; localhost stays uncaptured\n", err)
		}
		if msg.Start {
			break
		}
	}
	if debug {
		if out, err := exec.Command("pfctl", "-a", anchor, "-s", "nat").Output(); err == nil {
			fmt.Fprintf(os.Stderr, "ntcept: pf redirects: %s", out)
		}
	}

	// From here the only thing left is extending the capture as ntcept notices new services,
	// which only happens when pf could not report original destinations.
	go func() {
		for {
			next, err := readHandover(reader)
			if err != nil {
				return
			}
			if next.Natlook != nil {
				reply := NatlookReply{}
				got, lerr := pfnat.LookupFor(pfDev, next.Natlook)
				if lerr != nil {
					reply.Err = lerr.Error()
				} else {
					reply.OK, reply.IP, reply.Port = true, got.IP.String(), got.Port
				}
				_ = enc.Encode(reply)
				continue
			}
			if err := applyFrom(&rs, next); err != nil {
				fmt.Fprintf(os.Stderr, "ntcept: %v\n", err)
			}
		}
	}()

	return spawn(cmdArgs, over, gid)
}

// applyFrom folds a message into this session's ruleset and reloads it. Filter and translation
// rules are always written together: loading one half of an anchor discards the other.
func applyFrom(rs *ruleset, m handover) error {
	// Rules belonging to a session that is gone are flushed before this session's are loaded.
	// A session killed outright cannot clean up after itself, and its anchor is evaluated
	// ahead of the ones that come after it, so what it leaves behind would redirect loopback
	// into a listener that no longer exists.
	for _, stale := range staleAnchors() {
		if stale != rs.Anchor {
			flushAnchorFor(stale)
		}
	}
	switch {
	case m.CatchAll > 0:
		rs.CatchAll, rs.Local = m.CatchAll, nil
	case len(m.CaptureLocal) > 0:
		rs.CatchAll, rs.Local = 0, m.CaptureLocal
	}
	return rs.apply()
}

// prepare brings up the utun and this session's rules, and returns the pf-enable token so the
// caller can hand it back on exit. pf counts enable requests; a token that is never released
// leaves pf enabled with an ever-climbing reference count, which on a machine where pf was off is
// ntcept silently turning the firewall on and never off again.
func prepare(anchor string, gid int, debug bool) (*utunDevice, string, error) {
	dev, err := openUTUN()
	if err != nil {
		return nil, "", err
	}
	if err := ifconfigUp(dev.Name()); err != nil {
		dev.Close()
		return nil, "", err
	}
	token, err := enable()
	if err != nil {
		dev.Close()
		return nil, "", err
	}
	if err := (ruleset{Anchor: anchor, Iface: dev.Name(), GID: gid}).apply(); err != nil {
		release(token)
		dev.Close()
		return nil, "", err
	}
	if debug {
		fmt.Fprintf(os.Stderr, "ntcept: %s up, %s <-> %s\n", dev.Name(), tunnel.PeerIP, tunnel.HostIP)
		if out, err := exec.Command("pfctl", "-a", anchor, "-s", "rules").Output(); err == nil {
			fmt.Fprintf(os.Stderr, "ntcept: pf holds: %s", out)
		}
		if out, err := exec.Command("route", "-n", "get", tunnel.HostIP).Output(); err == nil {
			fmt.Fprintf(os.Stderr, "ntcept: route to %s:\n%s", tunnel.HostIP, out)
		}
	}
	return dev, token, nil
}

// readHandover reads one message. The reader is kept across calls so that a second message is
// not lost to the first one's buffering.
//
// The line is bounded: the peer is the user's own verified ntcept, but the helper is root and
// must not let a buggy or hostile peer make it allocate without limit. The first handover carries
// the whole environment as JSON, so the cap is generous, not tight.
func readHandover(r *bufio.Reader) (handover, error) {
	const maxLine = 8 << 20
	var over handover
	line := make([]byte, 0, 256)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return over, err
		}
		if b == '\n' {
			break
		}
		line = append(line, b)
		if len(line) > maxLine {
			return over, fmt.Errorf("handover message exceeds %d bytes", maxLine)
		}
	}
	return over, json.Unmarshal(line, &over)
}

// spawn runs the supervised command as the invoking user, tagged with the group pf matches, and
// with the environment ntcept was invoked with rather than the one sudo left behind.
func spawn(args []string, over handover, gid int) int {
	uid, realGID, err := SudoUID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ntcept: %v\n", err)
		return 1
	}
	path, err := lookIn(args[0], over.Env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ntcept: %v\n", err)
		return 127
	}
	cmd := exec.Command(path, args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = over.Env
	cmd.Dir = over.Dir
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
			// The real group stays supplementary, so file access is unchanged.
			Groups: []uint32{uint32(realGID)},
		},
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "ntcept: launching %s: %v\n", args[0], err)
		return 126
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

	var ee *exec.ExitError
	switch err := cmd.Wait(); {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.ExitCode()
	default:
		return 1
	}
}

// lookIn resolves the command against the caller's PATH, not sudo's secure_path.
func lookIn(name string, env []string) (string, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return name, nil
	}
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "PATH" {
			for _, dir := range filepath.SplitList(v) {
				candidate := filepath.Join(dir, name)
				if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
					return candidate, nil
				}
			}
		}
	}
	return exec.LookPath(name)
}

// verifyPeer checks that the process on the other end of the socket belongs to the user the
// sudoers grant names, rather than to anyone who happened to find the socket path.
func verifyPeer(c *net.UnixConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var peer *unix.Xucred
	var inner error
	if err := raw.Control(func(fd uintptr) {
		peer, inner = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return err
	}
	if inner != nil {
		return fmt.Errorf("reading peer credentials: %w", inner)
	}
	want, _, err := SudoUID()
	if err != nil {
		return err
	}
	// Root is always allowed: `sudo ntcept run` re-enters this binary directly rather than
	// going through the grant, so the peer legitimately is root. Refusing it made the whole
	// privileged path unusable for anyone running ntcept under sudo — which is also the only
	// way to run it on a machine where `ntcept install` was never done.
	//
	// This broad allow is safe only because of where the socket lives: Launch creates it in a
	// 0700 directory under the invoking user's own temp dir, so the only peers that can connect
	// at all are that user and root, and root is already trusted. If the socket ever moves
	// somewhere more reachable, this check must get narrower with it.
	if peer.Uid == 0 {
		return nil
	}
	if int(peer.Uid) != want {
		return fmt.Errorf("refusing to hand a utun to uid %d; this grant is for uid %d", peer.Uid, want)
	}
	return nil
}
