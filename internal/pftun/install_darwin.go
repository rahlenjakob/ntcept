//go:build darwin

package pftun

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

var installedOnce struct {
	sync.Once
	ok  bool
	why string
}

// Installed reports whether the one-time setup has been done, so `ntcept run` needs no password.
// The probe spawns sudo, so it is answered once per process rather than per caller.
func Installed() bool {
	ok, _ := installState()
	return ok
}

// InstallState explains a negative answer, which is the difference between "never installed" and
// "installed, but the binary has been rebuilt since".
func InstallState() (bool, string) { return installState() }

func installState() (bool, string) {
	installedOnce.Do(func() {
		if _, err := os.Stat(HelperPath); err != nil {
			installedOnce.why = "not installed yet"
			return
		}
		// The helper is a copy of this binary, so the privileged mode has to be named
		// explicitly; a bare flag would fall through to the ordinary CLI.
		out, err := exec.Command("sudo", "-n", HelperPath, HelperArg, "--check").Output()
		if err != nil {
			installedOnce.why = "the sudoers grant is not in effect"
			return
		}
		got := protocolOf(string(out))
		if got != HelperProtocol {
			installedOnce.why = fmt.Sprintf(
				"the installed helper speaks protocol %d, this ntcept speaks %d", got, HelperProtocol)
			return
		}
		installedOnce.ok = true
	})
	return installedOnce.ok, installedOnce.why
}

// protocolOf reads the version an installed helper reports. A helper too old to report one is
// protocol 0, which never matches.
func protocolOf(out string) int {
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) == 0 {
		return 0
	}
	n, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil {
		return 0
	}
	return n
}

// Install performs the one-time privileged setup: a root-owned helper, a narrowly scoped
// sudoers grant for exactly that helper, and the static pf anchor. After this, `ntcept run`
// never asks for a password again.
//
// It deliberately does not set the setuid bit. The grant is a sudoers rule pinned to one
// absolute path, which is auditable with `cat` and removable with `ntcept uninstall`.
func Install(grantSudoers bool) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run `sudo ntcept install` — this is the only step that needs a password")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(HelperPath), 0o755); err != nil {
		return err
	}
	if err := copyFile(self, HelperPath, 0o755); err != nil {
		return fmt.Errorf("installing the helper: %w", err)
	}
	if err := os.Chown(HelperPath, 0, 0); err != nil {
		return fmt.Errorf("securing the helper: %w", err)
	}

	// Confirm pf is operable, then hand the reference straight back — install must not leave pf
	// enabled. Each `run` enables it for its own lifetime and releases it on exit.
	token, err := enable()
	if err != nil {
		return err
	}
	release(token)
	fmt.Printf("  ✓ helper      %s (root-owned, not setuid)\n", HelperPath)
	fmt.Printf("  ✓ pf          reachable; enabled per run and released on exit\n")

	if !grantSudoers {
		_ = os.Remove(SudoersPath)
		fmt.Println("  · sudoers     skipped — `sudo ntcept run` will ask for a password each time")
		return nil
	}
	who, err := invokingUser()
	if err != nil {
		return err
	}
	rule := fmt.Sprintf("# installed by ntcept; remove with `sudo ntcept uninstall`\n%s ALL=(root) NOPASSWD: %s\n", who, HelperPath)
	if err := writeSudoers(rule); err != nil {
		return err
	}
	fmt.Printf("  ✓ sudoers     %s — %s may run that one path without a password\n", SudoersPath, who)
	fmt.Println("\n`ntcept run` now needs no sudo. `sudo ntcept uninstall` reverses all of it.")
	fmt.Println("\nWorth knowing what that grant is: the helper creates a utun and loads ntcept's")
	fmt.Printf("pf anchor, which means a process running as %s can inject IP packets into this\n", who)
	fmt.Println("machine's stack and install loopback redirects (of ntcept's fixed shape) without a")
	fmt.Println("password. On a single-user laptop that is a fair trade for never being prompted")
	fmt.Println("again. On a shared or hardened machine, prefer `sudo ntcept install --no-sudoers`")
	fmt.Println("and pay the password each run.")
	return nil
}

// Uninstall removes everything Install added.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run `sudo ntcept uninstall`")
	}
	for _, anchor := range staleAnchors() {
		flushAnchorFor(anchor)
	}
	var errs []string
	for _, p := range []string{HelperPath, SudoersPath} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	fmt.Println("  ✓ helper, sudoers grant and pf anchor removed")
	return nil
}

// writeSudoers validates before installing: a malformed drop-in can lock a machine out of sudo.
func writeSudoers(rule string) error {
	tmp, err := os.CreateTemp("", "ntcept-sudoers-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(rule); err != nil {
		return err
	}
	tmp.Close()
	if out, err := exec.Command("visudo", "-c", "-f", tmp.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("refusing to install an invalid sudoers rule: %s", strings.TrimSpace(string(out)))
	}
	if err := copyFile(tmp.Name(), SudoersPath, 0o440); err != nil {
		return err
	}
	return os.Chown(SudoersPath, 0, 0)
}

func invokingUser() (string, error) {
	if v := os.Getenv("SUDO_USER"); v != "" {
		return v, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if u.Uid == "0" {
		return "", fmt.Errorf("cannot tell which user to grant; run `sudo ntcept install` from your own account")
	}
	return u.Username, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Chmod(mode)
}

// SudoUID is the account a supervised command should run as — never root.
func SudoUID() (uid, gid int, err error) {
	uid, gid = os.Getuid(), os.Getgid()
	if v, e := strconv.Atoi(os.Getenv("SUDO_UID")); e == nil {
		uid = v
	}
	if v, e := strconv.Atoi(os.Getenv("SUDO_GID")); e == nil {
		gid = v
	}
	if uid == 0 {
		return 0, 0, fmt.Errorf("refusing to run the supervised command as root")
	}
	return uid, gid, nil
}
