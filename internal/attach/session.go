// Package attach starts an application under interception without changing the application or
// the machine it runs on. Everything it sets lives in the child process's own environment.
package attach

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/rahlenjakob/ntcept/internal/ca"
)

// A session is one running ntcept. There can be several: a frontend and a backend, or two
// services that talk to each other, are an obvious thing to want under one debugger, and until
// each had its own file the second `ntcept run` silently overwrote the first and every command
// afterwards addressed whichever wrote last.
type Session struct {
	// Name addresses this session. It is derived from the command unless one is given, because
	// `ntcept ls --session api` is what someone will actually type.
	Name        string    `json:"name"`
	PID         int       `json:"pid"`
	ProxyPort   int       `json:"proxy_port"`
	ControlPort int       `json:"control_port"`
	Started     time.Time `json:"started"`
	Command     string    `json:"command,omitempty"`
}

func (s Session) ControlURL() string {
	return fmt.Sprintf("http://127.0.0.1:%d", s.ControlPort)
}

// SessionsDir holds one file per running ntcept.
func SessionsDir() string { return filepath.Join(ca.Home(), "sessions") }

func SessionPath(name string) string {
	return filepath.Join(SessionsDir(), name+".json")
}

var unsafeName = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// CleanName reduces anything to something usable as both a file name and a command-line word.
func CleanName(s string) string {
	s = unsafeName.ReplaceAllString(strings.TrimSpace(s), "-")
	s = strings.Trim(s, "-.")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// NameFor invents a session name from the command being run, falling back to the pid. A second
// run of the same command gets a numbered suffix rather than clobbering the first.
func NameFor(args []string, pid int) string {
	base := ""
	if len(args) > 0 {
		base = CleanName(filepath.Base(args[0]))
		// `npm run dev` and `npm run build` should not both just be "npm".
		if base == "npm" || base == "yarn" || base == "pnpm" || base == "go" || base == "cargo" {
			for _, a := range args[1:] {
				if c := CleanName(a); c != "" && !strings.HasPrefix(a, "-") && c != "run" {
					base += "-" + c
					break
				}
			}
		}
	}
	if base == "" {
		base = fmt.Sprintf("ntcept-%d", pid)
	}
	if !exists(base) {
		return base
	}
	for i := 2; i < 100; i++ {
		candidate := fmt.Sprintf("%s-%d", base, i)
		if !exists(candidate) {
			return candidate
		}
	}
	return fmt.Sprintf("%s-%d", base, pid)
}

func exists(name string) bool {
	_, err := os.Stat(SessionPath(name))
	return err == nil
}

func WriteSession(s Session) error {
	if s.Name == "" {
		return errors.New("a session needs a name")
	}
	if err := os.MkdirAll(SessionsDir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(SessionPath(s.Name), b, 0o600)
}

func RemoveSession(name string) { _ = os.Remove(SessionPath(name)) }

// ListSessions returns the ones whose process is still alive, pruning the rest as it goes. A
// crashed run should not keep answering for a session that is gone.
func ListSessions() ([]Session, error) {
	entries, err := os.ReadDir(SessionsDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []Session
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(SessionsDir(), e.Name()))
		if err != nil {
			continue
		}
		var s Session
		if err := json.Unmarshal(b, &s); err != nil || s.PID == 0 {
			_ = os.Remove(filepath.Join(SessionsDir(), e.Name()))
			continue
		}
		if !alive(s.PID) {
			RemoveSession(s.Name)
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started.Before(out[j].Started) })
	return out, nil
}

// ErrNoSession is returned when nothing is running, so callers can tell it apart from ambiguity.
var ErrNoSession = errors.New("no ntcept is running — start one with `ntcept run -- <your app>`")

// ResolveSession picks the session a command should address.
//
// With one running, naming it is unnecessary — that is the common case and it stays a
// single-word command. With several, ntcept refuses and lists them rather than guessing, because
// silently addressing the wrong application is worse than an error.
func ResolveSession(want string) (*Session, error) {
	sessions, err := ListSessions()
	if err != nil {
		return nil, err
	}
	if want != "" {
		for i := range sessions {
			if sessions[i].Name == want {
				return &sessions[i], nil
			}
		}
		if len(sessions) == 0 {
			return nil, ErrNoSession
		}
		return nil, fmt.Errorf("no session named %q; running: %s", want, names(sessions))
	}
	switch len(sessions) {
	case 0:
		return nil, ErrNoSession
	case 1:
		return &sessions[0], nil
	default:
		return nil, fmt.Errorf("%d sessions are running: %s\n"+
			"say which one with --session <name>, or set NTCEPT_SESSION",
			len(sessions), names(sessions))
	}
}

func names(sessions []Session) string {
	out := make([]string, len(sessions))
	for i, s := range sessions {
		out[i] = s.Name
	}
	return strings.Join(out, ", ")
}

// StopStale terminates sessions whose starter has gone away but which are still holding ports,
// and reports how many. Used by `ntcept cleanup`.
func StopStale() []Session {
	sessions, err := ListSessions()
	if err != nil {
		return nil
	}
	var stopped []Session
	self := os.Getpid()
	for _, s := range sessions {
		if s.PID == self {
			continue
		}
		p, err := os.FindProcess(s.PID)
		if err != nil {
			RemoveSession(s.Name)
			continue
		}
		_ = p.Signal(syscall.SIGTERM)
		for i := 0; i < 20 && alive(s.PID); i++ {
			time.Sleep(50 * time.Millisecond)
		}
		if alive(s.PID) {
			_ = p.Signal(syscall.SIGKILL)
		}
		RemoveSession(s.Name)
		stopped = append(stopped, s)
	}
	// The single-session file this replaced, if an older ntcept left one behind.
	_ = os.Remove(filepath.Join(ca.Home(), "session.json"))
	return stopped
}

// alive probes with signal 0, which checks for the process without disturbing it. Go rejects a
// nil signal outright, so it cannot be used for this.
func alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
