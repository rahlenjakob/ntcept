package script

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

//go:embed harness.py
var harnessPy []byte

// Engine owns the python worker and mediates every call into it. It is safe for concurrent use: the
// proxy calls Eval from one goroutine per connection, and the control plane drives load/reload/reset
// from another. A nil *Engine, or one with no script loaded, is a no-op that passes everything.
type Engine struct {
	python      string
	harnessPath string

	mu         sync.Mutex
	w          *worker
	scriptPath string
	seq        int64
	timeout    time.Duration
	lastStart  time.Time
	watch      bool
	lastMod    time.Time
	done       chan struct{}

	// status
	loadErr  string
	calls    int64
	failures int64
	restarts int64
	counts   map[string]int64

	logs *ring
}

// New prepares an engine. It does not start a worker until a script is loaded. err is non-nil only
// when python3 is missing, so callers can report that specifically.
func New() (*Engine, error) {
	python := findPython()
	if python == "" {
		return nil, errNoPython
	}
	f, err := os.CreateTemp("", "ntcept-harness-*.py")
	if err != nil {
		return nil, err
	}
	if _, err := f.Write(harnessPy); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()
	e := &Engine{
		python: python, harnessPath: f.Name(),
		timeout: 2 * time.Second, counts: map[string]int64{}, logs: newRing(500),
		done: make(chan struct{}),
	}
	go e.watchLoop()
	return e, nil
}

// SetWatch turns auto-reload on file change on or off. With it on, editing the loaded script takes
// effect (keeping state) without any command.
func (e *Engine) SetWatch(on bool) {
	e.mu.Lock()
	e.watch = on
	if on && e.scriptPath != "" {
		if fi, err := os.Stat(e.scriptPath); err == nil {
			e.lastMod = fi.ModTime()
		}
	}
	e.mu.Unlock()
}

// watchLoop reloads the script when its file changes and watching is on. Polling mtime keeps this
// dependency-free and good enough for an agent saving a file.
func (e *Engine) watchLoop() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-e.done:
			return
		case <-t.C:
		}
		e.mu.Lock()
		watch, path, last := e.watch, e.scriptPath, e.lastMod
		e.mu.Unlock()
		if !watch || path == "" {
			continue
		}
		fi, err := os.Stat(path)
		if err != nil || !fi.ModTime().After(last) {
			continue
		}
		e.mu.Lock()
		e.lastMod = fi.ModTime()
		e.mu.Unlock()
		if err := e.Reload(); err == nil {
			e.logs.add("[ntcept] reloaded on change: " + path)
		}
	}
}

var errNoPython = errors.New("python3 is not on PATH; scripting needs it (see `ntcept doctor`)")

// ErrNoPython reports whether an error from New means python3 is absent.
func ErrNoPython(err error) bool { return errors.Is(err, errNoPython) }

func findPython() string {
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// Load points the worker at a script file and (re)starts it fresh. State is not carried over — Load
// is a new start; use Reload to keep state.
func (e *Engine) Load(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(abs); err != nil {
		return fmt.Errorf("script not found: %s", abs)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.scriptPath = abs
	return e.startLocked()
}

// LoadSource writes inline code (piped in, or sent over the control API) to dest and loads it, so
// reload and file-watching have a real path to work with.
func (e *Engine) LoadSource(src []byte, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(dest, src, 0o600); err != nil {
		return err
	}
	return e.Load(dest)
}

// Reload re-imports the script, keeping state; Reset re-imports and wipes state.
func (e *Engine) Reload() error { return e.command("reload") }
func (e *Engine) Reset() error  { return e.command("reset") }

func (e *Engine) command(cmd string) error {
	e.mu.Lock()
	w := e.w
	e.mu.Unlock()
	if w == nil {
		return errors.New("no script is loaded")
	}
	reply, err := w.roundtrip(map[string]any{"t": "cmd", "cmd": cmd, "seq": -1}, e.timeout)
	if err != nil {
		return err
	}
	var ack struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.Unmarshal(reply, &ack) == nil && !ack.OK {
		return fmt.Errorf("%s failed: %s", cmd, ack.Error)
	}
	return nil
}

// Off stops the worker and disables scripting; the proxy goes back to passing everything.
func (e *Engine) Off() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.w != nil {
		e.w.stop()
		e.w = nil
	}
	e.scriptPath = ""
}

// Stop shuts the engine down for good.
func (e *Engine) Stop() {
	select {
	case <-e.done:
	default:
		close(e.done)
	}
	e.Off()
	if e.harnessPath != "" {
		_ = os.Remove(e.harnessPath)
	}
}

// Enabled reports whether a script is loaded, so the hot path can skip Eval entirely otherwise.
func (e *Engine) Enabled() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scriptPath != ""
}

func (e *Engine) startLocked() error {
	if e.w != nil {
		e.w.stop()
		e.w = nil
	}
	e.lastStart = time.Now()
	w, err := startWorker(e.python, e.harnessPath, e.scriptPath, e.logs.add)
	if err != nil {
		e.loadErr = err.Error()
		return err
	}
	e.w = w
	e.loadErr = ""
	if fi, err := os.Stat(e.scriptPath); err == nil {
		e.lastMod = fi.ModTime() // so a fresh load is not immediately seen as a change
	}
	e.logs.add("[ntcept] loaded " + e.scriptPath)
	return nil
}

// Eval asks the worker to judge one message. The second return is false when the verdict could not
// be obtained (no script, worker error, timeout) — the caller passes the message through unchanged.
func (e *Engine) Eval(ev Event) (Result, bool) {
	e.mu.Lock()
	if e.scriptPath == "" {
		e.mu.Unlock()
		return Result{Action: Pass}, false
	}
	if e.w == nil || !e.w.alive() {
		// Restart at most every couple of seconds, so a script that crashes on start does not
		// spin the CPU relaunching python for every request.
		if time.Since(e.lastStart) < 2*time.Second {
			e.mu.Unlock()
			return Result{Action: Pass}, false
		}
		e.restarts++
		if err := e.startLocked(); err != nil {
			e.mu.Unlock()
			return Result{Action: Pass}, false
		}
	}
	e.seq++
	ev.Seq = e.seq
	e.calls++
	w := e.w
	timeout := e.timeout
	e.mu.Unlock()

	reply, err := w.roundtrip(ev, timeout)
	if err != nil {
		e.mu.Lock()
		e.failures++
		e.loadErr = err.Error()
		if e.w != nil {
			e.w.stop()
			e.w = nil // a timeout or death forces a fresh worker next time
		}
		e.mu.Unlock()
		e.logs.add("[ntcept] " + err.Error() + " — passing through")
		return Result{Action: Pass}, false
	}
	var wv wireVerdict
	if json.Unmarshal(reply, &wv) != nil {
		return Result{Action: Pass}, false
	}
	r := wv.result()
	// Tag each log line with the exchange id in the global ring, so `script logs` reads per-request.
	for _, l := range r.Logs {
		e.logs.add("[" + ev.Exchange + "] " + l)
	}
	e.mu.Lock()
	e.counts[string(r.Action)]++
	e.mu.Unlock()
	return r, true
}

// Status is a snapshot for `ntcept script status`.
type Status struct {
	Loaded    bool             `json:"loaded"`
	Path      string           `json:"path,omitempty"`
	Python    string           `json:"python"`
	Running   bool             `json:"running"`
	LastError string           `json:"last_error,omitempty"`
	Calls     int64            `json:"calls"`
	Failures  int64            `json:"failures"`
	Restarts  int64            `json:"restarts"`
	Verdicts  map[string]int64 `json:"verdicts"`
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	vs := map[string]int64{}
	for k, v := range e.counts {
		vs[k] = v
	}
	return Status{
		Loaded: e.scriptPath != "", Path: e.scriptPath, Python: e.python,
		Running: e.w != nil && e.w.alive(), LastError: e.loadErr,
		Calls: e.calls, Failures: e.failures, Restarts: e.restarts, Verdicts: vs,
	}
}

// Logs returns the recent worker output (prints, logs, tracebacks, engine notes).
func (e *Engine) Logs() []string { return e.logs.snapshot() }
