package script

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

// worker is one running python3 process holding the user's code and its state. It speaks the line
// protocol on its stdin/stdout; its stderr (prints, logs, tracebacks) is copied to the log sink.
type worker struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	replies chan []byte
	dead    chan struct{}

	mu     sync.Mutex
	closed bool
}

// startWorker launches python3 running the embedded harness against the user's script path. log
// receives every line the worker writes to stderr.
func startWorker(python, harnessPath, scriptPath string, log func(string)) (*worker, error) {
	cmd := exec.Command(python, harnessPath, scriptPath)
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1", "PYTHONDONTWRITEBYTECODE=1")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting python worker: %w", err)
	}

	w := &worker{cmd: cmd, stdin: stdin, replies: make(chan []byte, 8), dead: make(chan struct{})}

	// Replies: one JSON line per request, in order. Kept off the user's stderr, which carries logs.
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
		for sc.Scan() {
			b := append([]byte(nil), sc.Bytes()...)
			select {
			case w.replies <- b:
			case <-w.dead:
				return
			}
		}
	}()
	// Logs: the user's window into their own code.
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
		for sc.Scan() {
			log(sc.Text())
		}
	}()
	// Reap: closing dead unblocks any waiting request.
	go func() {
		_ = cmd.Wait()
		close(w.dead)
	}()
	return w, nil
}

var errWorkerGone = errors.New("python worker exited")

// roundtrip writes one request and waits for the matching reply, or fails if the worker is too slow
// or has died. The engine serializes calls, so there is only ever one request in flight.
func (w *worker) roundtrip(req any, timeout time.Duration) ([]byte, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil, errWorkerGone
	}
	_, err = w.stdin.Write(append(b, '\n'))
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case reply := <-w.replies:
		return reply, nil
	case <-w.dead:
		return nil, errWorkerGone
	case <-time.After(timeout):
		return nil, fmt.Errorf("python worker did not answer within %s", timeout)
	}
}

func (w *worker) stop() {
	w.mu.Lock()
	w.closed = true
	_ = w.stdin.Close()
	w.mu.Unlock()
	if w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
}

func (w *worker) alive() bool {
	select {
	case <-w.dead:
		return false
	default:
		return true
	}
}
