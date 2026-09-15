package script

import (
	"sync"
	"time"
)

// ring is a bounded, concurrent log buffer: the worker writes lines from one goroutine, the control
// plane reads snapshots from another, and old lines fall off the back.
type ring struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newRing(max int) *ring { return &ring{max: max} }

func (r *ring) add(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, time.Now().Format("15:04:05.000")+" "+line)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
}

func (r *ring) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}
