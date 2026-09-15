//go:build linux

package netns

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

// publisher owns the host-side listeners standing in for ports inside the namespace, and the
// poll that notices new ones.
type publisher struct {
	stk *tunnel.Stack
	out io.Writer

	mu   sync.Mutex
	open map[int]*tunnel.Publication
	// failed records ports that could not be taken on the host, so the reason is reported once
	// rather than every time the poll comes round.
	failed map[int]bool
}

func newPublisher(stk *tunnel.Stack, out io.Writer) *publisher {
	return &publisher{
		stk: stk, out: out,
		open:   map[int]*tunnel.Publication{},
		failed: map[int]bool{},
	}
}

func (p *publisher) add(pm tunnel.PortMap) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.open[pm.ChildPort]; ok {
		return nil
	}
	pub, err := p.stk.Publish(pm)
	if err != nil {
		return err
	}
	p.open[pm.ChildPort] = pub
	fmt.Fprintf(p.out, "ntcept: published %s\n", pub)
	return nil
}

// watch polls the namespace's socket table and publishes what turns up. Polling rather than
// subscribing because the alternative — a netlink socket diag inside the namespace — needs a
// process in there to hold it, and the helper has already become the user's command.
func (p *publisher) watch(ctx context.Context, pid int) {
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		found, err := listening(pid)
		if err != nil {
			// The child is gone, or its /proc entry is. Either way there is nothing to watch.
			return
		}
		for _, l := range found {
			p.mu.Lock()
			_, already := p.open[l.Port]
			failed := p.failed[l.Port]
			p.mu.Unlock()
			if already || failed {
				continue
			}
			if err := p.add(portMapFor(l)); err != nil {
				p.mu.Lock()
				p.failed[l.Port] = true
				p.mu.Unlock()
				// A port already taken on the host is the usual cause, and it is the user's
				// to resolve — ntcept says so and carries on rather than failing the run.
				fmt.Fprintf(p.out, "ntcept: the command is listening on :%d, but that port "+
					"could not be taken on this machine (%v)\n", l.Port, err)
			}
		}
	}
}

func (p *publisher) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, pub := range p.open {
		_ = pub.Close()
	}
	p.open = map[int]*tunnel.Publication{}
}
