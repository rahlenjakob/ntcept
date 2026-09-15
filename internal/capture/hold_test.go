package capture

import (
	"sync"
	"testing"
	"time"
)

func TestAParkedExchangeIsReleasedToItsOwnWaiter(t *testing.T) {
	q := NewQueue()
	a := &Held{Stage: StageRequest, Host: "a.example"}
	b := &Held{Stage: StageRequest, Host: "b.example"}
	ca, cb := q.Park(a), q.Park(b)

	if q.Len() != 2 {
		t.Fatalf("both should be parked, got %d", q.Len())
	}
	if a.ID == b.ID {
		t.Fatal("parked exchanges must be separately addressable")
	}

	if !q.Release(b.ID, Verdict{Action: ActionDrop}) {
		t.Fatal("releasing a parked exchange should succeed")
	}
	select {
	case v := <-cb:
		if v.Action != ActionDrop {
			t.Fatalf("the wrong verdict arrived: %q", v.Action)
		}
	case <-time.After(time.Second):
		t.Fatal("the verdict never reached the waiter")
	}
	select {
	case v := <-ca:
		t.Fatalf("releasing b must not wake a, but a got %q", v.Action)
	default:
	}
	if q.Len() != 1 {
		t.Fatalf("a released exchange must leave the queue, %d left", q.Len())
	}
}

func TestListPreservesArrivalOrder(t *testing.T) {
	q := NewQueue()
	for _, host := range []string{"first", "second", "third"} {
		q.Park(&Held{Host: host})
	}
	got := q.List()
	for i, want := range []string{"first", "second", "third"} {
		if got[i].Host != want {
			t.Fatalf("position %d is %q, want %q: the queue is not in arrival order",
				i, got[i].Host, want)
		}
	}
}

// Releasing something that already went, or that expired, has to be a clean no rather than a
// panic or a silent success — the control API turns this into a 404 the operator can act on.
func TestReleasingSomethingThatIsNoLongerHeldFails(t *testing.T) {
	q := NewQueue()
	h := &Held{Host: "gone.example"}
	q.Park(h)

	if !q.Release(h.ID, Verdict{Action: ActionForward}) {
		t.Fatal("the first release should succeed")
	}
	if q.Release(h.ID, Verdict{Action: ActionForward}) {
		t.Fatal("releasing twice must not succeed")
	}
	if q.Release("h-never-existed", Verdict{Action: ActionForward}) {
		t.Fatal("releasing an unknown id must not succeed")
	}
}

func TestForgetDropsAnExpiredHold(t *testing.T) {
	q := NewQueue()
	h := &Held{Host: "expired.example"}
	q.Park(h)
	q.Forget(h.ID)

	if q.Len() != 0 {
		t.Fatal("a forgotten hold must leave the queue")
	}
	if _, ok := q.Get(h.ID); ok {
		t.Fatal("a forgotten hold must not be gettable")
	}
	if q.Release(h.ID, Verdict{Action: ActionForward}) {
		t.Fatal("a forgotten hold must not be releasable")
	}
}

// The queue is written by every request goroutine and read by the control API at the same time.
// Under -race this is the test that would catch a missing lock.
func TestConcurrentParkAndRelease(t *testing.T) {
	q := NewQueue()
	const n = 64

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := &Held{Host: "concurrent.example"}
			ch := q.Park(h)
			select {
			case <-ch:
			case <-time.After(10 * time.Second):
				t.Error("a parked exchange was never released")
			}
		}()
	}

	released := 0
	deadline := time.Now().Add(10 * time.Second)
	for released < n && time.Now().Before(deadline) {
		for _, h := range q.List() {
			if q.Release(h.ID, Verdict{Action: ActionForward}) {
				released++
			}
		}
		// Also exercise the readers racing the writers.
		_ = q.Len()
	}
	wg.Wait()
	if released != n {
		t.Fatalf("released %d of %d", released, n)
	}
	if q.Len() != 0 {
		t.Fatalf("the queue should be empty, %d left", q.Len())
	}
}
