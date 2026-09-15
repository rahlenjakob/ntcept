package script

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newLoaded starts an engine on the given script source, skipping if python3 is absent.
func newLoaded(t *testing.T, src string) *Engine {
	t.Helper()
	e, err := New()
	if err != nil {
		if ErrNoPython(err) {
			t.Skip("python3 not available")
		}
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	path := filepath.Join(t.TempDir(), "rules.py")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Load(path); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEvalRespondAndPass(t *testing.T) {
	e := newLoaded(t, `
def on_request(m):
    if m.proto == "postgres" and m.is_select:
        return respond(pg_error="40001: injected")
    return None
`)
	r, ok := e.Eval(Event{Hook: "on_request", Proto: "postgres", SQL: "select 1", Direction: "request"})
	if !ok || r.Action != Respond || r.PGCode != "40001" || r.PGMessage != "injected" {
		t.Fatalf("select verdict = %+v ok=%v", r, ok)
	}
	r, ok = e.Eval(Event{Hook: "on_request", Proto: "postgres", SQL: "insert into t values(1)"})
	if !ok || r.Action != Pass {
		t.Fatalf("insert should pass, got %+v", r)
	}
}

func TestStatePersistsAndResetWipes(t *testing.T) {
	e := newLoaded(t, `
def on_request(m):
    state["n"] = state.get("n", 0) + 1
    if state["n"] >= 3:
        return drop()
    return None
`)
	for i := 0; i < 2; i++ {
		if r, _ := e.Eval(Event{Hook: "on_request", Proto: "redis"}); r.Action != Pass {
			t.Fatalf("call %d should pass", i)
		}
	}
	if r, _ := e.Eval(Event{Hook: "on_request", Proto: "redis"}); r.Action != Drop {
		t.Fatal("third call should drop once state reaches 3")
	}
	// Reload keeps state, so the counter stays past the threshold.
	if err := e.Reload(); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.Eval(Event{Hook: "on_request", Proto: "redis"}); r.Action != Drop {
		t.Fatal("reload should keep state (counter still >= 3)")
	}
	// Reset wipes it, so we pass again until the threshold is reached anew.
	if err := e.Reset(); err != nil {
		t.Fatal(err)
	}
	if r, _ := e.Eval(Event{Hook: "on_request", Proto: "redis"}); r.Action != Pass {
		t.Fatal("reset should wipe state (counter back to 1)")
	}
}

func TestPerExchangeContext(t *testing.T) {
	e := newLoaded(t, `
def on_request(m):
    m.ctx["v"] = 42
def on_response(m):
    if m.ctx.get("v") == 42:
        return drop()
`)
	e.Eval(Event{Hook: "on_request", Exchange: "x1", Proto: "postgres", Direction: "request"})
	if r, _ := e.Eval(Event{Hook: "on_response", Exchange: "x1", Proto: "postgres", Direction: "response"}); r.Action != Drop {
		t.Fatal("on_response should see the ctx value on_request set for the same exchange")
	}
	// A different exchange must not see it.
	if r, _ := e.Eval(Event{Hook: "on_response", Exchange: "x2", Proto: "postgres", Direction: "response"}); r.Action != Pass {
		t.Fatal("a different exchange must have its own empty ctx")
	}
}

func TestThrowingScriptFailsOpen(t *testing.T) {
	e := newLoaded(t, `
def on_request(m):
    raise ValueError("boom")
`)
	if r, ok := e.Eval(Event{Hook: "on_request", Proto: "postgres"}); r.Action != Pass || !ok {
		t.Fatalf("a throwing hook must fail open to pass, got %+v ok=%v", r, ok)
	}
}

func TestSlowScriptTimesOutAndFailsOpen(t *testing.T) {
	e := newLoaded(t, `
import time
def on_request(m):
    time.sleep(30)
`)
	e.timeout = 300 * time.Millisecond
	start := time.Now()
	r, ok := e.Eval(Event{Hook: "on_request", Proto: "postgres"})
	if r.Action != Pass || ok {
		t.Fatalf("a slow hook must time out and pass, got %+v ok=%v", r, ok)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout did not fire promptly")
	}
}

func TestWatchReloadsOnChange(t *testing.T) {
	e, err := New()
	if err != nil {
		if ErrNoPython(err) {
			t.Skip("python3 not available")
		}
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	path := filepath.Join(t.TempDir(), "rules.py")
	if err := os.WriteFile(path, []byte("def on_request(m):\n    return drop()\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Load(path); err != nil {
		t.Fatal(err)
	}
	e.SetWatch(true)
	if r, _ := e.Eval(Event{Hook: "on_request", Proto: "redis"}); r.Action != Drop {
		t.Fatal("should drop before the edit")
	}
	// Rewrite the file and stamp its mtime forward so the poll sees a change.
	if err := os.WriteFile(path, []byte("def on_request(m):\n    return None\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if r, _ := e.Eval(Event{Hook: "on_request", Proto: "redis"}); r.Action == Pass {
			return // the watcher reloaded the new rule
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("watch did not reload the changed script")
}
