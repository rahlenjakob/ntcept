package proxy

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/script"
)

// loadScript attaches a scripting engine running src to the harness's server, skipping if python3
// is absent.
func (h *dbHarness) loadScript(t *testing.T, src string) {
	t.Helper()
	e, err := script.New()
	if err != nil {
		if script.ErrNoPython(err) {
			t.Skip("python3 not available")
		}
		t.Fatal(err)
	}
	t.Cleanup(e.Stop)
	path := t.TempDir() + "/rules.py"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.Load(path); err != nil {
		t.Fatal(err)
	}
	h.srv.Script = e
}

// TestScriptRespondsToQuery: a rule answers a SELECT with an error, and it reaches the app while the
// server never sees the query.
func TestScriptRespondsToQuery(t *testing.T) {
	h := newDBHarness(t)
	h.loadScript(t, `
def on_request(m):
    if m.proto == "postgres" and m.is_select:
        log("faulting", m.sql)
        return respond(pg_error="40001: injected by policy")
`)

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		h.app.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := h.app.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
	}()
	go h.sendStartupAndQuery("select * from orders")

	select {
	case reply := <-got:
		if len(reply) == 0 || reply[0] != 'E' || !bytes.Contains(reply, []byte("injected by policy")) {
			t.Fatalf("app did not get the scripted error: %q", reply)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("app never received a reply")
	}
	if bytes.Contains(h.upRecv.bytesReceived(), []byte("select * from orders")) {
		t.Fatal("a scripted-respond query still reached the server")
	}
}

// TestScriptDelaysThenForwards: a rule delays a query; it still reaches the server, just later.
func TestScriptDelaysThenForwards(t *testing.T) {
	h := newDBHarness(t)
	h.loadScript(t, `
def on_request(m):
    if m.proto == "postgres" and m.is_select:
        return delay(500)
`)
	start := time.Now()
	go h.sendStartupAndQuery("select 1")
	waitFor(t, func() bool { return bytes.Contains(h.upRecv.bytesReceived(), []byte("select 1")) },
		"delayed query never reached the server")
	if time.Since(start) < 400*time.Millisecond {
		t.Fatal("query was forwarded without the scripted delay")
	}
}

// TestScriptFailOpenDoesNotBreakTraffic: a throwing rule must not stop the query reaching the server.
func TestScriptFailOpenDoesNotBreakTraffic(t *testing.T) {
	h := newDBHarness(t)
	h.loadScript(t, `
def on_request(m):
    raise RuntimeError("boom")
`)
	go h.sendStartupAndQuery("select 2")
	waitFor(t, func() bool { return bytes.Contains(h.upRecv.bytesReceived(), []byte("select 2")) },
		"a throwing script must fail open and forward the query")
}

// TestScriptRecordRedactsStoredCopy: record() masks the stored copy while the real row still reaches
// the app.
func TestScriptRecordRedactsStoredCopy(t *testing.T) {
	h := newDBHarness(t)
	h.loadScript(t, `
def on_response(m):
    if m.row and len(m.row) >= 2:
        return record(redact=[m.row[1]])   # mask column 2's value in the stored copy
`)
	go h.sendStartupAndQuery("select * from orders")
	uc := <-h.upReady
	waitFor(t, func() bool { return bytes.Contains(h.upRecv.bytesReceived(), []byte("select * from orders")) },
		"query never reached upstream")

	secret := "ada@secret.example"
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		h.app.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := h.app.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
	}()
	go func() { _, _ = uc.Write(pgDataRow("1", secret, "4900")) }()

	// The application must receive the real, unredacted row.
	select {
	case b := <-got:
		if !bytes.Contains(b, []byte(secret)) {
			t.Fatalf("app should receive the real row, got %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("app never received the row")
	}

	// The stored copy must be masked, never carrying the secret.
	waitFor(t, func() bool {
		flows, _ := h.srv.Store.List(capture.Filter{})
		for _, f := range flows {
			for _, m := range f.Messages {
				if bytes.Contains([]byte(m.Decoded), []byte("«redacted»")) {
					return true
				}
			}
		}
		return false
	}, "stored copy was never redacted")
	flows, _ := h.srv.Store.List(capture.Filter{})
	for _, f := range flows {
		for _, m := range f.Messages {
			if bytes.Contains([]byte(m.Decoded), []byte(secret)) {
				t.Fatalf("the secret leaked into the stored copy: %q", m.Decoded)
			}
		}
	}
}
