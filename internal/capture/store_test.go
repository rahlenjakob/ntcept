package capture

import (
	"strings"
	"testing"
	"time"
)

func TestRingEvictsOldestButKeepsTheNewest(t *testing.T) {
	s := NewStore(4096, 1<<20)
	for i := 0; i < 40; i++ {
		f := s.Begin(KindHTTP, "example.com", 443)
		s.Touch(f, EventFlowUpdate, func(f *Flow) { f.ReqBody = make([]byte, 256) })
	}
	_, bytes, _ := s.Stats()
	if bytes > 4096 {
		t.Fatalf("buffer overran its budget: %d bytes", bytes)
	}
	if _, ok := s.Get("1"); ok {
		t.Fatal("the oldest flow should have been evicted")
	}
	if _, ok := s.Get("40"); !ok {
		t.Fatal("the newest flow must be retained")
	}
}

func TestASingleOversizedFlowIsStillKept(t *testing.T) {
	s := NewStore(1024, 1<<20)
	f := s.Begin(KindHTTP, "example.com", 443)
	s.Touch(f, EventFlowUpdate, func(f *Flow) { f.ResBody = make([]byte, 100_000) })
	if n, _, _ := s.Stats(); n != 1 {
		t.Fatal("never evict down to nothing — the last flow is usually the interesting one")
	}
}

func TestSubscribersSeeEventsAndSlowOnesDoNotBlock(t *testing.T) {
	s := NewStore(1<<20, 1<<20)
	id, ch := s.Subscribe()
	defer s.Unsubscribe(id)
	s.Begin(KindHTTP, "example.com", 443)
	select {
	case e := <-ch:
		if e.Type != EventFlowNew {
			t.Fatalf("got %s", e.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber saw nothing")
	}
	// Overrun the buffer; the proxy must never be blocked by a subscriber that stopped reading.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			s.Begin(KindHTTP, "example.com", 443)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a slow subscriber blocked the capture path")
	}
}

func TestFilters(t *testing.T) {
	s := NewStore(1<<20, 1<<20)
	a := s.Begin(KindHTTP, "api.example.com", 443)
	s.Touch(a, EventFlowUpdate, func(f *Flow) { f.Method, f.Path, f.Status = "POST", "/orders", 201 })
	b := s.Begin(KindHTTP, "cdn.example.com", 443)
	s.Touch(b, EventFlowUpdate, func(f *Flow) { f.Method, f.Path, f.Status = "GET", "/logo.png", 200 })

	if got, _ := s.List(Filter{Host: "api"}); len(got) != 1 || got[0].Path != "/orders" {
		t.Fatalf("host filter: %v", got)
	}
	if got, _ := s.List(Filter{Status: 200}); len(got) != 1 || got[0].Path != "/logo.png" {
		t.Fatalf("status filter: %v", got)
	}
	if got, _ := s.List(Filter{Method: "post"}); len(got) != 1 {
		t.Fatal("method filter should be case-insensitive")
	}
	if _, err := s.List(Filter{Grep: "([bad"}); err == nil {
		t.Fatal("an invalid pattern should be reported, not silently ignored")
	}
}

func TestVerdictRejectsUnknownActions(t *testing.T) {
	var v Verdict
	if err := v.Action.UnmarshalJSON([]byte(`"forward"`)); err != nil {
		t.Fatalf("forward should be valid: %v", err)
	}
	if err := v.Action.UnmarshalJSON([]byte(`"explode"`)); err == nil {
		t.Fatal("an unknown action must be rejected rather than silently doing nothing")
	}
}

// A raw-relay flow should read as the protocol the decoder identified, not the bare transport —
// "postgres" and "redis" are what a person scans for, not "tcp".
func TestLineShowsDecodedProtocol(t *testing.T) {
	pg := &Flow{ID: "3", Kind: KindTCP, Host: "127.0.0.1", Port: 15432, Path: "postgres"}
	if !strings.Contains(pg.Line(), "postgres") || strings.Contains(pg.Line(), " tcp ") {
		t.Fatalf("a postgres flow should be labelled postgres, got %q", pg.Line())
	}
	dns := &Flow{ID: "4", Kind: KindUDP, Host: "1.1.1.1", Port: 53, Path: "dns"}
	if !strings.Contains(dns.Line(), "dns") {
		t.Fatalf("a dns flow should be labelled dns, got %q", dns.Line())
	}
	// An unidentified stream falls back to the transport.
	raw := &Flow{ID: "5", Kind: KindTCP, Host: "10.0.0.1", Port: 9999, Path: "raw"}
	if !strings.Contains(raw.Line(), "tcp") {
		t.Fatalf("an unrecognised stream should read as tcp, got %q", raw.Line())
	}
	// WebSocket keeps its own kind, since its Path holds the URL, not a protocol name.
	ws := &Flow{ID: "6", Kind: KindWS, Host: "example.com", Port: 443, Path: "/chat"}
	if !strings.Contains(ws.Line(), "ws") {
		t.Fatalf("a websocket flow should read as ws, got %q", ws.Line())
	}
}
