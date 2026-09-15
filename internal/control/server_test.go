package control

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/proxy"
)

func newServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := capture.NewStore(16<<20, 1<<20)
	s := &Server{
		Store: store,
		Proxy: proxy.New(store, authority),
		Info:  SessionInfo{PID: 4242, ProxyPort: 8080, ControlPort: 4300, Started: time.Now()},
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func get(t *testing.T, ts *httptest.Server, path string) map[string]any {
	t.Helper()
	res, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("GET %s: %d %s", path, res.StatusCode, b)
	}
	var m map[string]any
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		t.Fatal(err)
	}
	return m
}

func post(t *testing.T, ts *httptest.Server, path, body string) (int, map[string]any) {
	t.Helper()
	res, err := ts.Client().Post(ts.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(res.Body).Decode(&m)
	return res.StatusCode, m
}

func TestStatusReportsTheSessionAndItsMode(t *testing.T) {
	_, ts := newServer(t)
	m := get(t, ts, "/status")
	session, ok := m["session"].(map[string]any)
	if !ok {
		t.Fatalf("no session in status: %v", m)
	}
	if session["pid"].(float64) != 4242 {
		t.Fatalf("wrong pid: %v", session["pid"])
	}
	if m["hold_requests"].(bool) {
		t.Fatal("nothing should be held until asked; an unattended run must not stall")
	}
}

func TestModeTogglesAreAppliedAndReflected(t *testing.T) {
	s, ts := newServer(t)
	code, m := post(t, ts, "/mode", `{"hold_requests":true,"hold_ms":1234,"offline":true}`)
	if code != 200 {
		t.Fatalf("setting the mode failed: %d", code)
	}
	if !s.Proxy.HoldRequests.Load() || s.Proxy.HoldMS.Load() != 1234 || !s.Proxy.Offline.Load() {
		t.Fatal("the proxy did not take the new mode")
	}
	// The response is the new status, so a caller needs one round trip rather than two.
	if !m["hold_requests"].(bool) || m["hold_ms"].(float64) != 1234 {
		t.Fatalf("the response should be the resulting status, got %v", m)
	}

	// Fields left out must not be reset; a caller toggling one thing must not clear another.
	if _, m = post(t, ts, "/mode", `{"hold_responses":true}`); !m["hold_requests"].(bool) {
		t.Fatal("an unrelated toggle was cleared")
	}
}

func TestFlowsAreListedFilteredAndFetched(t *testing.T) {
	s, ts := newServer(t)
	for _, tc := range []struct {
		host, path, method string
		status             int
	}{
		{"api.stripe.com", "/v1/charges", "POST", 402},
		{"api.github.com", "/user", "GET", 200},
	} {
		f := s.Store.Begin(capture.KindHTTP, tc.host, 443)
		s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
			f.Method, f.Path, f.Status = tc.method, tc.path, tc.status
			f.ResBody = []byte(`{"id":"ch_42"}`)
		})
		s.Store.Finish(f, nil)
	}

	all := get(t, ts, "/flows")["flows"].([]any)
	if len(all) != 2 {
		t.Fatalf("expected both flows, got %d", len(all))
	}

	byStatus := get(t, ts, "/flows?status=402")["flows"].([]any)
	if len(byStatus) != 1 {
		t.Fatalf("status filter returned %d flows", len(byStatus))
	}

	// --grep is the one filter that reaches into bodies, and the UI does not use it yet.
	byGrep := get(t, ts, "/flows?grep=ch_42")["flows"].([]any)
	if len(byGrep) != 2 {
		t.Fatalf("grep across bodies returned %d flows", len(byGrep))
	}

	one := get(t, ts, "/flows/1")
	if one["method"] != "POST" || one["res_body"] != `{"id":"ch_42"}` {
		t.Fatalf("the detail view is missing what it is for: %v", one)
	}
}

func TestABadPatternIsAnErrorNotAnEmptyList(t *testing.T) {
	_, ts := newServer(t)
	res, err := ts.Client().Get(ts.URL + "/flows?grep=%5B")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatalf("an invalid regex should be a 400, got %d — silently matching nothing "+
			"would read as 'no traffic'", res.StatusCode)
	}
}

func TestAnUnknownFlowIs404(t *testing.T) {
	_, ts := newServer(t)
	res, err := ts.Client().Get(ts.URL + "/flows/nope")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}

func TestReleasingAHeldExchangeOverTheAPI(t *testing.T) {
	s, ts := newServer(t)
	h := &capture.Held{FlowID: "1", Stage: capture.StageRequest, Host: "api.stripe.com"}
	ch := s.Proxy.Queue.Park(h)

	queued := get(t, ts, "/queue")["held"].([]any)
	if len(queued) != 1 {
		t.Fatalf("expected one held exchange, got %d", len(queued))
	}

	code, _ := post(t, ts, "/queue/"+h.ID, `{"action":"drop"}`)
	if code != 200 {
		t.Fatalf("releasing failed: %d", code)
	}
	select {
	case v := <-ch:
		if v.Action != capture.ActionDrop {
			t.Fatalf("wrong verdict: %q", v.Action)
		}
	case <-time.After(time.Second):
		t.Fatal("the verdict never reached the waiting request")
	}

	// Releasing it again must say so rather than appear to work.
	if code, _ := post(t, ts, "/queue/"+h.ID, `{"action":"drop"}`); code != 404 {
		t.Fatalf("a second release should be 404, got %d", code)
	}
}

func TestAnUnknownVerdictIsRejected(t *testing.T) {
	s, ts := newServer(t)
	h := &capture.Held{FlowID: "1"}
	s.Proxy.Queue.Park(h)
	if code, _ := post(t, ts, "/queue/"+h.ID, `{"action":"obliterate"}`); code != 400 {
		t.Fatalf("an unknown action should be 400, got %d", code)
	}
	if s.Proxy.Queue.Len() != 1 {
		t.Fatal("a rejected verdict must leave the exchange held")
	}
}

// The capture buffer holds credentials for every service the app under test calls, so the
// control plane binding loopback is a security property, not a convenience.
func TestNonLoopbackPeersAreRefused(t *testing.T) {
	s, _ := newServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/status", nil)
	req.RemoteAddr = "203.0.113.7:51000"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a non-loopback peer must be refused, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "proxy_port") {
		t.Fatal("the refusal leaked session detail")
	}
}

// The inspector and `ntcept follow` both live on this stream.
func TestEventsStreamIsLiveNotBuffered(t *testing.T) {
	s, ts := newServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/events", nil)
	res, err := ts.Client().Do(req.WithContext(t.Context()))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if ct := res.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("wrong content type %q", ct)
	}

	// Give the subscription a moment to register before producing the event it must carry.
	time.Sleep(50 * time.Millisecond)
	s.Store.Begin(capture.KindHTTP, "late.example", 443)

	br := bufio.NewReader(res.Body)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("the stream ended before delivering anything: %v", err)
		}
		if strings.HasPrefix(line, "event: flow.new") {
			return
		}
	}
	t.Fatal("a flow created after subscribing never appeared on the stream")
}

func TestClearEmptiesTheBuffer(t *testing.T) {
	s, ts := newServer(t)
	s.Store.Begin(capture.KindHTTP, "example.com", 443)
	if code, _ := post(t, ts, "/clear", ""); code != 200 {
		t.Fatalf("clear failed: %d", code)
	}
	if n, _, _ := s.Store.Stats(); n != 0 {
		t.Fatalf("the buffer still holds %d flows", n)
	}
}

func TestNormalisePort(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"127.0.0.1:8080", 8080},
		{":4300", 4300},
		{"8080", 8080},
		{"", 0},
		{"nonsense", 0},
	} {
		if got := normalisePort(tc.in); got != tc.want {
			t.Errorf("normalisePort(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
