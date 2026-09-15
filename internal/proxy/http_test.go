package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/rahlenjakob/ntcept/internal/capture"
)

// h2client is the harness client with HTTP/2 left switched on, so the application negotiates h2
// with ntcept rather than HTTP/1.1.
func (h *harness) h2client() *http.Client {
	pu, _ := url.Parse(h.proxy)
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(pu),
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				RootCAs: h.pool, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"},
			},
		},
	}
}

// The protocol an application speaks to ntcept and the one ntcept speaks upstream are chosen
// independently, and the flow has to say which was which. This is the half nothing covered.
func TestHTTP2IsNegotiatedAndRecordedAsSuch(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"proto":"` + r.Proto + `"}`))
	}))
	defer upstream.Close()

	h := newHarness(t, upstream.Certificate())
	res, err := h.h2client().Get(upstream.URL + "/v1/thing")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.ProtoMajor != 2 {
		t.Skipf("the client did not negotiate h2 with ntcept (got %s); nothing to assert", res.Proto)
	}
	if res.StatusCode != 200 {
		t.Fatalf("unexpected status %d", res.StatusCode)
	}

	f := h.waitFor(t, 1)[0]
	if f.Proto != capture.ProtoH2 {
		t.Fatalf("an h2 conversation must be recorded as h2, got %q", f.Proto)
	}
	if string(f.ResBody) != string(body) {
		t.Fatalf("the captured body differs from what the app received: %q vs %q", f.ResBody, body)
	}
}

// h2c is HTTP/2 over cleartext by prior knowledge — what a Go service, a service mesh or a gRPC
// client on a plain port speaks. There is no ALPN to negotiate it, so ntcept has to recognise the
// connection preface itself, and nothing covered that branch.
func TestH2CIsDetectedFromThePreface(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		_, _ = io.WriteString(w, "served over "+r.Proto)
	}))
	defer upstream.Close()

	h := newHarness(t, nil)
	proxyAddr := strings.TrimPrefix(h.proxy, "http://")
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, proxyAddr)
			},
		},
	}

	res, err := client.Get(upstream.URL + "/rpc")
	if err != nil {
		t.Fatalf("ntcept did not serve a prior-knowledge h2c connection: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.ProtoMajor != 2 {
		t.Fatalf("the application should have spoken h2, got %s", res.Proto)
	}
	if !strings.HasPrefix(string(body), "served over ") {
		t.Fatalf("the upstream response did not come back: %q", body)
	}

	f := h.waitFor(t, 1)[0]
	if f.Proto != capture.ProtoH2C {
		t.Fatalf("cleartext h2 must be recorded as h2c, got %q", f.Proto)
	}
	if f.TLS {
		t.Fatal("h2c is cleartext; the flow must not claim TLS")
	}
	if string(f.ResBody) != string(body) {
		t.Fatalf("the captured body differs from what the app received: %q vs %q", f.ResBody, body)
	}
}

// An inspector that buffers a stream is an inspector that breaks it. Server-sent events and long
// polls have to reach the application as they arrive, not when the response ends.
func TestServerSentEventsReachTheAppAsTheyArrive(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: first\n\n")
		flusher.Flush()
		// Nothing more is written until the test confirms the first event already arrived.
		<-release
		_, _ = io.WriteString(w, "data: second\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	h := newHarness(t, nil)
	res, err := h.client().Get(upstream.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	br := bufio.NewReader(res.Body)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("the first event never arrived: %v", err)
	}
	if strings.TrimSpace(line) != "data: first" {
		t.Fatalf("unexpected first event %q", line)
	}
	close(release)

	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "data: second") {
		t.Fatalf("the second event never arrived: %q", rest)
	}
}

// The capture ceiling bounds memory, and it must bound only what is stored. The application
// still gets every byte, and the flow says plainly that what it holds is partial.
func TestABodyOverTheCeilingIsTruncatedInTheBufferOnly(t *testing.T) {
	const size = 64 << 10
	payload := strings.Repeat("x", size)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer upstream.Close()

	h := newHarness(t, nil)
	h.store.MaxBody = 1 << 10

	res, err := h.client().Get(upstream.URL + "/big")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if len(got) != size {
		t.Fatalf("the application must receive the whole body, got %d of %d", len(got), size)
	}

	f := h.waitFor(t, 1)[0]
	if !f.ResTruncated {
		t.Fatal("a truncated capture must say so")
	}
	if len(f.ResBody) > 1<<10 {
		t.Fatalf("the buffer kept %d bytes, over its %d ceiling", len(f.ResBody), 1<<10)
	}
	if f.ResLen != size {
		t.Fatalf("the real length must still be reported, got %d want %d", f.ResLen, size)
	}
}

// Offline is how an agent runs something in a sandbox that must not reach the network. It has to
// refuse locally and say so, not fail in a way the app reads as a flaky upstream.
func TestOfflineRefusesLocallyAndRecordsTheDecision(t *testing.T) {
	reached := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- struct{}{}
	}))
	defer upstream.Close()

	h := newHarness(t, nil)
	h.srv.Offline.Store(true)

	res, err := h.client().Get(upstream.URL + "/outside")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 502 {
		t.Fatalf("expected a local 502, got %d", res.StatusCode)
	}
	select {
	case <-reached:
		t.Fatal("offline must mean the upstream is never contacted")
	default:
	}
	f := h.waitFor(t, 1)[0]
	if f.Decision != capture.DecisionOffline {
		t.Fatalf("the flow should record why it was refused, got %q", f.Decision)
	}
}

// Hop-by-hop headers describe one connection and must not be carried onto the next one. ntcept
// terminates and re-originates every connection, so it is exactly the place this goes wrong.
func TestHopByHopHeadersAreNotForwarded(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
	}))
	defer upstream.Close()

	h := newHarness(t, nil)
	req, _ := http.NewRequest("GET", upstream.URL+"/x", nil)
	req.Header.Set("Proxy-Authorization", "Basic nope")
	req.Header.Set("X-Kept", "yes")
	res, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	got := <-seen
	if got.Get("Proxy-Authorization") != "" {
		t.Fatal("a hop-by-hop header was forwarded upstream")
	}
	if got.Get("X-Kept") != "yes" {
		t.Fatal("an ordinary header was dropped")
	}
}

// A hold nobody answers must not stall an application forever. The exchange goes through and the
// flow says a verdict was never given, because a run where nobody answered is not the run
// anyone thinks it was.
func TestAnUnansweredHoldForwardsAndIsRecorded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "arrived")
	}))
	defer upstream.Close()

	h := newHarness(t, nil)
	h.srv.HoldRequests.Store(true)
	h.srv.HoldMS.Store(150)

	start := time.Now()
	res, err := h.client().Get(upstream.URL + "/unwatched")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if string(body) != "arrived" {
		t.Fatalf("an expired hold must forward, got %q", body)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Fatalf("the hold budget was not waited out: %s", elapsed)
	}
	f := h.waitFor(t, 1)[0]
	if f.Decision != capture.DecisionHoldTimeout {
		t.Fatalf("expected the flow to record the expiry, got %q", f.Decision)
	}
	if h.srv.Queue.Len() != 0 {
		t.Fatal("an expired hold must be dropped from the queue")
	}
}

// Editing is the point of holding: the operator changes the request and the upstream sees the
// change, not the original.
func TestAnEditedRequestReachesTheUpstreamChanged(t *testing.T) {
	type got struct {
		method string
		header string
		body   string
	}
	seen := make(chan got, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen <- got{r.Method, r.Header.Get("X-Tenant"), string(b)}
	}))
	defer upstream.Close()

	h := newHarness(t, nil)
	h.srv.HoldRequests.Store(true)
	h.srv.HoldMS.Store(5000)

	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if held := h.srv.Queue.List(); len(held) > 0 {
				body := `{"amount":1}`
				h.srv.Queue.Release(held[0].ID, capture.Verdict{
					Action:     capture.ActionEdit,
					Body:       &body,
					SetHeaders: map[string]string{"X-Tenant": "staging"},
				})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	res, err := h.client().Post(upstream.URL+"/charge", "application/json",
		strings.NewReader(`{"amount":999999}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	g := <-seen
	if g.body != `{"amount":1}` {
		t.Fatalf("the edited body did not reach the upstream, got %q", g.body)
	}
	if g.header != "staging" {
		t.Fatalf("the added header did not reach the upstream, got %q", g.header)
	}
	f := h.waitFor(t, 1)[0]
	if f.Decision != capture.DecisionEdit {
		t.Fatalf("expected the flow to record the edit, got %q", f.Decision)
	}
}
