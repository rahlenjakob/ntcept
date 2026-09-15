package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
)

// harness wires a proxy in front of a real upstream server, with a client that trusts the
// ntcept CA exactly as an attached application would.
type harness struct {
	srv   *Server
	store *capture.Store
	proxy string
	pool  *x509.CertPool
}

func newHarness(t testing.TB, upstreamCert *x509.Certificate) *harness {
	t.Helper()
	dir := t.TempDir()
	authority, err := ca.LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	store := capture.NewStore(16<<20, 1<<20)
	srv := New(store, authority)

	if upstreamCert != nil {
		up := x509.NewCertPool()
		up.AddCert(upstreamCert)
		srv.UpstreamTLS(&tls.Config{RootCAs: up, MinVersion: tls.VersionTLS12})
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.Serve(ln)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority.PEM) {
		t.Fatal("could not load the generated CA")
	}
	return &harness{srv: srv, store: store, proxy: "http://" + ln.Addr().String(), pool: pool}
}

func (h *harness) client() *http.Client {
	pu, _ := url.Parse(h.proxy)
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{RootCAs: h.pool, MinVersion: tls.VersionTLS12},
		},
	}
}

func (h *harness) waitFor(t *testing.T, n int) []*capture.Flow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		flows, _ := h.store.List(capture.Filter{})
		done := 0
		for _, f := range flows {
			if f.Done {
				done++
			}
		}
		if done >= n {
			return flows
		}
		time.Sleep(20 * time.Millisecond)
	}
	flows, _ := h.store.List(capture.Filter{})
	t.Fatalf("expected %d completed flows, got %d", n, len(flows))
	return nil
}

func TestTLSInterceptionCapturesBothDirections(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"order":"A-91"}` {
			t.Errorf("upstream saw body %q; the proxy altered it", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"ok"}`))
	}))
	defer upstream.Close()

	h := newHarness(t, upstream.Certificate())
	res, err := h.client().Post(upstream.URL+"/orders", "application/json",
		strings.NewReader(`{"order":"A-91"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if res.StatusCode != 201 || string(got) != `{"id":"ok"}` {
		t.Fatalf("the application must see the real response, got %d %q", res.StatusCode, got)
	}

	flows := h.waitFor(t, 1)
	f := flows[0]
	if f.Method != "POST" || f.Status != 201 {
		t.Fatalf("unexpected flow: %s", f.Line())
	}
	// The regression this guards: a streamed request body was written into the tee but never
	// read back, so every captured request appeared to have no body at all.
	if string(f.ReqBody) != `{"order":"A-91"}` {
		t.Fatalf("request body not captured, got %q", f.ReqBody)
	}
	if string(f.ResBody) != `{"id":"ok"}` {
		t.Fatalf("response body not captured, got %q", f.ResBody)
	}
	if !f.TLS || f.Via != capture.ViaCONNECT {
		t.Fatalf("expected an intercepted TLS CONNECT, got tls=%v via=%s", f.TLS, f.Via)
	}
}

func TestCredentialsAreMaskedButPassedThroughIntact(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
	}))
	defer upstream.Close()

	h := newHarness(t, upstream.Certificate())
	req, _ := http.NewRequest("GET", upstream.URL+"/", nil)
	req.Header.Set("Authorization", "Bearer real-secret-value")
	res, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if got := <-seen; got != "Bearer real-secret-value" {
		t.Fatalf("the upstream must receive the real credential, got %q", got)
	}
	f := h.waitFor(t, 1)[0]
	if v := f.ReqHdr.Get("Authorization"); strings.Contains(v, "real-secret-value") {
		t.Fatalf("the credential survived into the capture buffer: %q", v)
	}
	if len(f.Redaction.Secrets) == 0 {
		t.Fatal("the credential should have been reported as masked")
	}
}

func TestWebSocketFramesAreCaptured(t *testing.T) {
	upstream := httptest.NewServer(websocket.Handler(func(c *websocket.Conn) {
		var msg string
		for {
			if err := websocket.Message.Receive(c, &msg); err != nil {
				return
			}
			if err := websocket.Message.Send(c, "echo:"+msg); err != nil {
				return
			}
		}
	}))
	defer upstream.Close()

	h := newHarness(t, nil)
	wsURL := "ws://" + strings.TrimPrefix(upstream.URL, "http://") + "/chat"
	cfg, err := websocket.NewConfig(wsURL, "http://localhost")
	if err != nil {
		t.Fatal(err)
	}
	// Reach the upstream through the proxy the way an attached application would.
	raw, err := net.Dial("tcp", strings.TrimPrefix(h.proxy, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	host := strings.TrimPrefix(upstream.URL, "http://")
	if _, err := io.WriteString(raw, "CONNECT "+host+" HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 39)
	if _, err := io.ReadFull(raw, buf); err != nil {
		t.Fatal(err)
	}
	conn, err := websocket.NewClient(cfg, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := websocket.Message.Send(conn, "hello"); err != nil {
		t.Fatal(err)
	}
	var reply string
	if err := websocket.Message.Receive(conn, &reply); err != nil {
		t.Fatal(err)
	}
	if reply != "echo:hello" {
		t.Fatalf("the application must see the real reply, got %q", reply)
	}
	conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		flows, _ := h.store.List(capture.Filter{Kind: capture.KindWS})
		if len(flows) == 1 && len(flows[0].Messages) >= 2 {
			m := flows[0].Messages
			if string(m[0].Data) != "hello" || m[0].Dir != capture.Out {
				t.Fatalf("first frame should be the outbound hello, got %+v", m[0])
			}
			if string(m[1].Data) != "echo:hello" || m[1].Dir != capture.In {
				t.Fatalf("second frame should be the inbound echo, got %+v", m[1])
			}
			if m[0].Opcode != capture.OpText {
				t.Fatalf("expected a text frame, got %q", m[0].Opcode)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("websocket frames were never captured")
}

func TestUpstreamFailureIsReportedNotSwallowed(t *testing.T) {
	h := newHarness(t, nil)
	// Nothing is listening here; the application should learn why rather than get a bare reset.
	res, err := h.client().Get("http://127.0.0.1:1/gone")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 502 {
		t.Fatalf("expected 502, got %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("X-Ntcept-Error"), "connection refused") {
		t.Fatalf("the cause should be named, got %q", res.Header.Get("X-Ntcept-Error"))
	}
	f := h.waitFor(t, 1)[0]
	if f.Error == "" {
		t.Fatal("the flow should record the failure")
	}
}

func TestHeldRequestCanBeAnsweredLocally(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("a request answered from the queue must never reach the upstream")
	}))
	defer upstream.Close()

	h := newHarness(t, nil)
	h.srv.HoldRequests.Store(true)
	h.srv.HoldMS.Store(5000)

	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if held := h.srv.Queue.List(); len(held) > 0 {
				body := `{"stubbed":true}`
				h.srv.Queue.Release(held[0].ID, capture.Verdict{
					Action: capture.ActionRespond, Status: 503, Body: &body,
				})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	res, err := h.client().Get(upstream.URL + "/real")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if res.StatusCode != 503 || string(got) != `{"stubbed":true}` {
		t.Fatalf("expected the queued answer, got %d %q", res.StatusCode, got)
	}
}

func TestHeldExchangeMasksCredentialsButForwardsTheRealOne(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("Authorization")
	}))
	defer upstream.Close()

	h := newHarness(t, nil)
	h.srv.HoldRequests.Store(true)
	h.srv.HoldMS.Store(5000)

	queued := make(chan *capture.Held, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if held := h.srv.Queue.List(); len(held) > 0 {
				queued <- held[0]
				// Forward untouched: the operator changed nothing, so the original
				// credential must reach the upstream rather than its fingerprint.
				h.srv.Queue.Release(held[0].ID, capture.Verdict{Action: capture.ActionForward})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		close(queued)
	}()

	req, _ := http.NewRequest("GET", upstream.URL+"/held", nil)
	req.Header.Set("Authorization", "Bearer real-secret-value")
	res, err := h.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	held := <-queued
	if held == nil {
		t.Fatal("nothing was ever held")
	}
	// The queue is reachable over the control API, so it must mask exactly like the buffer.
	if got := held.Headers.Get("Authorization"); strings.Contains(got, "real-secret-value") {
		t.Fatalf("the hold queue exposed the credential in clear: %q", got)
	}
	if got := <-seen; got != "Bearer real-secret-value" {
		t.Fatalf("forwarding unchanged must send the original credential, upstream saw %q", got)
	}
}
