package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/proxy"
)

// TestOriginalDestinationSurvivesTheStack is the claim the whole attach rests on: the
// application dialled a particular address, and although the connection is terminated locally,
// what it asked for is still known. Lose this and every flow is attributed to nowhere.
func TestOriginalDestinationSurvivesTheStack(t *testing.T) {
	done := make(chan struct{})
	rec := &recorder{serve: func(c net.Conn, _ string, _ int) {
		c.Close()
		close(done)
	}}
	_, p, _ := engine(t, rec, "")

	c, err := p.Dial(deadlineCtx(t), "93.184.216.34", 443)
	if err != nil {
		t.Fatalf("the supervised process could not connect: %v", err)
	}
	defer c.Close()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the connection never surfaced above the stack")
	}
	if got := rec.targets(); len(got) != 1 || got[0] != "93.184.216.34:443" {
		t.Fatalf("destination lost in the stack: %v", got)
	}
}

// TestBytesCrossTheStackIntact sends more than fits in one segment, in both directions. A stack
// that reassembles wrongly corrupts every body ntcept would ever show, silently.
func TestBytesCrossTheStackIntact(t *testing.T) {
	const size = 2 << 20

	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(payload)

	echoed := make(chan [32]byte, 1)
	rec := &recorder{serve: func(c net.Conn, _ string, _ int) {
		defer c.Close()
		h := sha256.New()
		if _, err := io.Copy(io.MultiWriter(h, c), c); err != nil {
			return
		}
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		echoed <- sum
	}}
	_, p, _ := engine(t, rec, "")

	c, err := p.Dial(deadlineCtx(t), "10.1.2.3", 9000)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	back := make(chan [32]byte, 1)
	go func() {
		h := sha256.New()
		_, _ = io.Copy(h, c)
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		back <- sum
	}()

	if _, err := c.Write(payload); err != nil {
		t.Fatalf("writing through the stack: %v", err)
	}
	// Half-close, so the echo side sees EOF and stops rather than waiting forever.
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("half-close: %v", err)
		}
	} else {
		t.Fatal("the peer connection cannot half-close; the test cannot terminate the echo")
	}

	select {
	case got := <-echoed:
		if got != want {
			t.Fatal("what the app sent was not what arrived: the stack corrupted the stream")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the upstream half never completed")
	}
	select {
	case got := <-back:
		if got != want {
			t.Fatal("what came back differs from what was echoed")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the return half never completed")
	}
}

// TestTunnelledHTTPSIsInterceptedAndCaptured runs the whole chain the way `ntcept run` does on a
// real machine: packets out of the supervised process, through the userspace stack, into the
// proxy, terminated with ntcept's CA, re-originated to the upstream. Only the TUN is simulated.
func TestTunnelledHTTPSIsInterceptedAndCaptured(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != `{"q":1}` {
			t.Errorf("upstream saw a mangled body: %q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := capture.NewStore(16<<20, 1<<20)
	px := proxy.New(store, authority)
	up := x509.NewCertPool()
	up.AddCert(upstream.Certificate())
	// ntcept dials the test server by its loopback address while the app believes it is talking
	// to appSees, so upstream verification has to be told which name the certificate carries.
	px.UpstreamTLS(&tls.Config{RootCAs: up, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12})

	// The app believes it is talking to this address; ntcept re-originates to the test server.
	const appSees = "203.0.113.9"
	px.MapHost(appSees+":443", strings.TrimPrefix(upstream.URL, "https://"))

	l := newLink()
	st, err := New(Options{Device: l, Handler: px, Store: store})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := newPeer(t, l)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority.PEM) {
		t.Fatal("could not load the generated CA")
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port := splitAddr(t, addr)
				return p.Dial(ctx, host, port)
			},
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}

	res, err := client.Post("https://"+appSees+"/orders", "application/json",
		strings.NewReader(`{"q":1}`))
	if err != nil {
		t.Fatalf("the supervised process could not complete the request: %v", err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if res.StatusCode != 202 || string(got) != `{"ok":true}` {
		t.Fatalf("the app must see the real response, got %d %q", res.StatusCode, got)
	}

	f := waitForFlow(t, store, capture.KindHTTP, done)
	if f.Via != capture.ViaTun {
		t.Fatalf("a tunnelled flow must be recorded as such, got via=%s", f.Via)
	}
	if !f.TLS || f.Method != "POST" || f.Status != 202 {
		t.Fatalf("unexpected flow: %s", f.Line())
	}
	if string(f.ReqBody) != `{"q":1}` || string(f.ResBody) != `{"ok":true}` {
		t.Fatalf("bodies not captured: req=%q res=%q", f.ReqBody, f.ResBody)
	}
	if f.Host != appSees {
		t.Fatalf("the flow should name what the app dialled, got %q", f.Host)
	}
}

// TestDNSGoesToTheHostResolverAndIsRecorded covers the one piece of traffic the engine answers
// itself rather than relaying verbatim: inside a namespace there is no resolver, so port 53 is
// redirected to the host's. Every name the app looks up is visible as a side effect.
func TestDNSGoesToTheHostResolverAndIsRecorded(t *testing.T) {
	query := dnsQuery("api.stripe.com")

	resolver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	asked := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1500)
		n, from, err := resolver.ReadFrom(buf)
		if err != nil {
			return
		}
		asked <- append([]byte(nil), buf[:n]...)
		reply := append([]byte(nil), buf[:n]...)
		reply[2] |= 0x80 // flip QR to response
		_, _ = resolver.WriteTo(reply, from)
	}()

	_, p, store := engine(t, &recorder{}, resolver.LocalAddr().String())

	// 1.1.1.1 is what a container's resolv.conf might say; it is never actually reached.
	c, err := p.DialUDP("1.1.1.1", 53)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write(query); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-asked:
		if !bytes.Equal(got, query) {
			t.Fatal("the query reached the host resolver altered")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the query never reached the host resolver")
	}

	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("the app never got an answer back: %v", err)
	}
	if n != len(query) || buf[2]&0x80 == 0 {
		t.Fatal("the answer did not come back intact")
	}

	f := waitForFlow(t, store, capture.KindUDP, func(f *capture.Flow) bool { return len(f.Messages) >= 2 })
	if f.Path != "dns" || f.Port != 53 {
		t.Fatalf("a DNS flow should be labelled as one: %s", f.Line())
	}
	if len(f.Messages) < 2 {
		t.Fatalf("both halves of the exchange should be recorded, got %d", len(f.Messages))
	}
	if !strings.Contains(f.Messages[0].Decoded, "api.stripe.com") {
		t.Fatalf("the name looked up should be readable, got %q", f.Messages[0].Decoded)
	}
}

// TestOnlyPortFiftyThreeIsRedirected guards the other half of the same branch. Inside a network
// namespace there is no resolver, so DNS is sent to the host's — but that redirection must not
// leak onto anything else, or a metrics datagram would silently arrive at the user's nameserver.
//
// The destination here is TEST-NET-1 and goes nowhere on purpose: the engine drops a loopback
// destination as a martian packet, so a reachable sink is not available to a portable test.
// What matters is where the engine aimed the datagram, and that is recorded on the flow.
func TestOnlyPortFiftyThreeIsRedirected(t *testing.T) {
	resolver, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	leaked := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		if _, _, err := resolver.ReadFrom(buf); err == nil {
			close(leaked)
		}
	}()

	_, p, store := engine(t, &recorder{}, resolver.LocalAddr().String())

	c, err := p.DialUDP("192.0.2.10", 8125)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("statsd.metric:1|c")); err != nil {
		t.Fatal(err)
	}

	f := waitForFlow(t, store, capture.KindUDP, func(f *capture.Flow) bool { return len(f.Messages) >= 1 })
	if f.Host != "192.0.2.10" || f.Port != 8125 {
		t.Fatalf("the datagram was aimed somewhere other than where the app sent it: %s:%d", f.Host, f.Port)
	}
	if f.Path == "dns" {
		t.Fatal("a datagram to an arbitrary port must not be labelled DNS")
	}
	if string(f.Messages[0].Data) != "statsd.metric:1|c" || f.Messages[0].Dir != capture.Out {
		t.Fatalf("the payload was not recorded as sent: %+v", f.Messages[0])
	}

	select {
	case <-leaked:
		t.Fatal("a non-DNS datagram was redirected to the host resolver")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestConcurrentConnectionsAreKeptApart is the shape a real app produces: many sockets at once,
// each to a different place. A stack that muxes them wrongly shows one app's body under another
// app's request.
func TestConcurrentConnectionsAreKeptApart(t *testing.T) {
	rec := &recorder{serve: func(c net.Conn, host string, port int) {
		defer c.Close()
		// Answer with the destination, so a crossed wire is visible rather than subtle.
		_, _ = io.WriteString(c, net.JoinHostPort(host, itoa(port)))
	}}
	_, p, _ := engine(t, rec, "")

	const n = 24
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := net.JoinHostPort("10.0.0."+itoa(i+1), itoa(8000+i))
			c, err := p.Dial(deadlineCtx(t), "10.0.0."+itoa(i+1), 8000+i)
			if err != nil {
				errs <- "dial: " + err.Error()
				return
			}
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
			b, err := io.ReadAll(c)
			if err != nil {
				errs <- "read: " + err.Error()
				return
			}
			if string(b) != want {
				errs <- "connection crossed: wanted " + want + ", got " + string(b)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestEngineRefusesAnIncompleteConfiguration(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("an engine with no device, handler or store should not start")
	}
}

// waitForFlow polls for a captured flow satisfying want. A UDP conversation has no end until it
// goes idle, so "done" is the wrong thing to wait for there; the caller says what it needs.
func waitForFlow(t *testing.T, store *capture.Store, kind capture.Kind, want func(*capture.Flow) bool) *capture.Flow {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		flows, _ := store.List(capture.Filter{Kind: kind})
		for _, f := range flows {
			if want(f) {
				return f
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s flow matching the expectation was ever captured", kind)
	return nil
}

func done(f *capture.Flow) bool { return f.Done }

func splitAddr(t testing.TB, addr string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("bad address %q: %v", addr, err)
	}
	return h, atoi(t, p)
}

func atoi(t testing.TB, s string) int {
	t.Helper()
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("bad port %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// dnsQuery builds a minimal A query, so the recorded flow has something a decoder can read.
func dnsQuery(name string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, label := range strings.Split(name, ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.WriteByte(0)
	b.Write([]byte{0x00, 0x01, 0x00, 0x01})
	return b.Bytes()
}
