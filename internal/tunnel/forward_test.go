package tunnel

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"

	"github.com/rahlenjakob/ntcept/internal/capture"
)

// listen makes the peer — the supervised process — accept on a port, the way a dev server does.
func (p *peer) listen(t testing.TB, port int) net.Listener {
	t.Helper()
	ln, err := gonet.ListenTCP(p.s, tcpip.FullAddress{
		NIC:  nicID,
		Addr: tcpip.AddrFromSlice(net.ParseIP(PeerIP).To4()),
		Port: uint16(port),
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("the supervised process could not bind %d: %v", port, err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

// engineStack is engine(), but keeping the Stack so the forwarding side can be exercised.
func engineStack(t testing.TB, h Handler) (*Stack, *peer) {
	t.Helper()
	l := newLink()
	store := capture.NewStore(16<<20, 1<<20)
	st, err := New(Options{Device: l, Handler: h, Store: store})
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	t.Cleanup(st.Close)
	return st, newPeer(t, l)
}

// TestDialChildReachesAServerInsideTheNamespace is the half of the link that has never existed.
// Everything else in ntcept dials outward; this is the engine dialling in.
func TestDialChildReachesAServerInsideTheNamespace(t *testing.T) {
	st, p := engineStack(t, &recorder{})
	ln := p.listen(t, 3000)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b, _ := io.ReadAll(c)
		_, _ = fmt.Fprintf(c, "the app saw %q", b)
	}()

	c, err := st.DialChild(deadlineCtx(t), "", 3000)
	if err != nil {
		t.Fatalf("could not reach a server inside the namespace: %v", err)
	}
	defer c.Close()
	if _, err := io.WriteString(c, "hello from the host"); err != nil {
		t.Fatal(err)
	}
	halfClose(c)

	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `the app saw "hello from the host"` {
		t.Fatalf("unexpected reply through the link: %q", got)
	}
}

// TestPublishMakesADevServerOpenableFromTheHost is the user-visible claim: `ntcept run -- npm
// run dev` on Linux must give you something you can open in a browser. Until this existed it
// gave you a captured app that nothing could reach.
func TestPublishMakesADevServerOpenableFromTheHost(t *testing.T) {
	st, p := engineStack(t, &recorder{})
	ln := p.listen(t, 3000)

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<h1>dev server</h1><p>%s</p>", r.URL.Path)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	pub, err := st.Publish(PortMap{HostAddr: "127.0.0.1:0", ChildPort: 3000})
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()

	// Exactly what a browser on this machine does.
	client := &http.Client{Timeout: 15 * time.Second}
	res, err := client.Get("http://" + pub.HostAddr + "/orders")
	if err != nil {
		t.Fatalf("a published dev server was not reachable from the host: %v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || !strings.Contains(string(body), "/orders") {
		t.Fatalf("unexpected response %d %q", res.StatusCode, body)
	}
}

// A browser opens several connections to a page at once, and keeps them alive.
func TestPublishHandlesConcurrentConnections(t *testing.T) {
	st, p := engineStack(t, &recorder{})
	ln := p.listen(t, 3000)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	pub, err := st.Publish(PortMap{HostAddr: "127.0.0.1:0", ChildPort: 3000})
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()

	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := fmt.Sprintf("/asset-%d", i)
			res, err := (&http.Client{Timeout: 20 * time.Second}).
				Get("http://" + pub.HostAddr + want)
			if err != nil {
				errs <- err.Error()
				return
			}
			defer res.Body.Close()
			b, _ := io.ReadAll(res.Body)
			if string(b) != want {
				errs <- fmt.Sprintf("connection crossed: wanted %s, got %s", want, b)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

// The publication is opened before the command runs, so the host port is held from the outset.
// Until the child binds, a connection has to fail cleanly rather than hang or panic.
func TestPublishingAPortNothingIsListeningOnFailsCleanly(t *testing.T) {
	st, _ := engineStack(t, &recorder{})
	pub, err := st.Publish(PortMap{HostAddr: "127.0.0.1:0", ChildPort: 3999})
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()

	c, err := net.DialTimeout("tcp", pub.HostAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("the host side should accept even before the child binds: %v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(25 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("the connection should be closed, not left hanging: %v", err)
	}
}

func TestClosingAPublicationReleasesTheHostPort(t *testing.T) {
	st, _ := engineStack(t, &recorder{})
	pub, err := st.Publish(PortMap{HostAddr: "127.0.0.1:0", ChildPort: 3000})
	if err != nil {
		t.Fatal(err)
	}
	addr := pub.HostAddr
	if err := pub.Close(); err != nil {
		t.Fatal(err)
	}
	// Closing twice is what a deferred Close plus an explicit one produces.
	if err := pub.Close(); err != nil {
		t.Fatalf("closing twice should be harmless: %v", err)
	}
	if c, err := net.DialTimeout("tcp", addr, 2*time.Second); err == nil {
		c.Close()
		t.Fatal("the host port is still accepting after Close")
	}
}

func TestParsePublish(t *testing.T) {
	for _, tc := range []struct {
		in    string
		host  string
		child int
		bad   bool
	}{
		{in: "3000", host: "127.0.0.1:3000", child: 3000},
		{in: "8080:3000", host: "127.0.0.1:8080", child: 3000},
		{in: "0:3000", host: "127.0.0.1:0", child: 3000},
		{in: " 3000 ", host: "127.0.0.1:3000", child: 3000},
		{in: "", bad: true},
		{in: "http", bad: true},
		{in: "3000:0", bad: true},
		{in: "70000", bad: true},
		{in: "-1", bad: true},
	} {
		got, err := ParsePublish(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("ParsePublish(%q) should have failed, got %+v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePublish(%q): %v", tc.in, err)
			continue
		}
		if got.HostAddr != tc.host || got.ChildPort != tc.child {
			t.Errorf("ParsePublish(%q) = %s → %d, want %s → %d",
				tc.in, got.HostAddr, got.ChildPort, tc.host, tc.child)
		}
	}
}
