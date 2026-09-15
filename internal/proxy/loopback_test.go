package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// "localhost" means two different things once a process is put in a namespace: the machine, or
// the namespace's own loopback. macOS has no such split, and these fix the rule that makes Linux
// behave the same — the command's own loopback first, the machine second.

// namespaceOn stands in for a service inside the supervised process's namespace.
func namespaceOn(t *testing.T, body string) (LoopbackDialer, *int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	var calls int32
	inside := ln.Addr().String()
	return func(ctx context.Context, port int) (net.Conn, error) {
		atomic.AddInt32(&calls, 1)
		return (&net.Dialer{}).DialContext(ctx, "tcp", inside)
	}, &calls
}

// A service the command started itself shadows one of the same port on the machine — which is
// what would happen on macOS, where they are the same network.
func TestAServiceInsideTheNamespaceWinsOverOneOnTheMachine(t *testing.T) {
	onTheMachine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "the machine")
	}))
	defer onTheMachine.Close()

	h := newHarness(t, nil)
	dial, calls := namespaceOn(t, "the namespace")
	h.srv.SetLoopbackDialer(dial)

	res, err := h.client().Get(onTheMachine.URL + "/where")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if string(got) != "the namespace" {
		t.Fatalf("a loopback call should reach the command's own service first, got %q", got)
	}
	if atomic.LoadInt32(calls) != 1 {
		t.Fatalf("the namespace dialler was consulted %d times", atomic.LoadInt32(calls))
	}
}

// A local Postgres the user started themselves is not in the namespace, and reaching it is the
// whole point of the fallback.
func TestAServiceOnlyOnTheMachineIsStillReached(t *testing.T) {
	onTheMachine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "the machine")
	}))
	defer onTheMachine.Close()

	h := newHarness(t, nil)
	var asked int32
	h.srv.SetLoopbackDialer(func(ctx context.Context, port int) (net.Conn, error) {
		atomic.AddInt32(&asked, 1)
		// Nothing of that name inside the namespace.
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	})

	res, err := h.client().Get(onTheMachine.URL + "/where")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if string(got) != "the machine" {
		t.Fatalf("a loopback call must fall back to this machine, got %q", got)
	}
	if atomic.LoadInt32(&asked) == 0 {
		t.Fatal("the namespace should have been tried first")
	}
}

// Without a namespace — macOS — nothing changes.
func TestWithoutANamespaceLoopbackIsJustLoopback(t *testing.T) {
	onTheMachine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "the machine")
	}))
	defer onTheMachine.Close()

	h := newHarness(t, nil)
	res, err := h.client().Get(onTheMachine.URL + "/where")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	got, _ := io.ReadAll(res.Body)
	if string(got) != "the machine" {
		t.Fatalf("got %q", got)
	}
}

// A non-loopback destination must never be sent into the namespace, however tempting the port.
func TestOnlyLoopbackDestinationsConsultTheNamespace(t *testing.T) {
	onTheMachine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "the machine")
	}))
	defer onTheMachine.Close()

	h := newHarness(t, nil)
	var asked int32
	h.srv.SetLoopbackDialer(func(ctx context.Context, port int) (net.Conn, error) {
		atomic.AddInt32(&asked, 1)
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	})
	// Rewrite the request to an external-looking authority pointing at the same server.
	h.srv.MapHost("api.example.com:80", strings.TrimPrefix(onTheMachine.URL, "http://"))

	res, err := h.client().Get("http://api.example.com/where")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if atomic.LoadInt32(&asked) != 0 {
		t.Fatal("a call to a public name was offered to the namespace")
	}
}

// Raw TCP goes through the same door now, so a Postgres or Redis on localhost resolves the same
// way an HTTP call does. Before centralising the dialler this path ignored both rules.
func TestRawTCPUsesTheSameLoopbackRule(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.WriteString(c, "+PONG\r\n") }()
		}
	}()

	h := newHarness(t, nil)
	reached := make(chan struct{}, 1)
	h.srv.SetLoopbackDialer(func(ctx context.Context, port int) (net.Conn, error) {
		select {
		case reached <- struct{}{}:
		default:
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", ln.Addr().String())
	})

	// A CONNECT to a loopback address carrying something that is not HTTP.
	raw, err := net.Dial("tcp", strings.TrimPrefix(h.proxy, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := io.WriteString(raw, "CONNECT 127.0.0.1:6379 HTTP/1.1\r\nHost: 127.0.0.1:6379\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 39)
	if _, err := io.ReadFull(raw, buf); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(raw, "PING\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	reply := make([]byte, 7)
	if _, err := io.ReadFull(raw, reply); err != nil {
		t.Fatalf("no reply through the raw relay: %v", err)
	}
	if string(reply) != "+PONG\r\n" {
		t.Fatalf("unexpected reply %q", reply)
	}
	select {
	case <-reached:
	default:
		t.Fatal("raw TCP to a loopback address bypassed the namespace rule")
	}
}

type errRefused struct{}

func (errRefused) Error() string   { return "connection refused" }
func (errRefused) Timeout() bool   { return false }
func (errRefused) Temporary() bool { return false }

// A protocol whose client opens with a short message and then waits must not be delayed. This
// is the regression for a sniffing read that asked for 64 bytes and held the connection for the
// full read deadline when fewer arrived — ten seconds added to every Redis connection.
func TestAShortOpeningMessageIsForwardedImmediately(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 6)
				if _, err := io.ReadFull(c, b); err != nil {
					return
				}
				_, _ = io.WriteString(c, "+PONG\r\n")
			}()
		}
	}()

	h := newHarness(t, nil)
	raw, err := net.Dial("tcp", strings.TrimPrefix(h.proxy, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	target := ln.Addr().String()
	if _, err := io.WriteString(raw, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(raw, make([]byte, 39)); err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	if _, err := io.WriteString(raw, "PING\r\n"); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(raw, make([]byte, 7)); err != nil {
		t.Fatalf("no reply: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("a six-byte opening message took %s to be forwarded; ntcept is waiting for "+
			"bytes the client will not send until it has been answered", elapsed)
	}
}
