// Package proxy is the interception plane: one listener that accepts forward-proxy CONNECT,
// SOCKS5, transparent TLS by SNI, and plain HTTP, then decodes HTTP/1.1, HTTP/2, WebSocket, or
// relays raw TCP with protocol decoders attached.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
)

type Server struct {
	Store *capture.Store
	CA    *ca.Authority
	Queue *capture.Queue

	transport *http.Transport
	h2        *http2.Server

	HoldRequests  atomic.Bool
	HoldResponses atomic.Bool
	HoldMS        atomic.Int64
	Offline       atomic.Bool // refuse to forward; answer 502 locally

	upstreamTLS *tls.Config

	mapMu   sync.RWMutex
	hostMap map[string]string

	loopMu sync.RWMutex
	loop   LoopbackDialer
}

// LoopbackDialer reaches a port inside the supervised process's own network namespace.
//
// It exists because "localhost" is ambiguous the moment a process is put in a namespace. On
// macOS there is no ambiguity: the command shares the machine's network, so 127.0.0.1 is the
// machine and a service the command itself started is on it too. On Linux the namespace has its
// own loopback, and without help the two meanings come apart — which is the last big difference
// between the platforms.
//
// Resolving it the same way macOS does means trying the command's own loopback first and the
// machine's second: a service the command started shadows one of the same port on the host,
// exactly as it would if they shared a network. Set by the Linux attach; nil everywhere else.
type LoopbackDialer func(ctx context.Context, port int) (net.Conn, error)

// SetLoopbackDialer installs the route into the supervised process's namespace.
func (s *Server) SetLoopbackDialer(d LoopbackDialer) {
	s.loopMu.Lock()
	defer s.loopMu.Unlock()
	s.loop = d
}

func (s *Server) loopbackDialer() LoopbackDialer {
	s.loopMu.RLock()
	defer s.loopMu.RUnlock()
	return s.loop
}

// dialUpstream is the one place ntcept opens a connection on an application's behalf. Routing
// every path through it means host mapping and loopback resolution apply to raw TCP and
// WebSocket upgrades as well as to HTTP, rather than only where someone remembered.
func (s *Server) dialUpstream(ctx context.Context, addr string) (net.Conn, error) {
	mapped := s.mapped(addr)
	host, port := splitHostPort(mapped, 0)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() && mapped == addr {
		if dial := s.loopbackDialer(); dial != nil {
			if c, err := dial(ctx, port); err == nil {
				return c, nil
			}
			// Nothing of that name inside the namespace: fall through to this machine, which
			// is where a database or another service the user started themselves lives.
		}
	}
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return d.DialContext(ctx, "tcp", mapped)
}

// MapHost routes one upstream authority to a different address, without the client knowing.
// Used by `ntcept doctor` to stand up an origin that is not loopback as far as the runtime under
// test is concerned, since every HTTP client bypasses proxies for localhost.
func (s *Server) MapHost(authority, addr string) {
	s.mapMu.Lock()
	defer s.mapMu.Unlock()
	if s.hostMap == nil {
		s.hostMap = map[string]string{}
	}
	s.hostMap[authority] = addr
}

func (s *Server) mapped(addr string) string {
	s.mapMu.RLock()
	defer s.mapMu.RUnlock()
	if to, ok := s.hostMap[addr]; ok {
		return to
	}
	return addr
}

func New(store *capture.Store, authority *ca.Authority) *Server {
	s := &Server{
		Store: store, CA: authority, Queue: capture.NewQueue(),
		transport: &http.Transport{
			Proxy:                 nil,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          200,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ExpectContinueTimeout: time.Second,
			// ntcept is a debugger: it must observe what the app actually does, including
			// talking to a host whose certificate is bad, rather than hide it behind a failure
			// the app would never have seen. The finding is recorded on the flow instead.
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
		h2: &http2.Server{},
	}
	s.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return s.dialUpstream(ctx, addr)
	}
	s.HoldMS.Store(30_000)
	return s
}

// UpstreamTLS overrides how ntcept verifies the servers it forwards to. Tests point it at a
// local certificate authority; nothing else should change it.
func (s *Server) UpstreamTLS(cfg *tls.Config) {
	s.transport.TLSClientConfig = cfg
	s.upstreamTLS = cfg
}

// target is what one accepted connection turned out to be aimed at.
type target struct {
	host string
	port int
	tls  bool
	via  capture.Via
}

func (t target) scheme() string {
	if t.tls {
		return "https"
	}
	return "http"
}

func (t target) addr() string {
	if t.port == 0 {
		if t.tls {
			t.port = 443
		} else {
			t.port = 80
		}
	}
	return net.JoinHostPort(t.host, strconv.Itoa(t.port))
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleConn(c)
	}
}

func (s *Server) handleConn(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(120 * time.Second))
	br := bufio.NewReader(c)
	head, err := br.Peek(1)
	if err != nil || len(head) == 0 {
		return
	}
	_ = c.SetReadDeadline(time.Time{})

	switch {
	case head[0] == 0x16:
		// Raw TLS arriving directly: DNS or a redirect pointed the app here, so SNI is the target.
		s.mitm(c, br, target{tls: true, via: capture.ViaSNI})
	case isCONNECT(br):
		s.serveCONNECT(c, br)
	default:
		s.serveHTTP1(c, br, target{via: capture.ViaPlain})
	}
}

// HandleTransparent takes a connection whose original destination is already known — every
// connection arriving from a child's network namespace — and runs it through the same dispatch
// as a proxied one.
func (s *Server) HandleTransparent(c net.Conn, host string, port int) {
	defer c.Close()
	s.dispatchTunnel(c, bufio.NewReader(c), target{host: host, port: port, via: capture.ViaTun})
}

func isCONNECT(br *bufio.Reader) bool {
	b, err := br.Peek(8)
	return err == nil && string(b) == "CONNECT "
}

func (s *Server) serveCONNECT(c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	host, port := splitHostPort(req.Host, 443)
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	s.dispatchTunnel(c, br, target{host: host, port: port, via: capture.ViaCONNECT})
}

// dispatchTunnel decides what is actually inside an established tunnel: TLS, plain HTTP, or
// something else entirely that we relay and decode as bytes.
func (s *Server) dispatchTunnel(c net.Conn, br *bufio.Reader, t target) {
	head, err := br.Peek(1)
	if err != nil {
		return
	}
	switch {
	case head[0] == 0x16:
		t.tls = true
		s.mitm(c, br, t)
	case looksHTTP(br):
		s.serveHTTP1(c, br, t)
	default:
		s.relayTCP(c, br, t)
	}
}

var httpMethods = []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC", "TRAC", "CONN", "PRI "}

func looksHTTP(br *bufio.Reader) bool {
	b, err := br.Peek(4)
	if err != nil {
		return false
	}
	for _, m := range httpMethods {
		if string(b) == m {
			return true
		}
	}
	return false
}

func splitHostPort(s string, def int) (string, int) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, _ := strconv.Atoi(p)
		return h, n
	}
	return s, def
}

// peeked lets the TLS stack and http.Server read bytes we already buffered.
type peeked struct {
	net.Conn
	r io.Reader
}

func (p *peeked) Read(b []byte) (int, error) { return p.r.Read(b) }

func (s *Server) mitm(c net.Conn, br *bufio.Reader, t target) {
	conn := &peeked{Conn: c, r: br}
	cfg := s.CA.ServerConfig(t.host, []string{"h2", "http/1.1"})
	tc := tls.Server(conn, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		return
	}
	if name := tc.ConnectionState().ServerName; name != "" {
		t.host = name
	}
	if t.port == 0 {
		t.port = 443
	}
	t.tls = true

	if tc.ConnectionState().NegotiatedProtocol == "h2" {
		s.h2.ServeConn(tc, &http2.ServeConnOpts{Handler: s.handler(t, capture.ProtoH2)})
		return
	}
	s.serveHTTP1(tc, bufio.NewReader(tc), t)
}

func (s *Server) serveHTTP1(c net.Conn, br *bufio.Reader, t target) {
	srv := &http.Server{
		Handler:           s.handler(t, capture.ProtoHTTP11),
		ReadHeaderTimeout: 30 * time.Second,
	}
	// h2c (prior-knowledge HTTP/2 over cleartext) announces itself with the PRI preface.
	if b, err := br.Peek(3); err == nil && string(b) == "PRI" {
		s.h2.ServeConn(&peeked{Conn: c, r: br}, &http2.ServeConnOpts{Handler: s.handler(t, capture.ProtoH2C)})
		return
	}
	_ = srv.Serve(&oneConn{c: &peeked{Conn: c, r: br}})
}

// oneConn hands http.Server exactly one already-accepted connection.
type oneConn struct {
	c    net.Conn
	done bool
}

func (l *oneConn) Accept() (net.Conn, error) {
	if l.done {
		// Block until the connection closes rather than returning an error, which would make
		// http.Server tear the whole thing down mid-request.
		<-make(chan struct{})
	}
	l.done = true
	return l.c, nil
}

func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return l.c.LocalAddr() }

func hostOnly(h string) string {
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}

func fmtErr(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
