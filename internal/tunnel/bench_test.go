package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/proxy"
)

// Under the tunnel attach a userspace TCP/IP stack sits between the application and everything
// it talks to, so every byte it sends or receives is reassembled in Go rather than by the
// kernel. That is the single largest thing ntcept adds to an application's network path and it
// has never been measured. These say what it costs.
//
//	go test ./internal/tunnel -run '^$' -bench . -benchmem
//
// The link here is an in-memory packet pipe rather than a TUN, so these numbers exclude the
// per-packet read and write syscalls a real device adds. They are an upper bound on the stack
// itself, not a prediction of what `ntcept run` delivers.

var stackSizes = []struct {
	name string
	n    int
}{
	{"64KB", 64 << 10},
	{"1MB", 1 << 20},
	{"16MB", 16 << 20},
}

// BenchmarkStackDownload is the case the TODO calls out: a large download through the stack.
// The handler writes as fast as it can and the application reads; nothing else is in the path.
func BenchmarkStackDownload(b *testing.B) {
	for _, sz := range stackSizes {
		payload := make([]byte, sz.n)
		b.Run(sz.name, func(b *testing.B) {
			// One engine per sub-benchmark: they are torn down when it ends, rather than
			// every size's stack staying alive and pumping alongside the one being measured.
			rec := &recorder{serve: func(c net.Conn, _ string, _ int) {
				defer c.Close()
				_, _ = c.Write(payload)
			}}
			_, p, _ := engine(b, rec, "")

			b.SetBytes(int64(sz.n))
			b.ResetTimer()
			for b.Loop() {
				c, err := p.Dial(deadlineCtx(b), "198.51.100.5", 443)
				if err != nil {
					b.Fatal(err)
				}
				n, err := io.Copy(io.Discard, c)
				c.Close()
				if err != nil || n != int64(sz.n) {
					b.Fatalf("short read: %d of %d (%v)", n, sz.n, err)
				}
			}
		})
	}
}

// BenchmarkStackUpload is the other direction. It is not symmetric: sending is where congestion
// control and the send window live, and an app posting a large file takes this path.
func BenchmarkStackUpload(b *testing.B) {
	for _, sz := range stackSizes {
		payload := make([]byte, sz.n)
		b.Run(sz.name, func(b *testing.B) {
			// The far end acknowledges once it has drained the whole upload. Without that,
			// closing as soon as the last Write returns measures how quickly the send buffer
			// accepts bytes rather than how quickly the stack moves them, and the result
			// swings by an order of magnitude between runs.
			rec := &recorder{serve: func(c net.Conn, _ string, _ int) {
				defer c.Close()
				if _, err := io.Copy(io.Discard, c); err != nil {
					return
				}
				_, _ = c.Write([]byte{1})
			}}
			_, p, _ := engine(b, rec, "")

			b.SetBytes(int64(sz.n))
			b.ResetTimer()
			for b.Loop() {
				c, err := p.Dial(deadlineCtx(b), "198.51.100.5", 443)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := c.Write(payload); err != nil {
					b.Fatal(err)
				}
				if cw, ok := c.(interface{ CloseWrite() error }); ok {
					if err := cw.CloseWrite(); err != nil {
						b.Fatal(err)
					}
				}
				var ack [1]byte
				if _, err := io.ReadFull(c, ack[:]); err != nil {
					b.Fatalf("the upload was not acknowledged: %v", err)
				}
				c.Close()
			}
		})
	}
}

// BenchmarkStackConnectionSetup prices the handshake rather than the transfer. An application
// that opens a connection per request — which is most of them, before keep-alive warms up —
// pays this on every one.
func BenchmarkStackConnectionSetup(b *testing.B) {
	rec := &recorder{serve: func(c net.Conn, _ string, _ int) { c.Close() }}
	_, p, _ := engine(b, rec, "")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		c, err := p.Dial(deadlineCtx(b), "198.51.100.5", 443)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, c)
		c.Close()
	}
}

// BenchmarkTunnelledHTTPS is the whole attach: packets out of the application, through the
// stack, into the proxy, TLS terminated and re-originated, captured, and back. The "direct" arm
// is the same proxy reached over loopback rather than through the stack, so the difference
// between the two is what the userspace stack costs and nothing else.
func BenchmarkTunnelledHTTPS(b *testing.B) {
	for _, sz := range []struct {
		name string
		n    int
	}{
		{"4KB", 4 << 10},
		{"1MB", 1 << 20},
	} {
		payload := make([]byte, sz.n)
		origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
			_, _ = w.Write(payload)
		}))
		defer origin.Close()

		authority, err := ca.LoadOrCreate(b.TempDir())
		if err != nil {
			b.Fatal(err)
		}
		store := capture.NewStore(256<<20, 1<<20)
		px := proxy.New(store, authority)
		upPool := x509.NewCertPool()
		upPool.AddCert(origin.Certificate())
		px.UpstreamTLS(&tls.Config{
			RootCAs: upPool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
		})
		const appSees = "203.0.113.9"
		px.MapHost(appSees+":443", strings.TrimPrefix(origin.URL, "https://"))

		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(authority.PEM)
		tlsCfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}

		l := newLink()
		st, err := New(Options{Device: l, Handler: px, Store: store})
		if err != nil {
			b.Fatal(err)
		}
		p := newPeer(b, l)
		b.Cleanup(st.Close)

		// The same proxy, reached directly by a CONNECT through the proxy port, with no userspace
		// stack anywhere in the path — the baseline the tunnel path is measured against.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { ln.Close() })
		go px.Serve(ln)
		proxyURL, err := url.Parse("http://" + ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}

		run := func(b *testing.B, c *http.Client) {
			b.SetBytes(int64(sz.n))
			b.ResetTimer()
			for b.Loop() {
				res, err := c.Get("https://" + appSees + "/blob")
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, res.Body); err != nil {
					b.Fatal(err)
				}
				res.Body.Close()
			}
		}

		b.Run(sz.name+"/via-connect-proxy", func(b *testing.B) {
			run(b, &http.Client{Timeout: time.Minute, Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: tlsCfg,
			}})
		})
		b.Run(sz.name+"/via-tunnel", func(b *testing.B) {
			run(b, &http.Client{Timeout: time.Minute, Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					host, port := splitAddr(b, addr)
					return p.Dial(ctx, host, port)
				},
				TLSClientConfig: tlsCfg,
			}})
		})
	}
}
