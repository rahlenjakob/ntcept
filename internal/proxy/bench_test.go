package proxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/rahlenjakob/ntcept/internal/capture"
)

// Nothing here is meaningful on its own: a proxy's cost is the difference between going through
// it and not, on the same machine, in the same run. Every benchmark below therefore ships with
// the direct measurement beside it, and reports bytes so the throughput ratio is readable
// without tooling.
//
//	go test ./internal/proxy -run '^$' -bench . -benchmem

// sizes chosen to straddle the interesting boundaries: an API response, a bundle, a download.
var benchSizes = []struct {
	name string
	n    int
}{
	{"4KB", 4 << 10},
	{"1MB", 1 << 20},
	{"32MB", 32 << 20},
}

func benchOrigin(tb testing.TB, tlsOn bool, payload []byte) *httptest.Server {
	tb.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	})
	var srv *httptest.Server
	if tlsOn {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	tb.Cleanup(srv.Close)
	return srv
}

func directClient(srv *httptest.Server) *http.Client {
	c := srv.Client()
	c.Timeout = 5 * time.Minute
	return c
}

func drain(b *testing.B, c *http.Client, url string) {
	b.Helper()
	res, err := c.Get(url)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		b.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		b.Fatalf("unexpected status %d", res.StatusCode)
	}
}

// BenchmarkDownload is the number the README's claim rests on: what it costs an application to
// have every byte it receives pass through ntcept. Cleartext, so this is capture cost alone with
// no TLS in the comparison.
func BenchmarkDownload(b *testing.B) {
	for _, sz := range benchSizes {
		payload := make([]byte, sz.n)
		origin := benchOrigin(b, false, payload)

		b.Run(sz.name+"/direct", func(b *testing.B) {
			c := directClient(origin)
			b.SetBytes(int64(sz.n))
			b.ResetTimer()
			for b.Loop() {
				drain(b, c, origin.URL+"/blob")
			}
		})

		b.Run(sz.name+"/proxied", func(b *testing.B) {
			h := newHarness(b, nil)
			c := h.client()
			c.Timeout = 5 * time.Minute
			b.SetBytes(int64(sz.n))
			b.ResetTimer()
			for b.Loop() {
				drain(b, c, origin.URL+"/blob")
			}
		})
	}
}

// BenchmarkDownloadTLS adds what interception really costs: terminating the application's TLS
// with a minted certificate and opening a second TLS connection upstream. The direct arm pays
// for one handshake's worth of crypto, the proxied arm for two.
func BenchmarkDownloadTLS(b *testing.B) {
	for _, sz := range benchSizes {
		payload := make([]byte, sz.n)
		origin := benchOrigin(b, true, payload)

		b.Run(sz.name+"/direct", func(b *testing.B) {
			c := directClient(origin)
			b.SetBytes(int64(sz.n))
			b.ResetTimer()
			for b.Loop() {
				drain(b, c, origin.URL+"/blob")
			}
		})

		b.Run(sz.name+"/intercepted", func(b *testing.B) {
			h := newHarness(b, origin.Certificate())
			c := h.client()
			c.Timeout = 5 * time.Minute
			b.SetBytes(int64(sz.n))
			b.ResetTimer()
			for b.Loop() {
				drain(b, c, origin.URL+"/blob")
			}
		})
	}
}

// BenchmarkUpload measures the other direction, which takes a different path through the code:
// a request body is streamed through a tee rather than copied out of a response.
func BenchmarkUpload(b *testing.B) {
	for _, sz := range benchSizes {
		payload := make([]byte, sz.n)
		origin := benchOrigin(b, false, nil)

		post := func(b *testing.B, c *http.Client) {
			b.SetBytes(int64(sz.n))
			b.ResetTimer()
			for b.Loop() {
				res, err := c.Post(origin.URL+"/ingest", "application/octet-stream",
					strings.NewReader(string(payload)))
				if err != nil {
					b.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
			}
		}

		b.Run(sz.name+"/direct", func(b *testing.B) { post(b, directClient(origin)) })
		b.Run(sz.name+"/proxied", func(b *testing.B) {
			h := newHarness(b, nil)
			c := h.client()
			c.Timeout = 5 * time.Minute
			post(b, c)
		})
	}
}

// BenchmarkRequestLatency is the case an API-driven app actually generates: many small round
// trips on a warm connection. Throughput hides per-request overhead; this exposes it.
func BenchmarkRequestLatency(b *testing.B) {
	origin := benchOrigin(b, false, []byte(`{"ok":true}`))

	b.Run("direct", func(b *testing.B) {
		c := directClient(origin)
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			drain(b, c, origin.URL+"/v1/ping")
		}
	})
	b.Run("proxied", func(b *testing.B) {
		h := newHarness(b, nil)
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			drain(b, h.client(), origin.URL+"/v1/ping")
		}
	})
	// Separated because the connection is reused: this is steady state, not the first request.
	b.Run("proxied-keepalive", func(b *testing.B) {
		h := newHarness(b, nil)
		c := h.client()
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			drain(b, c, origin.URL+"/v1/ping")
		}
	})
}

// BenchmarkCaptureCeiling asks how much of the cost is the capture buffer rather than the
// forwarding. A body under the ceiling is copied and redacted; one over it is only counted. If
// these differ sharply, --max-body-kb is a performance knob and should be documented as one.
func BenchmarkCaptureCeiling(b *testing.B) {
	const n = 8 << 20
	payload := make([]byte, n)
	origin := benchOrigin(b, false, payload)

	for _, ceiling := range []struct {
		name string
		kb   int
	}{
		{"nothing-captured", 0},
		{"64KB-captured", 64},
		{"whole-body-captured", (n >> 10) * 2},
	} {
		b.Run(ceiling.name, func(b *testing.B) {
			h := newHarness(b, nil)
			h.store.MaxBody = ceiling.kb << 10
			c := h.client()
			c.Timeout = 5 * time.Minute
			b.SetBytes(n)
			b.ResetTimer()
			for b.Loop() {
				drain(b, c, origin.URL+"/blob")
			}
		})
	}
}

// BenchmarkConcurrentFlows is the shape a real application produces under load, and the one that
// finds lock contention: the capture store takes a single mutex on every update.
func BenchmarkConcurrentFlows(b *testing.B) {
	origin := benchOrigin(b, false, make([]byte, 16<<10))
	h := newHarness(b, nil)
	pu, _ := url.Parse(h.proxy)

	b.ReportAllocs()
	b.SetBytes(16 << 10)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c := &http.Client{
			Timeout: time.Minute,
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(pu),
				TLSClientConfig: &tls.Config{RootCAs: h.pool, MinVersion: tls.VersionTLS12},
			},
		}
		for pb.Next() {
			res, err := c.Get(origin.URL + "/blob")
			if err != nil {
				b.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
	})
}

// BenchmarkHoldRoundTrip prices `intercept on`. Holding buffers the whole body rather than
// streaming it, and every exchange waits for a verdict, so this is the cost of the interactive
// mode as distinct from passive capture.
func BenchmarkHoldRoundTrip(b *testing.B) {
	origin := benchOrigin(b, false, []byte(`{"ok":true}`))
	h := newHarness(b, nil)
	h.srv.HoldRequests.Store(true)
	h.srv.HoldMS.Store(30_000)

	stop := make(chan struct{})
	defer close(stop)
	// An operator that always forwards immediately, so the measurement is ntcept's overhead
	// rather than a human's reaction time.
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, held := range h.srv.Queue.List() {
				h.srv.Queue.Release(held.ID, capture.Verdict{Action: capture.ActionForward})
			}
		}
	}()

	c := h.client()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		drain(b, c, origin.URL+"/v1/ping")
	}
}
