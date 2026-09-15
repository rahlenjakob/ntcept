package redact

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
)

// Redaction is the one thing ntcept does to every captured byte, and it is on the path of every
// response. These say what that costs per megabyte, which is the number that decides whether
// --max-body-kb is a safety valve or a performance setting.
//
//	go test ./internal/redact -run '^$' -bench . -benchmem

// prose stands in for the bodies ntcept mostly sees that are not JSON: HTML, a JS bundle, a CSS
// file. Uniformly random alphanumerics would be the wrong corpus — in a megabyte of it a
// three-letter lead like "eyJ" turns up by chance, which measures the generator rather than the
// code. Real text of this length contains no credential lead at all.
func prose(n int) []byte {
	const para = "<section class=\"card\"><h2>Recent orders</h2><p>The customer placed this " +
		"order on the fourteenth and it shipped the following morning from the northern " +
		"warehouse.</p><ul><li>Reference ORD-4471</li><li>Two items</li></ul></section>"
	var b []byte
	for len(b) < n {
		b = append(b, para...)
	}
	return b[:n]
}

// binary stands in for an image, a font or a protobuf: every byte value, nothing textual.
func binary(n int, seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	_, _ = r.Read(b)
	return b
}

// dense is the adversarial corpus, kept deliberately: packed alphanumerics of the kind a base64
// attachment produces, where a short lead does occur by chance and the full scan really runs.
func dense(n int, seed int64) []byte {
	r := rand.New(rand.NewSource(seed))
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return b
}

func jsonBody(n int) []byte {
	var rows []map[string]any
	for size := 0; size < n; {
		row := map[string]any{
			"id": fmt.Sprintf("ord_%d", len(rows)),
			"customer": map[string]any{
				"email": "someone@example.com",
				"note":  string(prose(120)),
			},
			"amount": 4200,
		}
		rows = append(rows, row)
		size += 220
	}
	b, _ := json.Marshal(map[string]any{"data": rows})
	return b
}

var bodySizes = []struct {
	name string
	n    int
}{
	{"64KB", 64 << 10},
	{"1MB", 1 << 20},
}

// BenchmarkBodyClean is the overwhelmingly common case: a body with no credential in it at all.
// This is the number that decides whether capture is free, because it is what almost every
// response costs.
func BenchmarkBodyClean(b *testing.B) {
	for _, shape := range []struct {
		name string
		gen  func(int) []byte
	}{
		{"prose", prose},
		{"binary", func(n int) []byte { return binary(n, 1) }},
		{"dense", func(n int) []byte { return dense(n, 1) }},
	} {
		for _, sz := range bodySizes {
			body := shape.gen(sz.n)
			b.Run(shape.name+"/"+sz.name, func(b *testing.B) {
				b.SetBytes(int64(sz.n))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					Body(body, "application/octet-stream")
				}
			})
		}
	}
}

// BenchmarkBodyJSON is the API case: parsed, walked key by key, re-marshalled.
func BenchmarkBodyJSON(b *testing.B) {
	for _, sz := range bodySizes {
		body := jsonBody(sz.n)
		b.Run(sz.name, func(b *testing.B) {
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				Body(body, "application/json")
			}
		})
	}
}

// BenchmarkBodyWithSecrets is the case that must stay correct however it is optimised: tokens
// really are in there and every one has to be found.
func BenchmarkBodyWithSecrets(b *testing.B) {
	body := prose(1 << 20)
	secrets := [][]byte{
		[]byte("sk_live" + "_abcdefghijklmnopqrstuvwx"),
		[]byte("ghp" + "_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		[]byte("AKIAIOSFODNN7EXAMPLE"),
	}
	for i, secret := range secrets {
		// Surrounded by spaces: every pattern requires a word boundary, and a token spliced
		// into the middle of a word is not a token.
		at := (i + 1) * (len(body) / 4)
		copy(body[at:], append(append([]byte(" "), secret...), ' '))
	}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_, r := Body(body, "application/octet-stream")
		if len(r.Secrets) == 0 {
			b.Fatal("the credentials planted in this body were not found")
		}
	}
}

// BenchmarkHeaders is per-request rather than per-byte, but it runs on every single flow.
func BenchmarkHeaders(b *testing.B) {
	h := realisticHeaders()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		Headers(h)
	}
}

func realisticHeaders() map[string][]string {
	return map[string][]string{
		"Authorization":   {"Bearer sk_live" + "_abcdefghijklmnopqrstuvwx"},
		"Content-Type":    {"application/json"},
		"Accept":          {"application/json"},
		"Accept-Encoding": {"gzip, deflate, br"},
		"User-Agent":      {"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"},
		"Cookie":          {"session=abc123; theme=dark"},
		"X-Request-Id":    {"7f3a1c9e-2b44-4f1a-9c0d-5e8b1a2d3f40"},
		"Traceparent":     {"00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"},
	}
}
