package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

const maxDecoded = 64 << 20

// decodeBody returns a readable copy of a compressed body. The bytes on the wire are never
// touched — the client gets exactly what the server sent — but almost every real API compresses
// its responses, and a capture buffer full of base64 is not an inspector.
//
// The returned flag says whether anything was decoded, which is what tells the hold path that a
// replaced body must not keep the original Content-Encoding.
func decodeBody(b []byte, encoding string) ([]byte, bool) {
	if len(b) == 0 {
		return b, false
	}
	// Content-Encoding may list several, applied in order; undo them from the right.
	parts := strings.Split(strings.ToLower(encoding), ",")
	out, decoded := b, false
	for i := len(parts) - 1; i >= 0; i-- {
		switch strings.TrimSpace(parts[i]) {
		case "gzip", "x-gzip":
			if next, ok := readAllFrom(func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) }, out); ok {
				out, decoded = next, true
			}
		case "deflate":
			// Servers disagree about whether deflate means zlib or raw; try both.
			if next, ok := readAllFrom(func(r io.Reader) (io.Reader, error) { return zlib.NewReader(r) }, out); ok {
				out, decoded = next, true
			} else if next, ok := readAllFrom(func(r io.Reader) (io.Reader, error) { return flate.NewReader(r), nil }, out); ok {
				out, decoded = next, true
			}
		case "br":
			// What Node and every browser ask for by default, so this was the common case
			// arriving as base64 rather than the exotic one.
			if next, ok := readAllFrom(func(r io.Reader) (io.Reader, error) { return brotli.NewReader(r), nil }, out); ok {
				out, decoded = next, true
			}
		}
	}
	return out, decoded
}

func readAllFrom(open func(io.Reader) (io.Reader, error), b []byte) ([]byte, bool) {
	r, err := open(bytes.NewReader(b))
	if err != nil {
		return nil, false
	}
	out, err := io.ReadAll(io.LimitReader(r, maxDecoded))
	if err != nil || len(out) == 0 {
		return nil, false
	}
	if c, ok := r.(io.Closer); ok {
		_ = c.Close()
	}
	return out, true
}

// undecodable names an encoding ntcept cannot read, so the flow says why rather than showing
// base64 and leaving the reader to guess.
func undecodable(encoding string) string {
	for _, p := range strings.Split(strings.ToLower(encoding), ",") {
		switch p = strings.TrimSpace(p); p {
		case "", "identity", "gzip", "x-gzip", "deflate", "br":
		default:
			return p
		}
	}
	return ""
}
