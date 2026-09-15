package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/andybalholm/brotli"
)

func gzipped(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func zlibbed(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func brotlied(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func rawDeflate(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Almost every real API compresses its responses, so a capture buffer that cannot decode them is
// a buffer full of base64. These cover each encoding a body actually arrives in.
func TestBodiesAreDecodedForTheBuffer(t *testing.T) {
	want := `{"order":"A-91","items":[1,2,3]}`

	for _, tc := range []struct {
		name     string
		encoding string
		body     func(*testing.T, []byte) []byte
	}{
		{"gzip", "gzip", gzipped},
		{"x-gzip spelling", "x-gzip", gzipped},
		{"deflate as zlib", "deflate", zlibbed},
		{"deflate raw", "deflate", rawDeflate},
		// br is what Node and every browser ask for by default, so it is the common case.
		{"brotli", "br", brotlied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, decoded := decodeBody(tc.body(t, []byte(want)), tc.encoding)
			if !decoded {
				t.Fatal("the body should have been decoded")
			}
			if string(out) != want {
				t.Fatalf("decoded to %q, want %q", out, want)
			}
		})
	}
}

// Content-Encoding may list several, applied left to right, so they must be undone right to left.
func TestStackedEncodingsAreUndoneInOrder(t *testing.T) {
	want := "the body"
	twice := gzipped(t, zlibbed(t, []byte(want)))
	out, decoded := decodeBody(twice, "deflate, gzip")
	if !decoded || string(out) != want {
		t.Fatalf("stacked encodings not undone: %q (decoded=%v)", out, decoded)
	}
}

// Brotli stacked under gzip: undone right to left like any other list.
func TestBrotliStacksWithTheOthers(t *testing.T) {
	want := "the body"
	twice := gzipped(t, brotlied(t, []byte(want)))
	out, decoded := decodeBody(twice, "br, gzip")
	if !decoded || string(out) != want {
		t.Fatalf("stacked br+gzip not undone: %q (decoded=%v)", out, decoded)
	}
}

func TestAnUncompressedBodyIsLeftAlone(t *testing.T) {
	body := []byte(`{"plain":true}`)
	out, decoded := decodeBody(body, "")
	if decoded {
		t.Fatal("nothing was encoded; nothing should have been decoded")
	}
	if string(out) != string(body) {
		t.Fatalf("an identity body was altered: %q", out)
	}
	if out, decoded := decodeBody(body, "identity"); decoded || string(out) != string(body) {
		t.Fatalf("identity is not an encoding: %q (decoded=%v)", out, decoded)
	}
}

// A body that claims gzip and is not must not be dropped or corrupted. ntcept is a debugger:
// showing what really arrived matters more than showing something tidy.
func TestAMislabelledBodyIsKeptAsReceived(t *testing.T) {
	body := []byte("this is not gzip at all")
	out, decoded := decodeBody(body, "gzip")
	if decoded {
		t.Fatal("a body that is not gzip cannot have been decoded")
	}
	if string(out) != string(body) {
		t.Fatalf("the original bytes must survive, got %q", out)
	}
}

// brotli is what every browser and Node send by default and ntcept cannot read it. That has to
// be reported rather than shown as base64 and left to the reader to work out.
func TestAnUndecodableEncodingIsNamed(t *testing.T) {
	for _, tc := range []struct{ encoding, want string }{
		{"br", ""},
		{"zstd", "zstd"},
		{"gzip, br", ""},
		{"br, zstd", "zstd"},
		{"gzip", ""},
		{"", ""},
		{"identity", ""},
		{"deflate", ""},
	} {
		if got := undecodable(tc.encoding); got != tc.want {
			t.Errorf("undecodable(%q) = %q, want %q", tc.encoding, got, tc.want)
		}
	}
}

func TestAnEmptyBodyIsNotDecoded(t *testing.T) {
	out, decoded := decodeBody(nil, "gzip")
	if decoded || len(out) != 0 {
		t.Fatalf("an empty body should stay empty: %q (decoded=%v)", out, decoded)
	}
}
