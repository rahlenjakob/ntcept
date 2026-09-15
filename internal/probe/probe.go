// Package probe answers "will this runtime's TLS actually be readable on this machine" by trying
// it, rather than by consulting a table.
//
// The tunnel routes every runtime below the socket API, so routing is never in question. What
// still fails independently is trust: the runtime must accept the certificate ntcept presents. A
// table cannot know — Apple's system python, for instance, reports SSL_CERT_FILE in its verify
// paths and then ignores it. A runtime that pins its own roots is recorded as an opaque
// passthrough rather than broken.
package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/rahlenjakob/ntcept/internal/attach"
	"github.com/rahlenjakob/ntcept/internal/ca"
)

// ProbeHost is a name in .invalid so it can never resolve; the trust test reaches the origin by
// address, and the certificate carries this name as a SAN alongside the loopback IP.
const ProbeHost = "probe.ntcept.invalid"

// State is a measured answer. Unknown is a real outcome and is never collapsed into No: if a
// runtime never reaches a TLS handshake, nothing has been learned about whether it would have
// trusted the certificate.
type State string

const (
	Yes     State = "yes"
	No      State = "no"
	Unknown State = "unknown"
)

type Result struct {
	Name  string `json:"runtime"`
	Path  string `json:"path,omitempty"`
	Trust State  `json:"trusts_ca"`

	TrustDetail string `json:"trust_detail,omitempty"`
}

// TunnelOK reports whether ntcept can read this runtime's TLS. Routing is not in question — it
// happens below the socket API — so only trust matters.
func (r Result) TunnelOK() bool { return r.Trust == Yes }

type runtimeProbe struct {
	name string
	bin  string
	// args builds a command that fetches url and exits non-zero on any failure.
	args func(url string) []string
}

var probes = []runtimeProbe{
	{"curl", "curl", func(u string) []string {
		return []string{"-sS", "--max-time", "8", "-o", "/dev/null", u}
	}},
	{"python", "python3", func(u string) []string {
		return []string{"-c", "import sys,urllib.request; urllib.request.urlopen(sys.argv[1], timeout=8).read()", u}
	}},
	{"node", "node", func(u string) []string {
		return []string{"-e", `const https=require("node:https");https.get(process.argv[1],r=>{r.resume();r.on("end",()=>process.exit(0))}).on("error",e=>{console.error(e.message);process.exit(1)})`, u}
	}},
	{"ruby", "ruby", func(u string) []string {
		return []string{"-e", `require "net/http"; Net::HTTP.get(URI(ARGV[0]))`, u}
	}},
	{"deno", "deno", func(u string) []string {
		return []string{"eval", "--allow-net", "--allow-env", fmt.Sprintf("await (await fetch(%q)).text()", u)}
	}},
	{"bun", "bun", func(u string) []string {
		return []string{"-e", fmt.Sprintf("await (await fetch(%q)).text()", u)}
	}},
}

// Run stands up a TLS origin signed by ntcept's own CA and drives every installed runtime at it,
// measuring whether each trusts the certificate. Nothing leaves the machine.
func Run(ctx context.Context) ([]Result, error) {
	authority, err := ca.LoadOrCreate(ca.Home())
	if err != nil {
		return nil, err
	}
	origin, originAddr, err := startOrigin(authority)
	if err != nil {
		return nil, err
	}
	defer origin.Close()

	directURL := "https://" + originAddr

	var out []Result
	for _, p := range probes {
		path, err := exec.LookPath(p.bin)
		if err != nil {
			continue
		}
		// Which binary was tested matters: two python3 installs on one machine can disagree
		// about whether SSL_CERT_FILE means anything.
		r := Result{Name: p.name, Path: path}
		r.Trust, r.TrustDetail = trustTest(ctx, p, directURL, authority.CertPath())
		out = append(out, r)
	}
	return out, nil
}

// trustTest asks whether the runtime accepts ntcept's certificate, by talking to the origin
// directly. This is the question the tunnel attach depends on.
func trustTest(ctx context.Context, p runtimeProbe, url, caPath string) (State, string) {
	runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, p.bin, p.args(url)...)
	cmd.Env = attach.Apply(nil, attach.Trust("", caPath), nil)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return Yes, "accepts ntcept's certificate"
	}
	return No, firstLine(string(out))
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output"
	}
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 140 {
		s = s[:140] + "…"
	}
	return s
}

// startOrigin serves TLS with a certificate ntcept minted, standing in for a real upstream so
// the probe needs no network.
func startOrigin(authority *ca.Authority) (*http.Server, string, error) {
	// The cert carries both the loopback IP (reached by address) and the .invalid name, so the
	// same origin works however a runtime forms the URL.
	leaf, err := authority.LeafForSANs([]string{ProbeHost}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, "", err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("ntcept probe\n"))
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12},
	}
	go srv.ServeTLS(ln, "", "")
	return srv, ln.Addr().String(), nil
}
