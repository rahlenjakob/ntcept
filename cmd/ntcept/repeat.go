package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rahlenjakob/ntcept/internal/attach"
	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
)

type headerFlag []string

func (h *headerFlag) String() string { return strings.Join(*h, ", ") }
func (h *headerFlag) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// repeatCmd re-sends a captured request through the proxy, so the result is captured as a new
// flow and can be compared against the original with `ntcept diff`.
func repeatCmd(args []string) int {
	fs := flag.NewFlagSet("repeat", flag.ContinueOnError)
	addSessionFlag(fs)
	var headers headerFlag
	fs.Var(&headers, "header", "override or add a header, Name: value (repeatable)")
	method := fs.String("method", "", "override the method")
	target := fs.String("url", "", "override the URL")
	bodyFile := fs.String("body", "", "replace the body with the contents of this file, or - for stdin")
	asJSON := fs.Bool("json", false, "machine-readable output")
	ids, rest := takePositionals(args, 1)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	ids = append(ids, fs.Args()...)
	if len(ids) != 1 {
		return die("usage: ntcept repeat <id> [--header 'Name: value'] [--body file]")
	}

	f, err := fetchFlow(ids[0])
	if err != nil {
		return die("%v", err)
	}
	if f.Kind != capture.KindHTTP {
		return die("flow %s is %s, and only http flows can be repeated", f.ID, f.Kind)
	}

	req, masked, err := rebuild(f, *method, *target, *bodyFile, headers)
	if err != nil {
		return die("%v", err)
	}
	if len(masked) > 0 {
		fmt.Fprintf(os.Stderr,
			"ntcept: %s were redacted at capture and cannot be replayed; pass --header to supply them\n",
			strings.Join(masked, ", "))
	}

	client, err := proxyClient()
	if err != nil {
		return die("%v", err)
	}
	started := time.Now()
	res, err := client.Do(req)
	if err != nil {
		return die("%v", err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))

	out := map[string]any{
		"status": res.StatusCode, "ms": time.Since(started).Milliseconds(),
		"body": string(body), "repeated": f.ID,
	}
	return emit(*asJSON, out, func() {
		fmt.Printf("← %d  %dms  (repeat of %s; look for the new flow in `ntcept ls`)\n",
			res.StatusCode, time.Since(started).Milliseconds(), f.ID)
		fmt.Println(clip(string(body), false))
	})
}

// rebuild reconstructs the outbound request, reporting which headers were masked at capture and
// therefore cannot be sent as they originally were.
func rebuild(f *capture.Flow, method, target, bodyFile string, overrides []string) (*http.Request, []string, error) {
	m := f.Method
	if method != "" {
		m = method
	}
	u := f.URL
	if target != "" {
		u = target
	}
	body := f.ReqBody
	if bodyFile != "" {
		var (
			b   []byte
			err error
		)
		if bodyFile == "-" {
			b, err = io.ReadAll(os.Stdin)
		} else {
			b, err = os.ReadFile(bodyFile)
		}
		if err != nil {
			return nil, nil, err
		}
		body = b
	}

	req, err := http.NewRequest(m, u, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	var masked []string
	for k, vs := range f.ReqHdr {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Host") {
			continue
		}
		for _, v := range vs {
			if strings.HasPrefix(v, "«") {
				masked = append(masked, k)
				continue
			}
			req.Header.Add(k, v)
		}
	}
	for _, h := range overrides {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			return nil, nil, fmt.Errorf("--header wants `Name: value`, got %q", h)
		}
		req.Header.Set(strings.TrimSpace(k), strings.TrimSpace(v))
		masked = remove(masked, strings.TrimSpace(k))
	}
	sort.Strings(masked)
	return req, masked, nil
}

func remove(xs []string, want string) []string {
	out := xs[:0]
	for _, x := range xs {
		if !strings.EqualFold(x, want) {
			out = append(out, x)
		}
	}
	return out
}

// proxyClient sends through the running ntcept, so a repeat is captured like any other traffic.
func proxyClient() (*http.Client, error) {
	s, err := attach.ResolveSession(sessionName)
	if err != nil {
		return nil, err
	}
	authority, err := ca.LoadOrCreate(ca.Home())
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority.PEM) {
		return nil, fmt.Errorf("could not load the ntcept CA")
	}
	pu, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(s.ProxyPort))
	return &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(pu),
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

// curlCmd prints an equivalent curl invocation, which is often what a person actually wants.
func curlCmd(args []string) int {
	ids, _ := takePositionals(args, 1)
	if len(ids) != 1 {
		return die("usage: ntcept curl <id>")
	}
	f, err := fetchFlow(ids[0])
	if err != nil {
		return die("%v", err)
	}
	var b strings.Builder
	b.WriteString("curl -X " + f.Method + " " + shellQuote(f.URL))
	keys := make([]string, 0, len(f.ReqHdr))
	for k := range f.ReqHdr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range f.ReqHdr[k] {
			b.WriteString(" \\\n  -H " + shellQuote(k+": "+v))
		}
	}
	if len(f.ReqBody) > 0 {
		b.WriteString(" \\\n  --data-raw " + shellQuote(string(f.ReqBody)))
	}
	fmt.Println(b.String())
	if hasMasked(f) {
		fmt.Fprintln(os.Stderr, "\nntcept: values shown as «name/fingerprint» were redacted at capture — substitute the real ones.")
	}
	return 0
}

func hasMasked(f *capture.Flow) bool {
	for _, vs := range f.ReqHdr {
		for _, v := range vs {
			if strings.HasPrefix(v, "«") {
				return true
			}
		}
	}
	return false
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func fetchFlow(id string) (*capture.Flow, error) {
	c, err := dial()
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := c.Get("/flows/"+id, nil, &raw); err != nil {
		return nil, err
	}
	return flowFromDetail(raw)
}
