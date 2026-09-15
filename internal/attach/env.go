package attach

import "strings"

// Var is one environment variable handed to the child, with the reason it exists. doctor prints
// these, so a runtime that slips past interception is a one-line diagnosis rather than an
// afternoon.
type Var struct {
	Key  string
	Val  string
	Why  string
	Runt string
}

// Trust teaches a runtime to accept ntcept's certificate. Routing a process's packets below the
// socket API does not make it trust the certificate ntcept presents, so without these TLS
// interception fails closed. These are the only variables ntcept sets: it configures no proxy,
// because the tunnel needs none.
func Trust(controlURL, caPath string) []Var {
	return []Var{
		{"SSL_CERT_FILE", caPath, "OpenSSL trust root", "curl, python, ruby, php"},
		{"CURL_CA_BUNDLE", caPath, "curl trust root", "curl"},
		{"REQUESTS_CA_BUNDLE", caPath, "requests ships certifi, not the OS store", "python requests"},
		{"NODE_EXTRA_CA_CERTS", caPath, "node ships its own Mozilla bundle", "node"},
		{"DENO_CERT", caPath, "deno trust root", "deno"},
		{"BUN_CA_BUNDLE", caPath, "bun trust root", "bun"},
		{"GIT_SSL_CAINFO", caPath, "git trust root", "git"},
		{"AWS_CA_BUNDLE", caPath, "aws sdk trust root", "aws"},
		{"CARGO_HTTP_CAINFO", caPath, "cargo trust root", "cargo"},

		{"NTCEPT_CONTROL", controlURL, "where the CLI finds this session", "ntcept"},
	}
}

// Apply merges the variables onto a copy of the parent environment, replacing only the keys it
// sets and leaving the app's own configuration intact.
func Apply(parent []string, vars []Var, extra map[string]string) []string {
	set := map[string]string{}
	for _, v := range vars {
		set[v.Key] = v.Val
	}
	for k, val := range extra {
		set[k] = val
	}

	out := make([]string, 0, len(parent)+len(set))
	for _, kv := range parent {
		k, _, ok := strings.Cut(kv, "=")
		if ok {
			if _, override := set[k]; override {
				continue
			}
		}
		out = append(out, kv)
	}
	for k, val := range set {
		out = append(out, k+"="+val)
	}
	return out
}
