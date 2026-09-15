// Package redact strips credentials on the way into the capture buffer, never on the way out.
// The forwarding path sees real bytes because it must; nothing retains them.
//
// The value is replaced by a stable fingerprint rather than dropped, so "the same token appears
// in both of these requests" stays answerable without the token being readable.
package redact

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

type Report struct {
	Secrets []string `json:"secrets,omitempty"`
}

func (r Report) Clean() bool { return len(r.Secrets) == 0 }

func (r *Report) Merge(o Report) { r.Secrets = union(r.Secrets, o.Secrets) }

func union(a, b []string) []string {
	for _, s := range b {
		if !slicesContains(a, s) {
			a = append(a, s)
		}
	}
	return a
}

func slicesContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

var secretHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"x-api-key": true, "api-key": true, "x-auth-token": true, "x-access-token": true,
	"x-amz-security-token": true, "x-goog-api-key": true, "x-session-token": true,
	"x-secret-key": true, "private-token": true,
}

var secretKeys = regexp.MustCompile(`(?i)^(password|passwd|secret|client_?secret|api_?key|apikey|access_?token|refresh_?token|id_?token|private_?key|session_?token|auth_?token|credential|signing_?key)$`)

// tokenRule is one kind of credential ntcept recognises wherever it appears.
//
// leads is what makes this affordable. Redaction runs over every captured byte, and a regex over
// a megabyte costs tens of milliseconds because RE2 simulates its automaton per byte. Every
// pattern here, though, requires a fixed literal to be present — a credential format is a brand
// followed by entropy — and searching for a fixed literal is a memchr, roughly two orders of
// magnitude faster. So leads decides whether the expensive pass happens at all, and which
// patterns are worth asking.
//
// The invariant that makes this safe: re must not be able to match any text containing none of
// leads. TestEveryRuleIsFoundThroughItsLead holds each rule to it.
type tokenRule struct {
	name  string
	leads []string
	re    *regexp.Regexp
}

var tokenRules = []*tokenRule{
	{"stripe", []string{"sk_live_", "sk_test_"},
		regexp.MustCompile(`\bsk_(live|test)_[A-Za-z0-9]{16,}`)},
	{"github", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
		regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}`)},
	{"aws", []string{"AKIA"},
		regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"google", []string{"AIza"},
		regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{30,}`)},
	{"slack", []string{"xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"},
		regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z\-]{10,}`)},
	{"jwt", []string{"eyJ"},
		regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)},
	{"private-key", []string{"-----BEGIN "},
		regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

func init() {
	// A rule with no lead would be silently skipped by every scan below, which is the one
	// failure mode of this design that would not announce itself. Refuse to start instead.
	for _, rule := range tokenRules {
		if len(rule.leads) == 0 {
			panic("redact: token rule " + rule.name + " declares no lead literal")
		}
	}
}

// candidates names the rules whose lead appears in b. An empty result means no pattern here can
// possibly match, so the body needs neither scanning nor copying.
func candidates(b []byte) []*tokenRule {
	var out []*tokenRule
	for _, rule := range tokenRules {
		for _, lead := range rule.leads {
			if bytes.Contains(b, []byte(lead)) {
				out = append(out, rule)
				break
			}
		}
	}
	return out
}

// candidatesIn is candidates over a string, kept separate so a header value or a JSON field does
// not have to be copied into a byte slice to be checked.
func candidatesIn(s string) []*tokenRule {
	var out []*tokenRule
	for _, rule := range tokenRules {
		for _, lead := range rule.leads {
			if strings.Contains(s, lead) {
				out = append(out, rule)
				break
			}
		}
	}
	return out
}

func replace(s string, rules []*tokenRule) (string, Report) {
	var r Report
	for _, rule := range rules {
		s = rule.re.ReplaceAllStringFunc(s, func(m string) string {
			r.Secrets = union(r.Secrets, []string{"token"})
			return mask("token", m)
		})
	}
	return s, r
}

func Fingerprint(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:8]
}

func mask(kind, v string) string { return "«" + kind + "/" + Fingerprint(v) + "»" }

func Headers(h http.Header) (http.Header, Report) {
	var r Report
	out := make(http.Header, len(h))
	for k, vs := range h {
		lk := strings.ToLower(k)
		cp := make([]string, len(vs))
		copy(cp, vs)
		if secretHeaders[lk] {
			r.Secrets = union(r.Secrets, []string{lk})
			for i, v := range cp {
				cp[i] = mask(lk, v)
			}
		} else {
			for i, v := range cp {
				nv, sub := Text(v)
				cp[i] = nv
				r.Merge(sub)
			}
		}
		out[k] = cp
	}
	return out, r
}

func Text(s string) (string, Report) {
	hits := candidatesIn(s)
	if len(hits) == 0 {
		return s, Report{}
	}
	return replace(s, hits)
}

// Body walks JSON structurally and falls back to a text scan for anything else.
func Body(body []byte, contentType string) ([]byte, Report) {
	var r Report
	if len(body) == 0 {
		return body, r
	}
	if looksJSON(body, contentType) {
		var v any
		if err := json.Unmarshal(body, &v); err == nil {
			v = walk(v, &r)
			if out, err := json.Marshal(v); err == nil {
				return out, r
			}
		}
	}
	// Converting a multi-megabyte body to a string to scan it costs a copy of the whole thing.
	// Ask first; for an image, a bundle or a video the answer is no and nothing is copied.
	hits := candidates(body)
	if len(hits) == 0 {
		return body, r
	}
	out, sub := replace(string(body), hits)
	r.Merge(sub)
	return []byte(out), r
}

func looksJSON(b []byte, ct string) bool {
	if strings.Contains(strings.ToLower(ct), "json") {
		return true
	}
	t := strings.TrimLeft(string(b[:min(len(b), 8)]), " \t\r\n")
	return strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")
}

func walk(v any, r *Report) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if secretKeys.MatchString(strings.ToLower(k)) {
				r.Secrets = union(r.Secrets, []string{strings.ToLower(k)})
				t[k] = mask(strings.ToLower(k), asText(child))
				continue
			}
			t[k] = walk(child, r)
		}
		return t
	case []any:
		for i, child := range t {
			t[i] = walk(child, r)
		}
		return t
	case string:
		out, sub := Text(t)
		r.Merge(sub)
		return out
	}
	return v
}

func asText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
