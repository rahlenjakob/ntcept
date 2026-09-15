package redact

import (
	"net/http"
	"strings"
	"testing"
)

func TestSecretsAreFingerprintedNotDropped(t *testing.T) {
	h := http.Header{"Authorization": {"Bearer abc123"}, "Content-Type": {"application/json"}}
	out, r := Headers(h)
	got := out.Get("Authorization")
	if strings.Contains(got, "abc123") {
		t.Fatalf("credential survived: %s", got)
	}
	if !strings.Contains(got, Fingerprint("Bearer abc123")) {
		t.Fatalf("identity must survive the value: %s", got)
	}
	if out.Get("Content-Type") != "application/json" {
		t.Fatal("ordinary headers must be untouched")
	}
	if len(r.Secrets) != 1 {
		t.Fatalf("expected one secret header, got %v", r.Secrets)
	}
}

func TestPayloadsStayReadable(t *testing.T) {
	in := []byte(`{"card":{"number":"4111111111111111"},"email":"a@b.com","ref":"ORD-4471"}`)
	out, r := Body(in, "application/json")
	s := string(out)
	for _, want := range []string{"4111111111111111", "a@b.com", "ORD-4471"} {
		if !strings.Contains(s, want) {
			t.Fatalf("a developer must be able to read their own payload, %q missing: %s", want, s)
		}
	}
	if !r.Clean() {
		t.Fatalf("nothing here is a credential: %+v", r)
	}
}

func TestSecretFieldsAndTokensInBodies(t *testing.T) {
	tok := "sk_live" + "_abcdefghij0123456789"
	in := []byte(`{"client_secret":"hunter2","note":"use ` + tok + ` for this"}`)
	out, r := Body(in, "application/json")
	s := string(out)
	if strings.Contains(s, "hunter2") || strings.Contains(s, tok) {
		t.Fatalf("credential survived into the buffer: %s", s)
	}
	if len(r.Secrets) != 2 {
		t.Fatalf("expected the field and the inline token, got %v", r.Secrets)
	}
}

func TestSameSecretGivesSameFingerprintAcrossFlows(t *testing.T) {
	a, _ := Headers(http.Header{"X-Api-Key": {"k1"}})
	b, _ := Headers(http.Header{"X-Api-Key": {"k1"}})
	c, _ := Headers(http.Header{"X-Api-Key": {"k2"}})
	if a.Get("X-Api-Key") != b.Get("X-Api-Key") {
		t.Fatal("the same credential must fingerprint identically")
	}
	if a.Get("X-Api-Key") == c.Get("X-Api-Key") {
		t.Fatal("different credentials must fingerprint differently")
	}
}

func TestNonJSONBodyIsScannedAsText(t *testing.T) {
	out, r := Body([]byte("token=ghp_"+strings.Repeat("a", 36)), "application/x-www-form-urlencoded")
	if strings.Contains(string(out), "ghp_a") {
		t.Fatalf("token survived: %s", out)
	}
	if r.Clean() {
		t.Fatal("expected a token finding")
	}
}

// TestEveryRuleIsFoundThroughItsLead is what makes the literal prefilter safe to rely on. Rules
// are only ever consulted for text containing one of their leads, so a rule whose leads do not
// cover its pattern would silently stop redacting — a credential would reach the capture buffer
// in clear and nothing would say so. Each rule is checked end to end through the public API,
// which is the path that would actually be wrong.
func TestEveryRuleIsFoundThroughItsLead(t *testing.T) {
	samples := map[string]string{
		"stripe":      "sk_live" + "_abcdefghij0123456789",
		"github":      "ghp_" + strings.Repeat("a", 36),
		"aws":         "AKIAIOSFODNN7EXAMPLE",
		"google":      "AIza" + strings.Repeat("b", 35),
		"slack":       "xoxb-1234567890-abcdefghij",
		"jwt":         "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		"private-key": "-----BEGIN RSA PRIVATE KEY-----",
	}
	if len(samples) != len(tokenRules) {
		t.Fatalf("every rule needs a sample: %d rules, %d samples", len(tokenRules), len(samples))
	}

	for _, rule := range tokenRules {
		sample, ok := samples[rule.name]
		if !ok {
			t.Errorf("rule %q has no sample; add one so its lead is checked", rule.name)
			continue
		}
		if !rule.re.MatchString(sample) {
			t.Errorf("rule %q does not match its own sample %q", rule.name, sample)
			continue
		}
		// The invariant: the prefilter must admit this rule for text its pattern matches.
		found := false
		for _, c := range candidates([]byte(sample)) {
			if c == rule {
				found = true
			}
		}
		if !found {
			t.Errorf("rule %q matches %q but none of its leads %v appear in it: "+
				"the prefilter would skip it and the credential would be stored in clear",
				rule.name, sample, rule.leads)
			continue
		}
		// And the whole thing, through the door a caller actually uses.
		body := []byte("trailing context " + sample + " more context")
		out, r := Body(body, "text/plain")
		if strings.Contains(string(out), sample) {
			t.Errorf("rule %q: credential survived into the buffer: %s", rule.name, out)
		}
		if r.Clean() {
			t.Errorf("rule %q: the finding was not reported", rule.name)
		}
	}
}

// TestCleanBodyIsReturnedUntouched guards the fast path's other half: when nothing matches, the
// body must come back byte-identical rather than round-tripped through anything.
func TestCleanBodyIsReturnedUntouched(t *testing.T) {
	body := []byte("<html><body>nothing secret here, just an ordinary page</body></html>")
	out, r := Body(body, "text/html")
	if string(out) != string(body) {
		t.Fatalf("a clean body was altered: %q", out)
	}
	if !r.Clean() {
		t.Fatalf("a clean body reported findings: %+v", r)
	}
}

// TestABodyThatIsAlmostACredentialIsLeftAlone: leads are literals, so text can contain one
// without containing a credential. That must cost nothing but a wasted scan.
func TestABodyThatIsAlmostACredentialIsLeftAlone(t *testing.T) {
	body := []byte(`{"note":"our sk_live_ prefix is documented; AKIA is the AWS one"}`)
	out, r := Body(body, "application/json")
	if !r.Clean() {
		t.Fatalf("a mention of a prefix is not a credential: %+v", r)
	}
	if !strings.Contains(string(out), "sk_live_") || !strings.Contains(string(out), "AKIA") {
		t.Fatalf("the developer's own text was mangled: %s", out)
	}
}
