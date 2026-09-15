package attach

import (
	"os"
	"strings"
	"testing"
)

func envMap(kv []string) map[string]string {
	m := map[string]string{}
	for _, e := range kv {
		if k, v, ok := strings.Cut(e, "="); ok {
			m[k] = v
		}
	}
	return m
}

// Apply is what decides whether a child is intercepted at all, and it has to leave the rest of
// the environment exactly as it found it — the app under test still needs its own configuration.
func TestApplyOverridesOnlyWhatItSets(t *testing.T) {
	parent := []string{"PATH=/usr/bin", "DATABASE_URL=postgres://localhost/app", "SSL_CERT_FILE=/etc/ssl/old.pem"}
	out := Apply(parent, Trust("http://127.0.0.1:10", "/tmp/ca.pem"), nil)
	got := envMap(out)

	if got["PATH"] != "/usr/bin" || got["DATABASE_URL"] != "postgres://localhost/app" {
		t.Fatalf("the child's own environment was disturbed: %v", got)
	}
	if got["SSL_CERT_FILE"] != "/tmp/ca.pem" {
		t.Fatalf("an existing trust root must be replaced with ntcept's CA, got %q", got["SSL_CERT_FILE"])
	}
	// A duplicate key would leave the outcome up to whichever the runtime reads last.
	seen := map[string]int{}
	for _, e := range out {
		k, _, _ := strings.Cut(e, "=")
		seen[k]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Fatalf("%s appears %d times; which one wins is up to the runtime", k, n)
		}
	}
}

// The tunnel attach delivers only the trust variables and must not set proxy ones: routing
// already happens below the socket API, and a proxy variable there would send traffic through a
// second hop for no reason.
func TestTrustCarriesNoProxy(t *testing.T) {
	trust := Trust("http://127.0.0.1:4300", "/tmp/ca.pem")
	full := envMap(applyVars(trust))
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if _, ok := full[k]; ok {
			t.Fatalf("the trust set must not configure a proxy, but sets %s", k)
		}
	}
	for _, k := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"} {
		if full[k] != "/tmp/ca.pem" {
			t.Fatalf("%s must point at the CA, got %q", k, full[k])
		}
	}
	if full["NTCEPT_CONTROL"] != "http://127.0.0.1:4300" {
		t.Fatal("the child must be told where to find its session")
	}
}

// Every variable exists to reach a particular runtime, and doctor prints the reason. One without
// a reason is one nobody can diagnose.
func TestEveryVariableExplainsItself(t *testing.T) {
	for _, v := range Trust("http://c", "/tmp/ca.pem") {
		if v.Why == "" || v.Runt == "" {
			t.Errorf("%s has no explanation (why=%q runtime=%q)", v.Key, v.Why, v.Runt)
		}
		if v.Val == "" {
			t.Errorf("%s has no value", v.Key)
		}
	}
}

// Sessions are how every other command finds a running instance. A stale one must read as
// "nothing is running" with an instruction, not as a session that will then fail to answer.
func TestASessionFromADeadProcessIsNotReported(t *testing.T) {
	t.Setenv("NTCEPT_HOME", t.TempDir())

	if _, err := ResolveSession(""); err == nil {
		t.Fatal("with nothing running, ResolveSession must fail")
	} else if !strings.Contains(err.Error(), "ntcept run") {
		t.Fatalf("the error should say how to start one, got %q", err)
	}

	// A pid that cannot be running.
	if err := WriteSession(Session{Name: "ghost", PID: -1, ProxyPort: 1, ControlPort: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSession(""); err == nil {
		t.Fatal("a session whose process is gone must not be reported as running")
	}
	if _, err := os.Stat(SessionPath("ghost")); err == nil {
		t.Fatal("a stale session file should have been cleaned up")
	}
}

func TestALiveSessionRoundTrips(t *testing.T) {
	t.Setenv("NTCEPT_HOME", t.TempDir())
	want := Session{Name: "api", PID: os.Getpid(), ProxyPort: 8080, ControlPort: 4300, Command: "npm run dev"}
	if err := WriteSession(want); err != nil {
		t.Fatal(err)
	}
	got, err := ResolveSession("")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "api" || got.PID != want.PID || got.Command != want.Command {
		t.Fatalf("session did not round trip: %+v", got)
	}
}

// The regression this whole registry exists for: a second `ntcept run` used to overwrite the
// first, and every command afterwards silently addressed whichever wrote last.
func TestASecondSessionDoesNotDisplaceTheFirst(t *testing.T) {
	t.Setenv("NTCEPT_HOME", t.TempDir())
	for _, name := range []string{"api", "web"} {
		if err := WriteSession(Session{Name: name, PID: os.Getpid(), ControlPort: 1}); err != nil {
			t.Fatal(err)
		}
	}
	sessions, err := ListSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("both sessions should be live, got %d", len(sessions))
	}

	// With more than one, guessing would silently address the wrong application.
	_, err = ResolveSession("")
	if err == nil {
		t.Fatal("an ambiguous session must be an error, not a guess")
	}
	for _, want := range []string{"api", "web", "--session"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error should name %q so the user can act on it: %q", want, err)
		}
	}

	// Named, it resolves.
	got, err := ResolveSession("web")
	if err != nil || got.Name != "web" {
		t.Fatalf("addressing by name failed: %+v %v", got, err)
	}
	if _, err := ResolveSession("nope"); err == nil {
		t.Fatal("an unknown name must be an error")
	}
}

func TestSessionNamesComeFromTheCommand(t *testing.T) {
	t.Setenv("NTCEPT_HOME", t.TempDir())
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"npm", "run", "dev"}, "npm-dev"},
		{[]string{"node", "server.js"}, "node"},
		{[]string{"/usr/bin/curl", "https://example.com"}, "curl"},
		{nil, "ntcept-99"},
	} {
		if got := NameFor(tc.args, 99); got != tc.want {
			t.Errorf("NameFor(%v) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

// Two runs of the same command must not collide, or the second silently takes the first's name.
func TestARepeatedCommandGetsItsOwnName(t *testing.T) {
	t.Setenv("NTCEPT_HOME", t.TempDir())
	first := NameFor([]string{"node", "server.js"}, 1)
	if err := WriteSession(Session{Name: first, PID: os.Getpid()}); err != nil {
		t.Fatal(err)
	}
	second := NameFor([]string{"node", "server.js"}, 2)
	if second == first {
		t.Fatalf("both runs were named %q; the second would overwrite the first", first)
	}
}

func TestCleanNameKeepsItUsableAsAFileAndAWord(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"api", "api"},
		{"my app/v2", "my-app-v2"},
		{"../../etc/passwd", "etc-passwd"},
		{"  spaced  ", "spaced"},
	} {
		if got := CleanName(tc.in); got != tc.want {
			t.Errorf("CleanName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if strings.ContainsAny(CleanName("a/b\\c"), `/\`) {
		t.Fatal("a session name must never contain a path separator")
	}
}

// Ports of 0 mean "pick a free one", and what was picked has to be discoverable — otherwise the
// CLI cannot find the session it just started.
func TestStartPicksFreePortsAndPublishesThem(t *testing.T) {
	t.Setenv("NTCEPT_HOME", t.TempDir())
	rt, err := Start(Options{BufferMB: 4, MaxBodyKB: 64, Name: "under-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Stop()

	if rt.Session.ProxyPort == 0 || rt.Session.ControlPort == 0 {
		t.Fatalf("ports were not resolved: %+v", rt.Session)
	}
	if rt.Session.ProxyPort == rt.Session.ControlPort {
		t.Fatal("the proxy and the control plane cannot share a port")
	}
	s, err := ResolveSession("under-test")
	if err != nil {
		t.Fatalf("the session ntcept just started is not addressable: %v", err)
	}
	if s.ControlPort != rt.Session.ControlPort {
		t.Fatalf("the published session disagrees with the running one: %d vs %d",
			s.ControlPort, rt.Session.ControlPort)
	}
	if !strings.HasSuffix(rt.ControlURL(), itoa(s.ControlPort)) {
		t.Fatalf("the control URL does not name the published port: %s", rt.ControlURL())
	}
}

func TestStopRemovesTheSession(t *testing.T) {
	t.Setenv("NTCEPT_HOME", t.TempDir())
	rt, err := Start(Options{BufferMB: 4, MaxBodyKB: 64, Name: "going-away"})
	if err != nil {
		t.Fatal(err)
	}
	rt.Stop()
	if _, err := os.Stat(SessionPath("going-away")); err == nil {
		t.Fatal("stopping must remove the session file, or the next command targets a dead one")
	}
}

func applyVars(vars []Var) []string { return Apply(nil, vars, nil) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
