// Package e2e drives the built binary against a real child process.
//
// Some behaviour only shows up under a real application: request-body capture, CA trust under
// the tunnel attach, whether a pf rule actually routes. The unit tests exercise packages; these
// build the binary and run a real command under it, end to end.
//
// They are skipped under -short.
package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// fakeToken is a credential-shaped fixture the origin returns so redaction can be checked. It is
// assembled from two pieces so the source carries no contiguous secret-shaped literal; the runtime
// value is an ordinary `sk_live_…` string.
const fakeToken = "sk_live" + "_abcdefghij0123456789"

// binary builds ntcept once per run and returns its path.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ntcept-e2e")
		if err != nil {
			buildErr = err
			return
		}
		binPath = filepath.Join(dir, "ntcept")
		cmd := exec.Command("go", "build", "-o", binPath, "./cmd/ntcept")
		cmd.Dir = ".."
		cmd.Dir, buildErr = filepath.Abs("../..")
		if buildErr != nil {
			return
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("building ntcept: %w\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binPath
}

// routableAddr is an address of this machine that is not loopback.
//
// It matters which one is used. Under the tunnel attach, loopback is deliberately left
// undiverted — see internal/pftun/pf_darwin.go — so a test server on 127.0.0.1 would be reached
// without ntcept ever seeing it, and would pass for the wrong reason.
func routableAddr(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.To4() == nil || !n.IP.IsGlobalUnicast() {
			continue
		}
		return n.IP.String()
	}
	t.Skip("this machine has no non-loopback IPv4 address to serve from")
	return ""
}

// origin serves on every interface so it can be reached by whichever address the child uses.
func origin(t *testing.T) (base string, hits func() int) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/fail" {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":"upstream is unwell"}`))
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"id":"ord_4471","token":"` + fakeToken + `"}`))
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return "http://" + net.JoinHostPort(routableAddr(t), port), func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

type run struct {
	stdout, stderr string
	code           int
}

func ntcept(t *testing.T, home string, args ...string) run {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	cmd.Env = append(os.Environ(), "NTCEPT_HOME="+home)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	r := run{stdout: out.String(), stderr: errb.String()}
	var ee *exec.ExitError
	if err != nil {
		if ok := asExitError(err, &ee); ok {
			r.code = ee.ExitCode()
		} else {
			t.Fatalf("running ntcept %v: %v\n%s", args, err, errb.String())
		}
	}
	return r
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

// tunnelReady skips the calling test unless this machine can perform the tunnel — the only attach
// ntcept has. A CI job that exists to cover it sets NTCEPT_E2E_REQUIRE_TUNNEL=1, which turns an
// unavailable tunnel from a skip into a failure, so the job cannot pass for the wrong reason.
func tunnelReady(t *testing.T, home string) {
	t.Helper()
	required := os.Getenv("NTCEPT_E2E_REQUIRE_TUNNEL") == "1"
	var doc struct {
		Checks []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"checks"`
	}
	r := ntcept(t, home, "doctor", "--json")
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		if required {
			t.Fatalf("NTCEPT_E2E_REQUIRE_TUNNEL is set but doctor --json is unreadable: %v", err)
		}
		t.Skipf("doctor --json was not parseable: %v", err)
	}
	for _, c := range doc.Checks {
		if strings.HasPrefix(c.Name, "tunnel attach") && c.OK {
			return
		}
	}
	if required {
		var why string
		for _, c := range doc.Checks {
			if strings.HasPrefix(c.Name, "tunnel attach") {
				why = c.Name
			}
		}
		t.Fatalf("NTCEPT_E2E_REQUIRE_TUNNEL is set but the tunnel attach is unavailable (%s); "+
			"this job exists to cover it", why)
	}
	t.Skip("the tunnel attach is unavailable on this machine")
}

// TestRunCapturesARealChildsTraffic is the claim on the front of the README, checked against a
// process ntcept did not write and cannot influence.
func TestRunCapturesARealChildsTraffic(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is not installed")
	}
	base, hits := origin(t)
	home := t.TempDir()
	tunnelReady(t, home)

	before := hits()
	r := ntcept(t, t.TempDir(), "run", "--",
		"curl", "-sS", "-o", "/dev/null", "-X", "POST",
		"-H", "Authorization: Bearer super-secret-value",
		base+"/orders")

	if r.code != 0 {
		t.Fatalf("the child failed under ntcept (exit %d):\n%s", r.code, r.stderr)
	}
	if hits() != before+1 {
		t.Fatalf("the request did not reach the upstream: %d hits", hits()-before)
	}
	// The summary is printed on stderr when a run ends without --keep. Only the part after the
	// banner is ntcept's own account of what it saw; the banner above it echoes the command line
	// the user typed, credential and all.
	_, summary, ok := strings.Cut(r.stderr, "flow(s) captured")
	if !ok {
		t.Fatalf("nothing was captured:\n%s", r.stderr)
	}
	if !strings.Contains(summary, "POST") || !strings.Contains(summary, "201") {
		t.Fatalf("the captured flow does not describe the request:\n%s", summary)
	}
	if !strings.Contains(summary, "[secret]") {
		t.Fatalf("the credential was not flagged:\n%s", summary)
	}
	if strings.Contains(summary, "super-secret-value") {
		t.Fatalf("the credential reached ntcept's own output in clear:\n%s", summary)
	}
}

// TestTheCLISurfaceAgentsUseWorksEndToEnd covers what the README promises an agent: every
// command takes --json, and a kept session is queryable after the child exits.
func TestTheCLISurfaceAgentsUseWorksEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is not installed")
	}
	base, _ := origin(t)
	home := t.TempDir()
	tunnelReady(t, home)

	// --keep leaves the session up after the child exits, so the CLI has something to query.
	cmd := exec.Command(binary(t), "run", "--keep", "--quiet", "--",
		"curl", "-sS", "-o", "/dev/null", base+"/orders", base+"/fail")
	cmd.Env = append(os.Environ(), "NTCEPT_HOME="+home)
	var errb strings.Builder
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_, _ = cmd.Process.Wait()
	}()

	waitForFlows(t, home, 2)

	var listed struct {
		Flows []struct {
			Method string `json:"method"`
			Status int    `json:"status"`
			Path   string `json:"path"`
			Line   string `json:"line"`
		} `json:"flows"`
	}
	r := ntcept(t, home, "ls", "--json")
	if err := json.Unmarshal([]byte(r.stdout), &listed); err != nil {
		t.Fatalf("ls --json is not parseable: %v\n%s", err, r.stdout)
	}
	if len(listed.Flows) != 2 {
		t.Fatalf("expected two flows, got %d: %s", len(listed.Flows), r.stdout)
	}

	// Filtering is the half an agent actually uses, and it has to happen server-side.
	failing := ntcept(t, home, "ls", "--status", "503", "--json")
	var only struct {
		Flows []map[string]any `json:"flows"`
	}
	if err := json.Unmarshal([]byte(failing.stdout), &only); err != nil {
		t.Fatalf("filtered ls --json is not parseable: %v\n%s", err, failing.stdout)
	}
	if len(only.Flows) != 1 {
		t.Fatalf("--status 503 returned %d flows", len(only.Flows))
	}

	// The detail view must carry the body, which is the point of capturing it.
	shown := ntcept(t, home, "show", "1", "--json")
	var detail map[string]any
	if err := json.Unmarshal([]byte(shown.stdout), &detail); err != nil {
		t.Fatalf("show --json is not parseable: %v\n%s", err, shown.stdout)
	}
	body, _ := detail["res_body"].(string)
	if !strings.Contains(body, "ord_4471") {
		t.Fatalf("the response body is missing from the detail view: %q", body)
	}
	// Redaction is on the way in, so it has to be visible on the way out too.
	if strings.Contains(body, fakeToken) {
		t.Fatalf("a credential in the response body reached the buffer in clear: %q", body)
	}
}

func waitForFlows(t *testing.T, home string, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		r := ntcept(t, home, "ls", "--json")
		var listed struct {
			Flows []map[string]any `json:"flows"`
		}
		if err := json.Unmarshal([]byte(r.stdout), &listed); err == nil && len(listed.Flows) >= n {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("fewer than %d flows after 30s", n)
}

// doctor is what a user is told to run when nothing was captured, so it must not itself fail.
func TestDoctorReportsMeasuredResults(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test")
	}
	home := t.TempDir()
	r := ntcept(t, home, "doctor", "--json")

	var doc struct {
		Platform string `json:"platform"`
		Checks   []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"checks"`
		Runtimes []struct {
			Name  string `json:"runtime"`
			Path  string `json:"path"`
			Trust string `json:"trusts_ca"`
		} `json:"runtimes"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
		t.Fatalf("doctor --json is not parseable: %v\n%s", err, r.stdout)
	}
	if doc.Platform == "" || len(doc.Checks) == 0 {
		t.Fatalf("doctor reported nothing: %s", r.stdout)
	}
	// The CA is created on demand, so this must pass on a machine that has never run ntcept.
	for _, c := range doc.Checks {
		if c.Name == "certificate authority" && !c.OK {
			t.Fatalf("doctor could not establish a CA in a fresh home: %s", r.stdout)
		}
	}
	// Results are measured rather than tabulated, so each runtime must name the binary tested.
	for _, rt := range doc.Runtimes {
		if rt.Path == "" {
			t.Errorf("%s was reported without saying which binary was tested", rt.Name)
		}
		if state := rt.Trust; state != "yes" && state != "no" && state != "unknown" {
			t.Errorf("%s reported an unexpected trust state %q", rt.Name, state)
		}
	}
}

// TestAServerUnderNtceptIsReachableFromTheHost closes the case that made `ntcept run --
// npm run dev` useless on Linux: the command lives in its own network namespace, so a port it
// binds was reachable from nothing at all. macOS never had the problem, because pf only diverts
// egress and the command stays on the host's network.
//
// This is the acceptance test for closing that difference. It is a no-op on macOS by design —
// there is nothing there to publish — and the assertion is the one a user actually makes: start
// a server under ntcept, then open it.
func TestAServerUnderNtceptIsReachableFromTheHost(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test")
	}
	if runtime.GOOS != "linux" {
		t.Skip("only the Linux namespace hides the command's listening sockets")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	home := t.TempDir()
	tunnelReady(t, home)

	port := freePort(t)
	// A server bound to loopback inside the namespace. This is the harder of the two cases and
	// the one most dev servers produce by default; it works because the helper enables
	// route_localnet on the link, so a packet addressed to 127.0.0.1 can arrive over it.
	cmd := exec.Command(binary(t), "run", "--quiet", "--",
		"python3", "-m", "http.server", fmt.Sprint(port), "--bind", "127.0.0.1")
	cmd.Env = append(os.Environ(), "NTCEPT_HOME="+home)
	var errb strings.Builder
	cmd.Stderr = &errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_, _ = cmd.Process.Wait()
	}()

	// Exactly what a browser on this machine does. Nothing was declared: ntcept is expected to
	// have noticed the bind by itself, the way macOS needs no help.
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		res, err := client.Get(url)
		if err == nil {
			defer res.Body.Close()
			if res.StatusCode != 200 {
				t.Fatalf("the published server answered %d", res.StatusCode)
			}
			if !strings.Contains(errb.String(), "published") {
				t.Errorf("the publication should be announced, stderr was:\n%s", errb.String())
			}
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("a server started under ntcept was never reachable at %s\nstderr:\n%s", url, errb.String())
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// linuxTunnelOnly skips a test that only means something where the supervised process has its
// own network namespace.
//
// It also honours NTCEPT_E2E_SKIP_LOOPBACK: loopback interception depends on the host routing
// 127/8 over the link, which hosted CI runners restrict. These tests pass on a real machine and
// are the point of running e2e locally; on a hosted runner they are skipped with a reason rather
// than reported as a product failure.
func linuxTunnelOnly(t *testing.T, home string) {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end test")
	}
	if runtime.GOOS != "linux" {
		t.Skip("only the Linux namespace makes localhost ambiguous")
	}
	if os.Getenv("NTCEPT_E2E_SKIP_LOOPBACK") == "1" {
		t.Skip("loopback capture is not exercised on hosted CI runners; run e2e locally to cover it")
	}
	tunnelReady(t, home)
}

// TestTwoLocalServicesTalkingToEachOtherAreCaptured is the question this was built to answer:
// start a service and something that calls it, both on localhost, and see the traffic between
// them. In a namespace 127.0.0.1 would be a private loopback that reaches nothing; routing it
// over the link hands it to the engine instead, which sends it back in — and records it.
//
// macOS cannot do this at all. pf can divert a loopback packet inwards, but the reply's source
// is 127.0.0.1 on a utun and the host drops it before the process sees it.
func TestTwoLocalServicesTalkingToEachOtherAreCaptured(t *testing.T) {
	home := t.TempDir()
	linuxTunnelOnly(t, home)
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}

	port := freePort(t)
	script := fmt.Sprintf(
		"python3 -m http.server %d --bind 127.0.0.1 >/dev/null 2>&1 & "+
			"for i in 1 2 3 4 5 6 7 8 9 10; do "+
			"  curl -sS -o /dev/null http://127.0.0.1:%d/service-to-service && exit 0; "+
			"  sleep 1; done; exit 1", port, port)

	r := ntcept(t, home, "run", "--quiet", "--", "sh", "-c", script)
	if r.code != 0 {
		t.Fatalf("one local service could not reach another (exit %d):\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "service-to-service") {
		t.Fatalf("traffic between two local services was not captured:\n%s", r.stderr)
	}
}

// TestALocalDatabaseOnTheHostIsReachable is the other half: a service the user started outside
// ntcept, on this machine's loopback — a Postgres, a Redis. The namespace must not hide it.
func TestALocalDatabaseOnTheHostIsReachable(t *testing.T) {
	home := t.TempDir()
	linuxTunnelOnly(t, home)
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl is not installed")
	}

	// Stands in for the database: on the host's loopback, nothing to do with ntcept.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "the service on this machine")
	})}
	go srv.Serve(ln)
	defer srv.Close()

	url := "http://" + ln.Addr().String() + "/on-the-host"
	r := ntcept(t, home, "run", "--quiet", "--",
		"curl", "-sS", "--max-time", "20", "-o", "/dev/null", url)
	if r.code != 0 {
		t.Fatalf("a service on this machine's loopback was unreachable from the namespace "+
			"(exit %d):\n%s", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "on-the-host") {
		t.Fatalf("the call to the host service was not captured:\n%s", r.stderr)
	}
}
