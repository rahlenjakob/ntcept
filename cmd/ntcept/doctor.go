package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/rahlenjakob/ntcept/internal/attach"
	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/pftun"
	"github.com/rahlenjakob/ntcept/internal/probe"
)

type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

// doctorCmd verifies the chain rather than the existence of config files: whether this machine
// can tunnel, and which runtimes will trust ntcept's certificate once it does.
func doctorCmd(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var checks []check
	add := func(name string, ok bool, detail, fix string) {
		checks = append(checks, check{name, ok, detail, fix})
	}

	authority, err := ca.LoadOrCreate(ca.Home())
	if err != nil {
		add("certificate authority", false, err.Error(), "check permissions on "+ca.Home())
	} else {
		add("certificate authority", true, authority.CertPath(), "")
	}

	ok, why := tunnelAvailable()
	add("tunnel attach ("+Mechanism()+")", ok, why, tunnelFix(ok))

	switch runtime.GOOS {
	case "darwin":
		_, perr := exec.LookPath("pfctl")
		add("pfctl present", perr == nil, "", "pfctl ships with macOS; check PATH")
		setupOK, setupWhy := pftun.InstallState()
		if setupOK {
			setupWhy = "ntcept run needs no password"
		}
		add("one-time setup done", setupOK, setupWhy, "sudo ntcept install")
	case "linux":
		_, terr := os.Stat("/dev/net/tun")
		add("/dev/net/tun", terr == nil, "",
			"load the tun module, or pass --device /dev/net/tun to your container runtime")
	}

	if sessions, err := attach.ListSessions(); err == nil && len(sessions) > 0 {
		for _, s := range sessions {
			add("session "+s.Name, true,
				fmt.Sprintf("pid %d, proxy :%d, inspector :%d", s.PID, s.ProxyPort, s.ControlPort), "")
		}
	} else {
		add("session running", false, attach.ErrNoSession.Error(), "ntcept run -- <your app>")
	}

	// Whether a runtime trusts ntcept's CA cannot be known without trying: a runtime can report
	// SSL_CERT_FILE in its verify paths and still ignore it. Every runtime installed here is
	// driven through a real TLS handshake, entirely on loopback. Trust is what the tunnel needs;
	// a runtime that pins its own roots stays an opaque passthrough rather than breaking.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	results, perr := probe.Run(ctx)
	if perr != nil {
		add("runtime trust probe", false, perr.Error(), "")
	}
	for _, r := range results {
		add(fmt.Sprintf("%s · trusts ntcept's certificate", r.Name), r.Trust == probe.Yes,
			r.Path+" — "+r.TrustDetail,
			"this runtime pins its own roots; ntcept records its TLS as an opaque passthrough")
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"checks": checks, "runtimes": results, "platform": runtime.GOOS})
		return failed(checks)
	}

	fmt.Printf("ntcept doctor — %s\n\n", runtime.GOOS)
	for _, c := range checks {
		mark := "✗"
		if c.OK {
			mark = "✓"
		}
		fmt.Printf("  %s %s", mark, c.Name)
		if c.Detail != "" {
			fmt.Printf("  — %s", c.Detail)
		}
		fmt.Println()
		if !c.OK && c.Fix != "" {
			fmt.Printf("      %s\n", c.Fix)
		}
	}
	fmt.Println("\nRuntime trust is measured, not assumed. The tunnel intercepts everything below")
	fmt.Println("the socket API regardless; trust is only what lets ntcept read a runtime's TLS")
	fmt.Println("rather than record it as an opaque passthrough.")
	return failed(checks)
}

// failed ignores checks that are informational rather than broken. A runtime that pins its own
// roots is a fact about that runtime, not a fault in this machine's setup.
func failed(checks []check) int {
	for _, c := range checks {
		if c.OK || c.Name == "session running" || strings.Contains(c.Name, "trusts ntcept") {
			continue
		}
		return 1
	}
	return 0
}

func tunnelFix(ok bool) string {
	if ok {
		return ""
	}
	if runtime.GOOS == "darwin" {
		return "run `sudo ntcept install` once — after that `ntcept run` needs no password"
	}
	return "run with sudo, or enable unprivileged user namespaces"
}
