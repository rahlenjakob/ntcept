package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/rahlenjakob/ntcept/internal/attach"
	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	proxyPort := fs.Int("proxy-port", 0, "proxy port (0 picks a free one)")
	controlPort := fs.Int("control-port", 0, "control port (0 picks a free one)")
	bufferMB := fs.Int("buffer-mb", 256, "capture buffer ceiling")
	maxBodyKB := fs.Int("max-body-kb", 1024, "per-body capture ceiling")
	keep := fs.Bool("keep", false, "stay up after the command exits, so flows can still be inspected")
	quiet := fs.Bool("quiet", false, "suppress the banner")
	var publish portList
	fs.Var(&publish, "publish", "expose a port the command binds, as 3000 or 8080:3000 (repeatable)")
	noPublish := fs.Bool("no-publish", false, "do not expose ports the command binds")
	name := fs.String("name", "", "name this session, so `ntcept ls --session <name>` can address it")
	var captureLocal portList
	fs.Var(&captureLocal, "capture-local",
		"capture localhost:PORT from the first connection, rather than from the second (repeatable)")
	noCaptureLocal := fs.Bool("no-capture-local", false,
		"do not capture the command's traffic to services on this machine's localhost")
	captureLocalAll := fs.Bool("capture-local-all", false,
		"capture every localhost port, including services that start later; one session only")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	published, err := publish.maps()
	if err != nil {
		return die("%v", err)
	}
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		return die("nothing to run.\n\n  ntcept run -- npm run dev\n  ntcept run -- curl https://api.github.com")
	}

	// ntcept has one attach. A machine that cannot tunnel is told why and refused, rather than
	// silently degraded to a proxy that would miss most of the traffic.
	if ok, why := tunnelAvailable(); !ok {
		return die("ntcept cannot intercept on this machine: %s", why)
	}
	// --publish means the same thing everywhere, and on most platforms it is already true. It
	// is accepted rather than refused so a command line stays portable between machines.
	if len(published) > 0 && !needsPublishing() {
		fmt.Fprintln(os.Stderr, "ntcept: --publish is unnecessary here — the command shares this")
		fmt.Fprintln(os.Stderr, "        machine's network, so a port it binds is already reachable.")
		published = nil
	}

	rt, err := attach.Start(attach.Options{
		ProxyPort: *proxyPort, ControlPort: *controlPort,
		BufferMB: *bufferMB, MaxBodyKB: *maxBodyKB,
		Args: cmdArgs, Name: *name,
	})
	if err != nil {
		return die("%v", err)
	}
	defer rt.Stop()

	if !*quiet {
		banner(rt, cmdArgs, needsLocalCapture() && !*noCaptureLocal)
	}

	localPorts, err := captureLocal.ports()
	if err != nil {
		return die("%v", err)
	}
	if len(localPorts) > 0 && !needsLocalCapture() {
		fmt.Fprintln(os.Stderr, "ntcept: --capture-local is unnecessary here — loopback traffic")
		fmt.Fprintln(os.Stderr, "        is already captured under this attach.")
		localPorts = nil
	}

	code, err := launch(rt, cmdArgs, exposure{
		Publish:         published,
		Auto:            !*noPublish && needsPublishing(),
		CaptureLocal:    localPorts,
		NoCaptureLocal:  *noCaptureLocal,
		CaptureLocalAll: *captureLocalAll,
	})
	if err != nil {
		return die("%v", err)
	}

	if *keep {
		fmt.Fprintf(os.Stderr, "\nntcept: command exited (%d); still capturing. Ctrl-C to stop.\n", code)
		waitForSignal()
		return code
	}
	if !*quiet {
		summary(rt)
	}
	return code
}

// portList collects a repeatable --publish.
type portList []string

func (p *portList) String() string { return strings.Join(*p, ",") }

func (p *portList) Set(v string) error {
	*p = append(*p, v)
	return nil
}

// ports reads the list as bare port numbers, for flags that take a port rather than a mapping.
func (p *portList) ports() ([]int, error) {
	var out []int
	for _, spec := range *p {
		pm, err := tunnel.ParsePublish(spec)
		if err != nil {
			return nil, err
		}
		out = append(out, pm.ChildPort)
	}
	return out, nil
}

func (p *portList) maps() ([]tunnel.PortMap, error) {
	var out []tunnel.PortMap
	for _, spec := range *p {
		pm, err := tunnel.ParsePublish(spec)
		if err != nil {
			return nil, err
		}
		out = append(out, pm)
	}
	return out, nil
}

func banner(rt *attach.Runtime, cmdArgs []string, localCapture bool) {
	authority, _ := ca.LoadOrCreate(ca.Home())
	fmt.Fprintf(os.Stderr, "ntcept\n")
	fmt.Fprintf(os.Stderr, "  session   %s\n", rt.Session.Name)
	fmt.Fprintf(os.Stderr, "  inspector %s\n", rt.ControlURL())
	if authority != nil {
		fmt.Fprintf(os.Stderr, "  ca        %s\n", authority.CertPath())
	}
	if len(cmdArgs) > 0 {
		fmt.Fprintf(os.Stderr, "  running   %s\n", strings.Join(cmdArgs, " "))
	}
	fmt.Fprintf(os.Stderr, "  attach    %s\n", Mechanism())
	fmt.Fprintf(os.Stderr, "            below the socket API, so every language and protocol is covered\n")
	if needsPublishing() {
		// Only Linux needs saying: there the command is off the host's network, and a server it
		// binds is reachable because ntcept publishes it, not by default.
		fmt.Fprintf(os.Stderr, "  ports     published to this machine as the command binds them\n")
	}
	if localCapture {
		fmt.Fprintf(os.Stderr, "  localhost this command's calls to services on this machine are\n")
		fmt.Fprintf(os.Stderr, "            captured too; other processes using them are untouched\n")
	}
	fmt.Fprintf(os.Stderr, "  scope     this process tree only — no trust store, resolver or firewall change\n\n")
}

func summary(rt *attach.Runtime) {
	flows, _ := rt.Store.List(capture.Filter{})
	if len(flows) == 0 {
		fmt.Fprintln(os.Stderr, "\nntcept: no traffic captured.")
		fmt.Fprintln(os.Stderr, "        `ntcept doctor` checks whether this runtime honours the attach.")
		return
	}
	fmt.Fprintf(os.Stderr, "\nntcept: %d flow(s) captured\n", len(flows))
	for _, f := range flows {
		fmt.Fprintf(os.Stderr, "  %s\n", f.Line())
	}
	fmt.Fprintln(os.Stderr, "\n  Re-run with --keep to inspect them with `ntcept ls` / `ntcept show`.")
}

func waitForSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	fmt.Fprintln(os.Stderr, "\nntcept: stopped. Capture buffer discarded.")
}
