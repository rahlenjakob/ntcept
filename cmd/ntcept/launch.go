package main

import (
	"os"
	"runtime"

	"github.com/rahlenjakob/ntcept/internal/attach"
	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/netns"
	"github.com/rahlenjakob/ntcept/internal/pftun"
	"github.com/rahlenjakob/ntcept/internal/tunnel"
)

// ntcept has one attach: the tunnel, below the socket API — a network namespace on Linux, a utun
// that pf steers into on macOS. It covers every language and every protocol and needs no
// cooperation from the runtime.
//
// There is deliberately no proxy-variable fallback. A machine that cannot tunnel fails loudly,
// because the alternative — quietly capturing only the runtimes that honour proxy variables, and
// nothing of raw TCP, UDP or DNS — surfaces as an empty capture buffer that reads as "the program
// made no requests" rather than "ntcept could not see them".

// Mechanism names what the tunnel actually does on this platform.
func Mechanism() string {
	if runtime.GOOS == "darwin" {
		return "utun + pf, scoped to the command's group"
	}
	return "network namespace, scoped to the process tree"
}

// tunnelAvailable reports whether this machine can intercept below the socket API, and why not
// when it cannot. `ntcept run` refuses to start rather than degrade.
func tunnelAvailable() (bool, string) {
	switch runtime.GOOS {
	case "linux":
		if netns.Available() {
			return true, ""
		}
		if _, err := os.Stat("/dev/net/tun"); err != nil {
			return false, "/dev/net/tun is not present"
		}
		return false, "unprivileged user namespaces are disabled on this kernel; try sudo"
	case "darwin":
		return pftun.Available()
	}
	return false, runtime.GOOS + " has no below-the-socket attach"
}

// needsPublishing reports whether a port the command binds has to be forwarded to be reachable
// from this machine. Only the Linux namespace hides the command's listening sockets; pf on macOS
// diverts egress only and leaves the command on the host's network.
func needsPublishing() bool {
	return runtime.GOOS == "linux"
}

// needsLocalCapture reports whether loopback traffic has to be redirected to be seen. Only macOS
// needs it: there the command shares the machine's network, so its loopback never reaches the
// tunnel; on Linux 127.0.0.0/8 is routed over the link and captured without anyone asking.
func needsLocalCapture() bool {
	return runtime.GOOS == "darwin"
}

// exposure is what should be reachable from this machine while the command runs.
type exposure struct {
	Publish         []tunnel.PortMap
	Auto            bool
	CaptureLocal    []int
	NoCaptureLocal  bool
	CaptureLocalAll bool
}

// launch runs the command under the tunnel and returns its exit code.
func launch(rt *attach.Runtime, args []string, expose exposure) (int, error) {
	// Routing a process's packets through ntcept does not make it trust the certificate ntcept
	// presents. Without these, TLS interception fails closed and the app sees a verification
	// error rather than its response.
	authority, err := ca.LoadOrCreate(ca.Home())
	if err != nil {
		return 1, err
	}
	env := attach.Apply(os.Environ(), attach.Trust(rt.ControlURL(), authority.CertPath()), nil)

	resolver := netns.HostResolver()
	if runtime.GOOS == "darwin" {
		return pftun.Launch(pftun.Options{
			Args: args, Proxy: rt.Proxy, Store: rt.Store, Resolver: resolver, Env: env,
			CaptureLocal: expose.CaptureLocal, NoCaptureLocal: expose.NoCaptureLocal,
			CaptureLocalAll: expose.CaptureLocalAll, Out: os.Stderr,
		})
	}
	return netns.Launch(netns.Options{
		Args: args, Proxy: rt.Proxy, Store: rt.Store, Resolver: resolver, Env: env,
		Publish: expose.Publish, AutoPublish: expose.Auto, Out: os.Stderr,
	})
}
