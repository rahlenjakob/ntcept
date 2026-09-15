// Package pftun is the macOS attach. It creates a utun device, tells pf to route one process
// group's outbound traffic into it, and hands the packets to the shared tunnel engine.
//
// Scoping is the point: pf matches on the supervised process's group id, so only the command
// ntcept launched is diverted. Every other process on the machine — the browser, other terminals,
// the VPN — is untouched. The pf anchor is flushed and the utun destroyed when ntcept exits.
package pftun

import (
	"errors"
	"io"

	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/proxy"
)

// Options is declared here, not beside the darwin implementation, so there is one definition
// rather than one per build tag.
type Options struct {
	Args     []string
	Proxy    *proxy.Server
	Store    *capture.Store
	Resolver string
	Env      []string // the child's environment; nil means inherit ntcept's

	// CaptureLocal pre-arms loopback ports, so that even the first connection to one is
	// captured. It is rarely needed: ntcept discovers what the application talks to as it runs.
	CaptureLocal []int
	// NoCaptureLocal turns loopback capture off entirely.
	NoCaptureLocal bool
	// CaptureLocalAll asks for one redirect covering every loopback port rather than one per
	// port the application is seen to use. It captures the first connection to a service that
	// starts after ntcept, and it cannot be shared: pf cannot scope a redirect to a process, so
	// a second session running at the same time would lose its own view of localhost.
	CaptureLocalAll bool
	// Out is where the redirect is announced. nil means os.Stderr.
	Out io.Writer
}

// ErrUnsupported is returned on platforms that are not macOS.
var ErrUnsupported = errors.New("the pf attach is macOS-only")

const (
	// AnchorPrefix lives under com.apple/* because that is the only anchor point the stock
	// /etc/pf.conf already evaluates. Using it means ntcept never edits /etc/pf.conf. Each
	// session appends its own marker group, so no two sessions share an anchor.
	AnchorPrefix = "com.apple/ntcept"

	// Anchor is the prefix as a glob, for cleaning up after crashed runs.
	Anchor = AnchorPrefix

	// HelperPath is the root-owned copy `ntcept install` places, and the exact path the
	// sudoers drop-in authorises. Pinning the path is what keeps the grant narrow.
	HelperPath  = "/usr/local/libexec/ntcept-helper"
	SudoersPath = "/etc/sudoers.d/ntcept"

	// HelperArg re-enters the binary in privileged mode. It is never invoked by a user.
	HelperArg = "__mac-helper"

	// HelperProtocol is the contract between ntcept and its installed helper: the argv shape and
	// the socket handshake. Compatibility is judged on this rather than on the helper's bytes, so
	// rebuilding ntcept does not invalidate the install — only changing the contract does. Bump
	// it whenever the argv or handshake changes, so `ntcept doctor` can tell the user to
	// reinstall instead of failing obscurely.
	HelperProtocol = 1
)
