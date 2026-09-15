package pftun

// handover is what ntcept passes to the privileged helper once the packet stack is attached.
//
// It travels over the unix socket rather than the process environment because sudo resets the
// environment by default and overrides PATH with secure_path. Inheriting that would hand the
// supervised command a sanitised environment — the wrong PATH, the wrong HOME, none of its own
// configuration — which would break most real applications.
type handover struct {
	Env []string `json:"env"`
	Dir string   `json:"dir"`

	// CaptureLocal maps a port on loopback that the application talks to onto the port ntcept
	// is listening on for it. It travels here rather than in argv so that adding it needed no
	// change to the helper's command line.
	CaptureLocal map[int]int `json:"capture_local,omitempty"`

	// CatchAll, when set, replaces the per-port redirects with a single rule sending every
	// loopback port to this one. It is only ever set once ntcept has proved it can recover the
	// original destination, because without that a redirected connection cannot be forwarded.
	CatchAll int `json:"catch_all,omitempty"`

	// Start tells the helper the interception is fully set up and the command may run. It is
	// what keeps the two apart: pf rules are decided, probed and installed while there is no
	// application yet, so nothing it does can be disturbed by installing them.
	Start bool `json:"start,omitempty"`

	// Natlook asks the helper what a redirected connection was originally aimed at.
	//
	// It goes to the helper rather than being done in ntcept because XNU refuses DIOCNATLOOK
	// from an unprivileged process — measured: "operation not permitted" — even when handed a
	// /dev/pf descriptor that root opened. The check is on the caller's credentials, not the
	// descriptor's, so the lookup has to happen on this side of the privilege line.
	Natlook *NatlookReq `json:"natlook,omitempty"`
}

// NatlookReq is one question about a redirected connection: who connected, and to which local
// socket it arrived on.
type NatlookReq struct {
	SrcIP   string `json:"src_ip"`
	SrcPort int    `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort int    `json:"dst_port"`
}

// Tuple lets the lookup be performed without pfnat importing this package.
func (r *NatlookReq) Tuple() (string, int, string, int) {
	return r.SrcIP, r.SrcPort, r.DstIP, r.DstPort
}

// NatlookReply is what pf said the connection was originally aimed at.
type NatlookReply struct {
	OK   bool   `json:"ok"`
	IP   string `json:"ip,omitempty"`
	Port int    `json:"port,omitempty"`
	Err  string `json:"err,omitempty"`
}
