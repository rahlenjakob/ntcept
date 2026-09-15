package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/rahlenjakob/ntcept/internal/attach"
	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/control"
)

// sessionName is which running ntcept a command addresses. A child launched by `ntcept run` is
// told directly through NTCEPT_CONTROL; everyone else names a session, or relies on there being
// exactly one.
var sessionName = os.Getenv("NTCEPT_SESSION")

// addSessionFlag offers --session on any command that talks to a running ntcept.
func addSessionFlag(fs *flag.FlagSet) {
	fs.StringVar(&sessionName, "session", sessionName,
		"which running ntcept to address (see `ntcept sessions`)")
}

func dial() (*control.Client, error) {
	// A process started by `ntcept run` already knows where its own session is, and must not
	// be made ambiguous by other sessions the user happens to be running.
	if base := os.Getenv("NTCEPT_CONTROL"); base != "" {
		return control.NewClient(base), nil
	}
	s, err := attach.ResolveSession(sessionName)
	if err != nil {
		return nil, err
	}
	return control.NewClient("http://127.0.0.1:" + strconv.Itoa(s.ControlPort)), nil
}

// sessionsCmd lists what is running, which is the answer to every "which one?" error above.
func sessionsCmd(args []string) int {
	fs := flag.NewFlagSet("sessions", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sessions, err := attach.ListSessions()
	if err != nil {
		return die("%v", err)
	}
	return emit(*asJSON, map[string]any{"sessions": sessions}, func() {
		if len(sessions) == 0 {
			fmt.Println("no ntcept is running — start one with `ntcept run -- <your app>`")
			return
		}
		for _, s := range sessions {
			fmt.Printf("%-20s pid %-7d proxy :%-6d inspector :%-6d  %s\n",
				s.Name, s.PID, s.ProxyPort, s.ControlPort, s.Command)
		}
	})
}

func emit(asJSON bool, v any, human func()) int {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(v); err != nil {
			return die("%v", err)
		}
		return 0
	}
	human()
	return 0
}

func lsCmd(args []string) int {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	host := fs.String("host", "", "substring match on host")
	path := fs.String("path", "", "substring match on path")
	method := fs.String("method", "", "HTTP method")
	kind := fs.String("kind", "", "http, ws, tcp or udp")
	grep := fs.String("grep", "", "regular expression over headers, bodies and messages")
	status := fs.Int("status", 0, "exact status code")
	limit := fs.Int("limit", 0, "keep only the most recent N")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	q := url.Values{}
	for k, v := range map[string]string{
		"host": *host, "path": *path, "method": *method, "kind": *kind, "grep": *grep,
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if *status > 0 {
		q.Set("status", strconv.Itoa(*status))
	}
	if *limit > 0 {
		q.Set("limit", strconv.Itoa(*limit))
	}

	var out struct {
		Flows []map[string]any `json:"flows"`
	}
	if err := c.Get("/flows", q, &out); err != nil {
		return die("%v", err)
	}
	return emit(*asJSON, out, func() {
		if len(out.Flows) == 0 {
			fmt.Println("no flows captured")
			return
		}
		for _, f := range out.Flows {
			fmt.Println(f["line"])
		}
	})
}

func showCmd(args []string) int {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	full := fs.Bool("full", false, "print whole bodies instead of the first 2 KB")
	ids, rest := takePositionals(args, 1)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	ids = append(ids, fs.Args()...)
	if len(ids) != 1 {
		return die("usage: ntcept show <id>")
	}
	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	var f map[string]any
	if err := c.Get("/flows/"+ids[0], nil, &f); err != nil {
		return die("%v", err)
	}
	return emit(*asJSON, f, func() { renderFlow(f, *full) })
}

func renderFlow(f map[string]any, full bool) {
	str := func(k string) string {
		if v, ok := f[k].(string); ok {
			return v
		}
		return ""
	}
	num := func(k string) int {
		if v, ok := f[k].(float64); ok {
			return int(v)
		}
		return 0
	}
	// Lead with the protocol the decoder settled on for a raw-relay flow (postgres, redis, …)
	// rather than the bare transport; keep the wire protocol (h2, http/1.1) for HTTP.
	label := str("proto")
	if k := str("kind"); k == "tcp" || k == "udp" {
		if p := str("path"); p != "" && p != "raw" {
			label = p
		} else {
			label = k
		}
	}
	fmt.Printf("%s  %s\n", str("id"), label)
	if m := str("method"); m != "" {
		fmt.Printf("%s %s\n", m, str("url"))
	} else {
		fmt.Printf("%s:%d\n", str("host"), num("port"))
	}
	if e := str("error"); e != "" {
		fmt.Printf("error: %s\n", e)
	}
	fmt.Printf("%d ms", num("ms"))
	if d := str("decision"); d != "" {
		fmt.Printf("  · %s", d)
	}
	fmt.Println()

	printHeaders("request", f["req_headers"])
	printBody("request body", str("req_body"), f["req_truncated"] == true, full)
	if s := num("status"); s > 0 {
		fmt.Printf("\n← %d\n", s)
	}
	printHeaders("response", f["res_headers"])
	printBody("response body", str("res_body"), f["res_truncated"] == true, full)

	if msgs, ok := f["messages"].([]any); ok && len(msgs) > 0 {
		fmt.Printf("\nmessages (%d)\n", len(msgs))
		for _, m := range msgs {
			mm, _ := m.(map[string]any)
			arrow := "→"
			if mm["dir"] == "in" {
				arrow = "←"
			}
			text, _ := mm["decoded"].(string)
			if text == "" {
				text, _ = mm["data"].(string)
			}
			// Only websocket frames carry an opcode; tcp segments and datagrams do not.
			opcode, _ := mm["opcode"].(string)
			if opcode != "" {
				opcode = " " + opcode
			}
			fmt.Printf("  %s%-7s %s\n", arrow, opcode, clip(text, full))
		}
	}
}

func printHeaders(label string, v any) {
	h, ok := v.(map[string]any)
	if !ok || len(h) == 0 {
		return
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("\n%s headers\n", label)
	for _, k := range keys {
		vals, _ := h[k].([]any)
		parts := make([]string, 0, len(vals))
		for _, x := range vals {
			parts = append(parts, fmt.Sprint(x))
		}
		fmt.Printf("  %s: %s\n", k, strings.Join(parts, ", "))
	}
}

func printBody(label, body string, truncated, full bool) {
	if body == "" {
		return
	}
	fmt.Printf("\n%s\n%s\n", label, clip(body, full))
	if truncated {
		fmt.Println("  … truncated at the capture ceiling")
	}
}

func clip(s string, full bool) string {
	const limit = 2048
	if full || len(s) <= limit {
		return s
	}
	return s[:limit] + fmt.Sprintf("\n  … %d more bytes (--full to see them)", len(s)-limit)
}

func statusCmd(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	var st map[string]any
	if err := c.Get("/status", nil, &st); err != nil {
		return die("%v", err)
	}
	return emit(*asJSON, st, func() {
		sess, _ := st["session"].(map[string]any)
		fmt.Printf("proxy     http://127.0.0.1:%v\n", sess["proxy_port"])
		fmt.Printf("control   http://127.0.0.1:%v\n", sess["control_port"])
		if cmd, _ := sess["command"].(string); cmd != "" {
			fmt.Printf("running   %s\n", cmd)
		}
		fmt.Printf("flows     %v (%v bytes buffered)\n", st["flows"], st["buffer_bytes"])
		fmt.Printf("held      %v\n", st["held"])
	})
}

func clearCmd(args []string) int {
	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	if err := c.Post("/clear", nil, nil); err != nil {
		return die("%v", err)
	}
	fmt.Println("capture buffer discarded")
	return 0
}

func caCmd(args []string) int {
	authority, err := ca.LoadOrCreate(ca.Home())
	if err != nil {
		return die("%v", err)
	}
	fmt.Println(authority.CertPath())
	fmt.Println()
	fmt.Println("`ntcept run` points a child process at this file through environment variables,")
	fmt.Println("so the machine's own trust store is never modified. Nothing else is required.")
	return 0
}

// flowFromDetail turns a /flows/{id} response back into a Flow, restoring the bodies that are
// carried as printable strings rather than as part of the struct.
func flowFromDetail(raw map[string]any) (*capture.Flow, error) {
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var f capture.Flow
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if s, ok := raw["req_body"].(string); ok {
		f.ReqBody = capture.FromPrintable(s)
	}
	if s, ok := raw["res_body"].(string); ok {
		f.ResBody = capture.FromPrintable(s)
	}
	return &f, nil
}
