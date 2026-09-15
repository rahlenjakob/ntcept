package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rahlenjakob/ntcept/internal/capture"
)

// interceptCmd arms or disarms holding. Nothing is held until this is on, so an unattended run
// can never stall waiting for a verdict nobody is going to give.
func interceptCmd(args []string) int {
	fs := flag.NewFlagSet("intercept", flag.ContinueOnError)
	addSessionFlag(fs)
	requests := fs.Bool("requests", true, "hold outbound requests before they are sent (the default)")
	responses := fs.Bool("responses", true, "hold responses before the application sees them")
	holdMS := fs.Int64("hold-ms", 0, "how long to wait for a verdict before giving up (0 keeps the current value)")
	asJSON := fs.Bool("json", false, "machine-readable output")
	words, rest := takePositionals(args, 1)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	words = append(words, fs.Args()...)
	state := "on"
	if len(words) > 0 {
		state = words[0]
	}
	if state != "on" && state != "off" {
		return die("usage: ntcept intercept on|off [--requests] [--responses] [--hold-ms N]")
	}

	// Distinguish "not mentioned" from "set to its default", so `intercept on --responses`
	// holds responses only rather than silently arming requests as well.
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })

	body := map[string]any{}
	switch {
	case state == "off":
		body["hold_requests"], body["hold_responses"] = false, false
	case !given["requests"] && !given["responses"]:
		body["hold_requests"], body["hold_responses"] = true, false
	default:
		body["hold_requests"] = given["requests"] && *requests
		body["hold_responses"] = given["responses"] && *responses
	}
	if *holdMS > 0 {
		body["hold_ms"] = *holdMS
	}

	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	var st map[string]any
	if err := c.Post("/mode", body, &st); err != nil {
		return die("%v", err)
	}
	return emit(*asJSON, st, func() {
		fmt.Printf("holding requests:  %v\n", st["hold_requests"])
		fmt.Printf("holding responses: %v\n", st["hold_responses"])
		fmt.Printf("hold budget:       %vms\n", st["hold_ms"])
		if st["hold_requests"] == true || st["hold_responses"] == true {
			fmt.Println("\nHeld exchanges appear in `ntcept queue` and in the inspector.")
			fmt.Println("Answer them with forward / drop / respond / edit, or they time out.")
		}
	})
}

func queueCmd(args []string) int {
	fs := flag.NewFlagSet("queue", flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	full := fs.Bool("full", false, "print whole bodies")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	var out struct {
		Held []*capture.Held `json:"held"`
	}
	if err := c.Get("/queue", nil, &out); err != nil {
		return die("%v", err)
	}
	return emit(*asJSON, out, func() {
		if len(out.Held) == 0 {
			fmt.Println("nothing held")
			fmt.Println("\n`ntcept intercept on` arms holding.")
			return
		}
		for _, h := range out.Held {
			// A database/TCP message reads by its protocol and decoded text, not method and URL.
			if h.Kind == capture.KindTCP {
				dir := "request"
				if h.Dir == capture.In {
					dir = "response"
				}
				fmt.Printf("%s  %s %s  held %s\n", h.ID, h.Proto, dir, time.Since(h.At).Truncate(time.Second))
				fmt.Printf("  %s\n", h.Text)
				fmt.Println()
				continue
			}
			fmt.Printf("%s  %s  held %s\n", h.ID, h.Stage, time.Since(h.At).Truncate(time.Second))
			if h.Stage == capture.StageRequest {
				fmt.Printf("  %s %s\n", h.Method, h.URL)
			} else {
				// A response is not worth judging without the request that caused it.
				fmt.Printf("  %d for %s %s\n", h.Status, h.Method, h.URL)
				if len(h.ReqHeaders) > 0 || h.ReqBody != "" {
					fmt.Println("  --- sent ---")
					printHeaderMap(h.ReqHeaders)
					if h.ReqBody != "" {
						fmt.Printf("    %s\n", strings.ReplaceAll(clip(h.ReqBody, *full), "\n", "\n    "))
					}
					fmt.Println("  --- received ---")
				}
			}
			printHeaderMap(h.Headers)
			if h.Body != "" {
				fmt.Printf("  body\n    %s\n", strings.ReplaceAll(clip(h.Body, *full), "\n", "\n    "))
			}
			fmt.Println()
		}
	})
}

func printHeaderMap(h http.Header) {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %s: %s\n", k, strings.Join(h[k], ", "))
	}
}

type kvFlag []string

func (k *kvFlag) String() string { return strings.Join(*k, ", ") }
func (k *kvFlag) Set(v string) error {
	*k = append(*k, v)
	return nil
}

// verdictCmd answers one held exchange.
func verdictCmd(action capture.Action) func([]string) int {
	return func(args []string) int {
		fs := flag.NewFlagSet(string(action), flag.ContinueOnError)
		addSessionFlag(fs)
		status := fs.Int("status", 0, "status code to send")
		bodyArg := fs.String("body", "", "replacement body; @file reads a file, - reads stdin")
		method := fs.String("method", "", "replacement method")
		target := fs.String("url", "", "replacement URL")
		// Database/TCP holds: rewrite a message's wire bytes, or answer a request with an error.
		sqlArg := fs.String("sql", "", "replacement SQL for a held query; rebuilds the message (edit)")
		rawArg := fs.String("set-raw", "", "replacement wire bytes for a database/TCP message; @file or - (edit)")
		pgError := fs.String("pg-error", "", "answer a held Postgres request with an error, `SQLSTATE: message` (respond)")
		var set kvFlag
		var del kvFlag
		fs.Var(&set, "set-header", "set a header, Name: value (repeatable)")
		fs.Var(&del, "remove-header", "remove a header by name (repeatable)")
		ids, rest := takePositionals(args, 1)
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		ids = append(ids, fs.Args()...)
		if len(ids) != 1 {
			return die("usage: ntcept %s <held-id>   (ids come from `ntcept queue`)", action)
		}

		v := capture.Verdict{Action: action, Status: *status, Method: *method, URL: *target}
		if len(set) > 0 {
			v.SetHeaders = map[string]string{}
			for _, h := range set {
				k, val, ok := strings.Cut(h, ":")
				if !ok {
					return die("--set-header wants Name: value, got %q", h)
				}
				v.SetHeaders[strings.TrimSpace(k)] = strings.TrimSpace(val)
			}
		}
		v.RemoveHeaders = del
		if *bodyArg != "" {
			b, err := readBodyArg(*bodyArg)
			if err != nil {
				return die("%v", err)
			}
			s := string(b)
			v.Body = &s
		}
		if *sqlArg != "" {
			s := *sqlArg
			v.SQL = &s
		}
		if *rawArg != "" {
			b, err := readBodyArg(*rawArg)
			if err != nil {
				return die("%v", err)
			}
			s := capture.Printable(b)
			v.Raw = &s
		}
		if *pgError != "" {
			v.Error = parsePGError(*pgError)
		}

		c, err := dial()
		if err != nil {
			return die("%v", err)
		}
		var res map[string]any
		if err := c.Post("/queue/"+ids[0], v, &res); err != nil {
			return die("%v", err)
		}
		fmt.Printf("%s %s\n", ids[0], action)
		return 0
	}
}

// parsePGError reads a `SQLSTATE: message` argument into an error to answer a held request with.
// A bare message (no colon, or no five-character SQLSTATE) is taken as the message alone.
func parsePGError(arg string) *capture.ProtoError {
	if code, msg, ok := strings.Cut(arg, ":"); ok {
		code = strings.TrimSpace(code)
		if len(code) == 5 {
			return &capture.ProtoError{Code: code, Message: strings.TrimSpace(msg)}
		}
	}
	return &capture.ProtoError{Message: strings.TrimSpace(arg)}
}

func readBodyArg(arg string) ([]byte, error) {
	switch {
	case arg == "-":
		return readAll(os.Stdin)
	case strings.HasPrefix(arg, "@"):
		return os.ReadFile(strings.TrimPrefix(arg, "@"))
	default:
		return []byte(arg), nil
	}
}

func readAll(f *os.File) ([]byte, error) {
	var b []byte
	buf := make([]byte, 32*1024)
	for {
		n, err := f.Read(buf)
		b = append(b, buf[:n]...)
		if err != nil {
			return b, nil
		}
	}
}

var _ = json.Marshal
