package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"
)

// scriptCmd drives the programmable interception layer: load Python that decides what to do with
// intercepted traffic, and reload/reset/inspect it without restarting ntcept.
func scriptCmd(args []string) int {
	sub := "status"
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, rest = args[0], args[1:]
	}
	switch sub {
	case "load":
		return scriptLoad(rest)
	case "reload", "reset", "off":
		return scriptAction(sub, rest)
	case "status":
		return scriptStatus(rest)
	case "logs":
		return scriptLogs(rest)
	default:
		return die("usage: ntcept script <load <file|-> | reload | reset | off | status | logs>")
	}
}

// scriptLoad sends a script by path, from @file, or piped on stdin (-). A bare path is sent as a
// path so it can be watched in place; @file/stdin source is sent inline and persisted server-side.
func scriptLoad(args []string) int {
	fs := flag.NewFlagSet("script load", flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	watch := fs.Bool("watch", false, "reload automatically when the file changes (path loads only)")
	words, rest := takePositionals(args, 1)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	words = append(words, fs.Args()...)
	if len(words) != 1 {
		return die("usage: ntcept script load <file | @file | ->   (- reads stdin)")
	}
	arg := words[0]

	body := map[string]any{"action": "load", "watch": *watch}
	switch {
	case arg == "-" || strings.HasPrefix(arg, "@"):
		b, err := readBodyArg(arg) // reuses the -/@file convention from the verdict commands
		if err != nil {
			return die("%v", err)
		}
		body["source"] = string(b)
	default:
		abs, err := filepath.Abs(arg)
		if err != nil {
			return die("%v", err)
		}
		body["path"] = abs
	}

	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	var res map[string]any
	if err := c.Post("/script", body, &res); err != nil {
		return die("%v", err)
	}
	return emit(*asJSON, res, func() {
		fmt.Println("script loaded")
		fmt.Println("\nInspect it with `ntcept script status` and `ntcept script logs`.")
		fmt.Println("Edit and `ntcept script reload` (keeps state) or `reset` (wipes it).")
	})
}

func scriptAction(action string, args []string) int {
	fs := flag.NewFlagSet("script "+action, flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	var res map[string]any
	if err := c.Post("/script", map[string]any{"action": action}, &res); err != nil {
		return die("%v", err)
	}
	return emit(*asJSON, res, func() { fmt.Printf("script %s\n", action) })
}

func scriptStatus(args []string) int {
	fs := flag.NewFlagSet("script status", flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	var res map[string]any
	if err := c.Get("/script", nil, &res); err != nil {
		return die("%v", err)
	}
	return emit(*asJSON, res, func() {
		if res["available"] != true {
			fmt.Println("scripting unavailable — python3 is not on PATH (`ntcept doctor`)")
			return
		}
		st, _ := res["status"].(map[string]any)
		if st == nil || st["loaded"] != true {
			fmt.Println("no script loaded")
			fmt.Println("\n  ntcept script load rules.py")
			return
		}
		fmt.Printf("loaded:   %v\n", st["path"])
		fmt.Printf("running:  %v\n", st["running"])
		fmt.Printf("calls:    %v\n", num(st["calls"]))
		fmt.Printf("failures: %v\n", num(st["failures"]))
		if v, ok := st["verdicts"].(map[string]any); ok && len(v) > 0 {
			fmt.Printf("verdicts: %v\n", v)
		}
		if e, _ := st["last_error"].(string); e != "" {
			fmt.Printf("last error: %s\n", e)
		}
	})
}

func scriptLogs(args []string) int {
	fs := flag.NewFlagSet("script logs", flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	var res struct {
		Logs  []string `json:"logs"`
		Error string   `json:"error"`
	}
	if err := c.Get("/script/logs", nil, &res); err != nil {
		return die("%v", err)
	}
	if *asJSON {
		return emit(true, res, nil)
	}
	if len(res.Logs) == 0 {
		fmt.Println("no script output yet")
		return 0
	}
	for _, l := range res.Logs {
		fmt.Println(l)
	}
	return 0
}

// num renders a JSON number (float64) without a trailing .0 for display.
func num(v any) string {
	if f, ok := v.(float64); ok {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%v", v)
}
