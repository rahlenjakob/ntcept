package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/rahlenjakob/ntcept/internal/capture"
)

// diffCmd compares two flows. The usual question during debugging is "what is different about
// the one that failed", and answering it by eye across two `show` outputs is miserable.
func diffCmd(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	ids, rest := takePositionals(args, 2)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	ids = append(ids, fs.Args()...)
	if len(ids) != 2 {
		return die("usage: ntcept diff <id-a> <id-b>")
	}
	a, err := fetchFlow(ids[0])
	if err != nil {
		return die("%v", err)
	}
	b, err := fetchFlow(ids[1])
	if err != nil {
		return die("%v", err)
	}

	d := map[string]any{}
	addScalar(d, "method", a.Method, b.Method)
	addScalar(d, "url", a.URL, b.URL)
	addScalar(d, "status", fmt.Sprint(a.Status), fmt.Sprint(b.Status))
	addScalar(d, "proto", string(a.Proto), string(b.Proto))
	d["request_headers"] = diffHeaders(a.ReqHdr, b.ReqHdr)
	d["response_headers"] = diffHeaders(a.ResHdr, b.ResHdr)
	d["request_body"] = diffBody(a.ReqBody, b.ReqBody)
	d["response_body"] = diffBody(a.ResBody, b.ResBody)

	return emit(*asJSON, d, func() { renderDiff(a, b, d) })
}

func addScalar(d map[string]any, name, x, y string) {
	if x != y {
		d[name] = map[string]string{"a": x, "b": y}
	}
}

type headerDelta struct {
	OnlyInA map[string]string   `json:"only_in_a,omitempty"`
	OnlyInB map[string]string   `json:"only_in_b,omitempty"`
	Changed map[string][]string `json:"changed,omitempty"`
}

func diffHeaders(a, b http.Header) headerDelta {
	d := headerDelta{OnlyInA: map[string]string{}, OnlyInB: map[string]string{}, Changed: map[string][]string{}}
	for k, av := range a {
		bv, ok := b[k]
		switch {
		case !ok:
			d.OnlyInA[k] = strings.Join(av, ", ")
		case strings.Join(av, ",") != strings.Join(bv, ","):
			d.Changed[k] = []string{strings.Join(av, ", "), strings.Join(bv, ", ")}
		}
	}
	for k, bv := range b {
		if _, ok := a[k]; !ok {
			d.OnlyInB[k] = strings.Join(bv, ", ")
		}
	}
	return d
}

// diffBody compares JSON structurally when it can, because a reordered object is not a change.
func diffBody(a, b []byte) map[string]any {
	if string(a) == string(b) {
		return nil
	}
	var ja, jb any
	if json.Unmarshal(a, &ja) == nil && json.Unmarshal(b, &jb) == nil {
		paths := map[string][]any{}
		walkDiff("", ja, jb, paths)
		if len(paths) == 0 {
			return nil
		}
		out := map[string]any{}
		for k, v := range paths {
			out[k] = map[string]any{"a": v[0], "b": v[1]}
		}
		return map[string]any{"json": out}
	}
	return map[string]any{"a_bytes": len(a), "b_bytes": len(b), "text_differs": true}
}

func walkDiff(path string, a, b any, out map[string][]any) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		for k := range keys {
			walkDiff(path+"/"+k, am[k], bm[k], out)
		}
		return
	}
	if fmt.Sprint(a) != fmt.Sprint(b) {
		out[path] = []any{a, b}
	}
}

func renderDiff(a, b *capture.Flow, d map[string]any) {
	fmt.Printf("a  %s\nb  %s\n", a.Line(), b.Line())
	printed := false
	for _, name := range []string{"method", "url", "status", "proto"} {
		if v, ok := d[name].(map[string]string); ok {
			fmt.Printf("\n%s\n  a: %s\n  b: %s\n", name, v["a"], v["b"])
			printed = true
		}
	}
	for _, name := range []string{"request_headers", "response_headers"} {
		hd, _ := d[name].(headerDelta)
		if len(hd.OnlyInA) == 0 && len(hd.OnlyInB) == 0 && len(hd.Changed) == 0 {
			continue
		}
		printed = true
		fmt.Printf("\n%s\n", strings.ReplaceAll(name, "_", " "))
		for _, k := range sortedKeys(hd.OnlyInA) {
			fmt.Printf("  - %s: %s\n", k, hd.OnlyInA[k])
		}
		for _, k := range sortedKeys(hd.OnlyInB) {
			fmt.Printf("  + %s: %s\n", k, hd.OnlyInB[k])
		}
		for k, v := range hd.Changed {
			fmt.Printf("  ~ %s\n      a: %s\n      b: %s\n", k, v[0], v[1])
		}
	}
	for _, name := range []string{"request_body", "response_body"} {
		body, _ := d[name].(map[string]any)
		if body == nil {
			continue
		}
		printed = true
		fmt.Printf("\n%s\n", strings.ReplaceAll(name, "_", " "))
		if js, ok := body["json"].(map[string]any); ok {
			for _, k := range sortedAny(js) {
				v := js[k].(map[string]any)
				fmt.Printf("  ~ %s\n      a: %v\n      b: %v\n", k, v["a"], v["b"])
			}
		} else {
			fmt.Printf("  bodies differ (%v vs %v bytes, not both JSON)\n", body["a_bytes"], body["b_bytes"])
		}
	}
	if !printed {
		fmt.Println("\nidentical in every compared dimension")
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedAny(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
