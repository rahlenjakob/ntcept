package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/control"
)

// followCmd tails the live stream. Agents use it to watch a run rather than poll it.
func followCmd(args []string) int {
	fs := flag.NewFlagSet("follow", flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "emit one JSON object per line")
	host := fs.String("host", "", "substring match on host")
	path := fs.String("path", "", "substring match on path")
	status := fs.Int("status", 0, "exact status code")
	errorsOnly := fs.Bool("errors", false, "only failures: transport errors and 4xx/5xx")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := dial()
	if err != nil {
		return die("%v", err)
	}
	match := func(f *capture.Flow) bool {
		return flowMatches(f, *host, *path, *status, *errorsOnly)
	}
	return stream(c, func(e capture.Event) {
		if e.Type != capture.EventFlowDone || e.Flow == nil || !match(e.Flow) {
			return
		}
		if *asJSON {
			b, _ := json.Marshal(e.Flow)
			fmt.Println(string(b))
			return
		}
		fmt.Println(e.Flow.Line())
	})
}

// waitCmd blocks until a matching flow completes, so an agent can synchronise with the app it is
// driving instead of sleeping and hoping.
func waitCmd(args []string) int {
	fs := flag.NewFlagSet("wait", flag.ContinueOnError)
	addSessionFlag(fs)
	asJSON := fs.Bool("json", false, "machine-readable output")
	host := fs.String("host", "", "substring match on host")
	path := fs.String("path", "", "substring match on path")
	status := fs.Int("status", 0, "exact status code")
	errorsOnly := fs.Bool("errors", false, "wait for the next failure")
	count := fs.Int("count", 1, "how many matching flows to wait for")
	timeout := fs.Duration("timeout", 60*time.Second, "give up after this long")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := dial()
	if err != nil {
		return die("%v", err)
	}

	// Anything already captured counts, so a race between starting the app and starting the
	// wait does not hang.
	q := url.Values{}
	if *host != "" {
		q.Set("host", *host)
	}
	if *path != "" {
		q.Set("path", *path)
	}
	if *status > 0 {
		q.Set("status", strconv.Itoa(*status))
	}
	var seen struct {
		Flows []*capture.Flow `json:"flows"`
	}
	_ = c.Get("/flows", q, &seen)
	var hits []*capture.Flow
	for _, f := range seen.Flows {
		if f.Done && flowMatches(f, *host, *path, *status, *errorsOnly) {
			hits = append(hits, f)
		}
	}
	if len(hits) >= *count {
		return reportWait(hits[len(hits)-*count:], *asJSON)
	}

	done := make(chan []*capture.Flow, 1)
	go func() {
		_ = stream(c, func(e capture.Event) {
			if e.Type != capture.EventFlowDone || e.Flow == nil {
				return
			}
			if !flowMatches(e.Flow, *host, *path, *status, *errorsOnly) {
				return
			}
			hits = append(hits, e.Flow)
			if len(hits) >= *count {
				select {
				case done <- hits:
				default:
				}
			}
		})
	}()

	select {
	case got := <-done:
		return reportWait(got, *asJSON)
	case <-time.After(*timeout):
		fmt.Fprintf(os.Stderr, "ntcept: timed out after %s waiting for %d matching flow(s); saw %d\n",
			*timeout, *count, len(hits))
		return 3
	}
}

func reportWait(flows []*capture.Flow, asJSON bool) int {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"flows": flows})
		return 0
	}
	for _, f := range flows {
		fmt.Println(f.Line())
	}
	return 0
}

func flowMatches(f *capture.Flow, host, path string, status int, errorsOnly bool) bool {
	if host != "" && !strings.Contains(strings.ToLower(f.Host), strings.ToLower(host)) {
		return false
	}
	if path != "" && !strings.Contains(f.Path, path) {
		return false
	}
	if status > 0 && f.Status != status {
		return false
	}
	if errorsOnly && f.Error == "" && f.Status < 400 {
		return false
	}
	return true
}

// stream consumes the control plane's SSE endpoint.
func stream(c *control.Client, onEvent func(capture.Event)) int {
	body, err := c.Stream("/events")
	if err != nil {
		return die("%v", err)
	}
	defer body.Close()
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var e capture.Event
		if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e); err != nil {
			continue
		}
		onEvent(e)
	}
	return 0
}
