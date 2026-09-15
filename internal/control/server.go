// Package control is the local API the CLI and web UI talk to. It binds loopback only: the
// capture buffer holds credentials for every service the app under test calls.
package control

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/proxy"
	"github.com/rahlenjakob/ntcept/internal/ui"
)

type Server struct {
	Store *capture.Store
	Proxy *proxy.Server
	Info  SessionInfo
}

type SessionInfo struct {
	Name        string    `json:"name"`
	PID         int       `json:"pid"`
	ProxyPort   int       `json:"proxy_port"`
	ControlPort int       `json:"control_port"`
	Started     time.Time `json:"started"`
	Command     string    `json:"command,omitempty"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", s.status)
	mux.HandleFunc("GET /flows", s.flows)
	mux.HandleFunc("GET /flows/{id}", s.flow)
	mux.HandleFunc("GET /events", s.events)
	mux.HandleFunc("GET /queue", s.queue)
	mux.HandleFunc("POST /queue/{id}", s.release)
	mux.HandleFunc("POST /mode", s.mode)
	mux.HandleFunc("POST /clear", s.clear)
	mux.HandleFunc("GET /script", s.scriptStatus)
	mux.HandleFunc("POST /script", s.scriptControl)
	mux.HandleFunc("GET /script/logs", s.scriptLogs)
	mux.Handle("GET /", ui.Handler())
	return loopbackOnly(mux)
}

// loopbackOnly refuses non-loopback peers even if something upstream managed to route to us.
func loopbackOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			http.Error(w, "ntcept control plane is loopback only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func fail(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	count, bytes, seq := s.Store.Stats()
	writeJSON(w, 200, map[string]any{
		"session":        s.Info,
		"flows":          count,
		"buffer_bytes":   bytes,
		"seq":            seq,
		"held":           s.Proxy.Queue.Len(),
		"hold_requests":  s.Proxy.HoldRequests.Load(),
		"hold_responses": s.Proxy.HoldResponses.Load(),
		"hold_ms":        s.Proxy.HoldMS.Load(),
		"offline":        s.Proxy.Offline.Load(),
		"script":         s.scriptInfo(),
	})
}

// scriptInfo is the compact scripting state carried in /status, so the UI can show that a script is
// in control and disable the manual hold toggles it would otherwise override.
func (s *Server) scriptInfo() map[string]any {
	if s.Proxy.Script == nil {
		return map[string]any{"available": false, "loaded": false}
	}
	st := s.Proxy.Script.Status()
	return map[string]any{"available": true, "loaded": st.Loaded, "path": st.Path}
}

func (s *Server) flows(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := capture.Filter{
		Host: q.Get("host"), Path: q.Get("path"), Method: q.Get("method"),
		Kind: capture.Kind(q.Get("kind")), Grep: q.Get("grep"),
	}
	f.Status, _ = strconv.Atoi(q.Get("status"))
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if v := q.Get("since"); v != "" {
		f.Since, _ = strconv.ParseInt(v, 10, 64)
	}
	flows, err := s.Store.List(f)
	if err != nil {
		fail(w, 400, err)
		return
	}
	out := make([]map[string]any, 0, len(flows))
	for _, fl := range flows {
		var m map[string]any
		b, _ := json.Marshal(fl)
		_ = json.Unmarshal(b, &m)
		m["line"] = fl.Line()
		out = append(out, m)
	}
	writeJSON(w, 200, map[string]any{"flows": out})
}

func (s *Server) flow(w http.ResponseWriter, r *http.Request) {
	fl, ok := s.Store.Get(r.PathValue("id"))
	if !ok {
		fail(w, 404, fmt.Errorf("no flow %s", r.PathValue("id")))
		return
	}
	writeJSON(w, 200, fl.Detail())
}

// events is a Server-Sent Events stream of everything the store publishes.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		fail(w, 500, fmt.Errorf("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	flusher.Flush()

	id, ch := s.Store.Subscribe()
	defer s.Store.Unsubscribe(id)
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		case e, open := <-ch:
			if !open {
				return
			}
			b, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, b)
			flusher.Flush()
		}
	}
}

func (s *Server) queue(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"held": s.Proxy.Queue.List()})
}

func (s *Server) release(w http.ResponseWriter, r *http.Request) {
	var v capture.Verdict
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		fail(w, 400, err)
		return
	}
	if !v.Action.Valid() {
		fail(w, 400, fmt.Errorf("unknown action %q", v.Action))
		return
	}
	id := r.PathValue("id")
	if !s.Proxy.Queue.Release(id, v) {
		fail(w, 404, fmt.Errorf("%s is not held (already released, or the hold expired)", id))
		return
	}
	writeJSON(w, 200, map[string]any{"released": id, "action": v.Action})
}

func (s *Server) mode(w http.ResponseWriter, r *http.Request) {
	var m struct {
		HoldRequests  *bool  `json:"hold_requests"`
		HoldResponses *bool  `json:"hold_responses"`
		HoldMS        *int64 `json:"hold_ms"`
		Offline       *bool  `json:"offline"`
	}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		fail(w, 400, err)
		return
	}
	if m.HoldRequests != nil {
		s.Proxy.HoldRequests.Store(*m.HoldRequests)
	}
	if m.HoldResponses != nil {
		s.Proxy.HoldResponses.Store(*m.HoldResponses)
	}
	if m.HoldMS != nil {
		s.Proxy.HoldMS.Store(*m.HoldMS)
	}
	if m.Offline != nil {
		s.Proxy.Offline.Store(*m.Offline)
	}
	s.status(w, r)
}

func (s *Server) clear(w http.ResponseWriter, r *http.Request) {
	s.Store.Clear()
	writeJSON(w, 200, map[string]any{"cleared": true})
}

func normalisePort(addr string) int {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		n, _ := strconv.Atoi(p)
		return n
	}
	if n, err := strconv.Atoi(strings.TrimPrefix(addr, ":")); err == nil {
		return n
	}
	return 0
}

// --- scripting ---

// scriptStatus reports whether scripting is available and, if loaded, its stats.
func (s *Server) scriptStatus(w http.ResponseWriter, r *http.Request) {
	if s.Proxy.Script == nil {
		writeJSON(w, 200, map[string]any{"available": false,
			"detail": "python3 is not on PATH; scripting is unavailable"})
		return
	}
	st := s.Proxy.Script.Status()
	writeJSON(w, 200, map[string]any{"available": true, "status": st})
}

// scriptControl loads, reloads, resets or unloads the interception script. Load takes either a path
// or inline source (piped in / sent by an agent); inline source is written to a per-session file so
// reload and file-watching still work.
func (s *Server) scriptControl(w http.ResponseWriter, r *http.Request) {
	if s.Proxy.Script == nil {
		writeJSON(w, 400, map[string]any{"error": "python3 is not on PATH; scripting is unavailable"})
		return
	}
	var req struct {
		Action string `json:"action"`
		Path   string `json:"path"`
		Source string `json:"source"`
		Watch  bool   `json:"watch"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request: " + err.Error()})
		return
	}
	var err error
	switch req.Action {
	case "load":
		if req.Source != "" {
			err = s.Proxy.Script.LoadSource([]byte(req.Source), s.scriptFile())
		} else if req.Path != "" {
			err = s.Proxy.Script.Load(req.Path)
		} else {
			err = fmt.Errorf("load needs a path or inline source")
		}
		if err == nil {
			s.Proxy.Script.SetWatch(req.Watch)
		}
	case "reload":
		err = s.Proxy.Script.Reload()
	case "reset":
		err = s.Proxy.Script.Reset()
	case "off":
		s.Proxy.Script.Off()
	default:
		err = fmt.Errorf("unknown action %q: want load, reload, reset or off", req.Action)
	}
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"status": s.Proxy.Script.Status()})
}

// scriptLogs returns the worker's recent output (prints, logs, tracebacks). With an event-stream
// Accept header it tails; otherwise it returns the current snapshot.
func (s *Server) scriptLogs(w http.ResponseWriter, r *http.Request) {
	if s.Proxy.Script == nil {
		writeJSON(w, 400, map[string]any{"error": "python3 is not on PATH; scripting is unavailable"})
		return
	}
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		writeJSON(w, 200, map[string]any{"logs": s.Proxy.Script.Logs()})
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]any{"error": "streaming unsupported"})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	sent := 0
	emit := func() bool {
		lines := s.Proxy.Script.Logs()
		for _, l := range lines[min(sent, len(lines)):] {
			b, _ := json.Marshal(l)
			fmt.Fprintf(w, "data: %s\n\n", b)
		}
		sent = len(lines)
		flusher.Flush()
		return true
	}
	emit()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			emit()
		}
	}
}

// scriptFile is where inline (piped) source is persisted for this session, so reload/watch work.
func (s *Server) scriptFile() string {
	name := s.Info.Name
	if name == "" {
		name = "session"
	}
	return filepath.Join(ca.Home(), "scripts", name+".py")
}
