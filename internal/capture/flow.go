// Package capture holds what ntcept has seen: a bounded, redacted, in-memory ring of flows.
package capture

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rahlenjakob/ntcept/internal/redact"
)

type Message struct {
	T         time.Time `json:"t"`
	Dir       Dir       `json:"dir"`
	Opcode    Opcode    `json:"opcode,omitempty"`
	Data      []byte    `json:"-"`
	Decoded   string    `json:"decoded,omitempty"`
	Truncated bool      `json:"truncated,omitempty"`
}

func (m Message) MarshalJSON() ([]byte, error) {
	type alias Message
	return json.Marshal(struct {
		alias
		Data string `json:"data,omitempty"`
		Size int    `json:"size"`
	}{alias(m), Printable(m.Data), len(m.Data)})
}

type Flow struct {
	ID    string    `json:"id"`
	Seq   int64     `json:"seq"`
	Kind  Kind      `json:"kind"`
	Start time.Time `json:"start"`
	MS    int64     `json:"ms"`
	Done  bool      `json:"done"`

	Client string `json:"client,omitempty"`
	Host   string `json:"host"`
	Port   int    `json:"port,omitempty"`
	TLS    bool   `json:"tls,omitempty"`
	Proto  Proto  `json:"proto,omitempty"`
	Via    Via    `json:"via,omitempty"`
	PID    int    `json:"pid,omitempty"`
	Cmd    string `json:"cmd,omitempty"`

	Method string      `json:"method,omitempty"`
	URL    string      `json:"url,omitempty"`
	Path   string      `json:"path,omitempty"`
	Query  string      `json:"query,omitempty"`
	Status int         `json:"status,omitempty"`
	ReqHdr http.Header `json:"req_headers,omitempty"`
	ResHdr http.Header `json:"res_headers,omitempty"`
	ReqLen int         `json:"req_len"`
	ResLen int         `json:"res_len"`

	ReqBody      []byte `json:"-"`
	ResBody      []byte `json:"-"`
	ReqTruncated bool   `json:"req_truncated,omitempty"`
	ResTruncated bool   `json:"res_truncated,omitempty"`

	Messages []Message `json:"messages,omitempty"`

	// ScriptLog holds the lines an interception script logged while judging this flow's messages,
	// so `ntcept show` can replay what the policy saw and decided for this request.
	ScriptLog []string `json:"script_log,omitempty"`

	Decision  Decision      `json:"decision,omitempty"`
	Redaction redact.Report `json:"redaction,omitempty"`
	// Error is a failure: the exchange did not complete. Note is an observation about a flow
	// that is otherwise fine, and must not be conflated with it — `--errors` filters on Error.
	Error string `json:"error,omitempty"`
	Note  string `json:"note,omitempty"`
}

// Detail is the JSON shape returned when one flow is asked for in full.
func (f *Flow) Detail() map[string]any {
	b, _ := json.Marshal(f)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	m["req_body"] = Printable(f.ReqBody)
	m["res_body"] = Printable(f.ResBody)
	m["line"] = f.Line()
	return m
}

func (f *Flow) Size() int {
	n := len(f.ReqBody) + len(f.ResBody) + 512
	for _, m := range f.Messages {
		n += len(m.Data) + 64
	}
	return n
}

// Line is the one-row summary: what `ntcept ls` prints and what most queries need.
func (f *Flow) Line() string {
	ts := f.Start.Format("15:04:05.000")
	switch f.Kind {
	case KindHTTP:
		status := "···"
		if f.Status > 0 {
			status = fmt.Sprintf("%d", f.Status)
		}
		return fmt.Sprintf("%-5s %s %-3s %-6s %-5s %6dms %s%s%s",
			f.ID, ts, string(f.Proto), f.Method, status, f.MS, f.Host, trunc(f.Path, 52), f.flags())
	default:
		// For a raw-relay flow the decoder's guess (postgres, redis, mysql, mongodb, dns) is
		// the useful label — far more so than the bare transport. WebSocket keeps its own kind,
		// since its Path holds the URL, not a protocol name.
		label := string(f.Kind)
		if (f.Kind == KindTCP || f.Kind == KindUDP) && f.Path != "" && f.Path != "raw" {
			label = f.Path
		}
		return fmt.Sprintf("%-5s %s %-8s %6dms %s:%d  %d msg%s",
			f.ID, ts, label, f.MS, f.Host, f.Port, len(f.Messages), f.flags())
	}
}

func (f *Flow) flags() string {
	var s []string
	if len(f.Redaction.Secrets) > 0 {
		s = append(s, "secret")
	}
	if f.Error != "" {
		s = append(s, "err")
	}
	if f.Note != "" {
		s = append(s, "note")
	}
	if f.Decision != "" && f.Decision != DecisionPass {
		s = append(s, string(f.Decision))
	}
	if len(s) == 0 {
		return ""
	}
	return "  [" + strings.Join(s, " ") + "]"
}

func trunc(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// Printable renders bytes for JSON: text as-is, binary as base64 with a marker.
func Printable(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if utf8.Valid(b) && !hasControl(b) {
		return string(b)
	}
	return "base64:" + base64.StdEncoding.EncodeToString(b)
}

func hasControl(b []byte) bool {
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			return true
		}
	}
	return false
}

// FromPrintable is the inverse of Printable, for turning a detail response back into bytes.
func FromPrintable(s string) []byte {
	if s == "" {
		return nil
	}
	if rest, ok := strings.CutPrefix(s, "base64:"); ok {
		if b, err := base64.StdEncoding.DecodeString(rest); err == nil {
			return b
		}
	}
	return []byte(s)
}
