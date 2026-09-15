// Package script (protocol.go: the ntcept<->worker wire types).
//
// script runs user-supplied Python that decides what to do with intercepted traffic. A
// long-lived python3 worker holds the code and its in-memory state; ntcept sends it one message at
// a time and applies the verdict it returns. The worker is never trusted with the bytes on the
// wire — it returns a decision, and ntcept carries it out — and any failure fails open, so a broken
// rule slows nothing and breaks nothing.
package script

import "strings"

// Event is one intercepted message handed to the worker for a verdict. The same Exchange id is set
// on a request and its response, so a rule can carry per-exchange context between the two.
type Event struct {
	Seq       int64  `json:"seq"`
	Hook      string `json:"hook"`  // "on_request" or "on_response"
	Exchange  string `json:"id"`    // stable across an exchange's request and response
	End       bool   `json:"end"`   // this message ends the exchange; the worker frees its ctx
	Kind      string `json:"kind"`  // "http" or "tcp"
	Proto     string `json:"proto"` // "http", "postgres", "redis", "mysql", "mongodb"
	Host      string `json:"host"`
	Port      int    `json:"port,omitempty"`
	Direction string `json:"direction"` // "request" or "response"

	// HTTP.
	Method  string              `json:"method,omitempty"`
	URL     string              `json:"url,omitempty"`
	Path    string              `json:"path,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    string              `json:"body,omitempty"`
	Status  int                 `json:"status,omitempty"`

	// Databases.
	MsgKind string    `json:"msg_kind,omitempty"` // "Query", "Bind", "DataRow", …
	SQL     string    `json:"sql,omitempty"`
	Cmd     string    `json:"cmd,omitempty"`  // redis command verb
	Args    []string  `json:"args,omitempty"` // redis command arguments
	Row     []*string `json:"row,omitempty"`  // a returned result row (nil entry = NULL)
	Text    string    `json:"text,omitempty"` // the decoded one-line rendering
}

// wireVerdict is what the worker writes back for an event. It is deliberately a superset shared with
// the manual verdict shape, so a rule can express anything a person can from the queue.
type wireVerdict struct {
	Seq     int64  `json:"seq"`
	Action  string `json:"action"` // pass | drop | edit | respond | hold | record
	DelayMS int    `json:"delay_ms,omitempty"`

	// edit
	SQL        *string           `json:"sql,omitempty"`
	Row        []*string         `json:"row,omitempty"`
	Raw        *string           `json:"raw,omitempty"`
	Body       *string           `json:"body,omitempty"`
	Status     int               `json:"status,omitempty"`
	Method     string            `json:"method,omitempty"`
	URL        string            `json:"url,omitempty"`
	SetHeaders map[string]string `json:"set_headers,omitempty"`

	// respond
	PGError   string `json:"pg_error,omitempty"`
	PGCode    string `json:"pg_code,omitempty"`
	PGMessage string `json:"pg_message,omitempty"`

	// record (dynamic redaction of the stored copy only)
	RecordText   *string  `json:"record_text,omitempty"`
	RecordRedact []string `json:"record_redact,omitempty"`

	// logs the script's log() calls made while judging this message.
	Logs []string `json:"logs,omitempty"`
}

// Action is the decision, decoupled from the manual-verdict types so this package does not depend on
// capture. The proxy translates a Result into the verdict it already knows how to apply.
type Action string

const (
	Pass    Action = "pass"    // forward unchanged (possibly after a delay)
	Drop    Action = "drop"    // kill the connection
	Edit    Action = "edit"    // forward a modified message
	Respond Action = "respond" // answer locally, never reaching the upstream
	Hold    Action = "hold"    // hand to the manual queue for a person to judge
	Record  Action = "record"  // forward unchanged, but store a redacted copy
)

// Result is a verdict translated for the proxy to carry out.
type Result struct {
	Action  Action
	DelayMS int

	SQL        *string
	Row        []*string
	Raw        *string
	Body       *string
	Status     int
	Method     string
	URL        string
	SetHeaders map[string]string

	PGCode    string
	PGMessage string

	RecordText   *string
	RecordRedact []string

	Logs []string // the script's log() lines for this message
}

func (w wireVerdict) result() Result {
	r := Result{
		Action: Action(w.Action), DelayMS: w.DelayMS,
		SQL: w.SQL, Row: w.Row, Raw: w.Raw, Body: w.Body, Status: w.Status,
		Method: w.Method, URL: w.URL, SetHeaders: w.SetHeaders,
		RecordText: w.RecordText, RecordRedact: w.RecordRedact, Logs: w.Logs,
	}
	if r.Action == "" {
		r.Action = Pass
	}
	// pg_error is the friendly "SQLSTATE: message" form; the split fields win if both are given.
	r.PGCode, r.PGMessage = w.PGCode, w.PGMessage
	if w.PGError != "" && r.PGCode == "" && r.PGMessage == "" {
		if code, msg, ok := strings.Cut(w.PGError, ":"); ok && len(strings.TrimSpace(code)) == 5 {
			r.PGCode, r.PGMessage = strings.TrimSpace(code), strings.TrimSpace(msg)
		} else {
			r.PGMessage = strings.TrimSpace(w.PGError)
		}
	}
	return r
}
