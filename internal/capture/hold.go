package capture

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Held is an exchange parked mid-flight waiting for a verdict. This is the manual half of
// "manage": no rules, no matching — someone is looking at this one request and deciding.
type Held struct {
	ID      string      `json:"id"`
	FlowID  string      `json:"flow_id"`
	Stage   Stage       `json:"stage"`
	Host    string      `json:"host"`
	Method  string      `json:"method,omitempty"`
	URL     string      `json:"url,omitempty"`
	Status  int         `json:"status,omitempty"`
	Headers http.Header `json:"headers,omitempty"`
	Body    string      `json:"body,omitempty"`
	At      time.Time   `json:"at"`

	// On a response hold, what was sent to produce it. A response is not worth judging
	// without the request that caused it.
	ReqHeaders http.Header `json:"req_headers,omitempty"`
	ReqBody    string      `json:"req_body,omitempty"`

	// Message-level fields, set for a held database/TCP frame rather than an HTTP exchange.
	Kind    Kind   `json:"kind,omitempty"`     // "tcp" for a database/raw frame
	Proto   string `json:"proto,omitempty"`    // the decoded wire protocol, e.g. "postgres"
	Dir     Dir    `json:"dir,omitempty"`      // which way the frame was travelling
	MsgKind string `json:"msg_kind,omitempty"` // the message type, e.g. "Query", "Bind"
	Text    string `json:"text,omitempty"`     // the decoded, human-readable message
	Raw     string `json:"raw,omitempty"`      // the frame's wire bytes, printable or base64
	SQL     string `json:"sql,omitempty"`      // the statement text, for a message that carries one
	// Row is a returned result row's column values, for a held DataRow. A nil entry is SQL NULL.
	Row []*string `json:"row,omitempty"`

	ch chan Verdict
}

// ProtoError answers a held database request locally with a protocol error. The fields are
// protocol-shaped — Code is a SQLSTATE for Postgres.
type ProtoError struct {
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	Severity string `json:"severity,omitempty"`
}

type Verdict struct {
	Action        Action            `json:"action"`
	Status        int               `json:"status,omitempty"`
	SetHeaders    map[string]string `json:"set_headers,omitempty"`
	RemoveHeaders []string          `json:"remove_headers,omitempty"`
	Body          *string           `json:"body,omitempty"`
	Method        string            `json:"method,omitempty"`
	URL           string            `json:"url,omitempty"`

	// Message-level verdict fields, for a held database/TCP frame.
	Raw   *string     `json:"raw,omitempty"`   // edit: replacement wire bytes (printable or base64)
	SQL   *string     `json:"sql,omitempty"`   // edit: rebuild the message around this statement text
	Row   []*string   `json:"row,omitempty"`   // edit: rebuild a result row from these column values
	Error *ProtoError `json:"error,omitempty"` // respond: answer the request with this error
}

type Queue struct {
	mu    sync.Mutex
	items map[string]*Held
	order []string
	n     int
}

func NewQueue() *Queue { return &Queue{items: map[string]*Held{}} }

func (q *Queue) Park(h *Held) <-chan Verdict {
	q.mu.Lock()
	q.n++
	h.ID = fmt.Sprintf("h%d", q.n)
	h.At = time.Now()
	h.ch = make(chan Verdict, 1)
	q.items[h.ID] = h
	q.order = append(q.order, h.ID)
	q.mu.Unlock()
	return h.ch
}

func (q *Queue) List() []*Held {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]*Held, 0, len(q.order))
	for _, id := range q.order {
		if h, ok := q.items[id]; ok {
			out = append(out, h)
		}
	}
	return out
}

func (q *Queue) Get(id string) (*Held, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	h, ok := q.items[id]
	return h, ok
}

func (q *Queue) Release(id string, v Verdict) bool {
	q.mu.Lock()
	h, ok := q.items[id]
	if ok {
		q.remove(id)
	}
	q.mu.Unlock()
	if !ok {
		return false
	}
	h.ch <- v
	return true
}

// Forget drops a held exchange whose hold budget expired.
func (q *Queue) Forget(id string) {
	q.mu.Lock()
	q.remove(id)
	q.mu.Unlock()
}

func (q *Queue) remove(id string) {
	delete(q.items, id)
	for i, x := range q.order {
		if x == id {
			q.order = append(q.order[:i], q.order[i+1:]...)
			break
		}
	}
}

func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
