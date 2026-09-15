package capture

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Event struct {
	Type EventType `json:"type"`
	Flow *Flow     `json:"flow,omitempty"`
	Held *Held     `json:"held,omitempty"`
}

type Store struct {
	mu       sync.Mutex
	items    []*Flow
	byID     map[string]*Flow
	bytes    int
	maxBytes int
	seq      int64
	MaxBody  int

	subs    map[int]chan Event
	nextSub int
}

func NewStore(maxBytes, maxBody int) *Store {
	return &Store{
		byID: map[string]*Flow{}, maxBytes: maxBytes, MaxBody: maxBody,
		subs: map[int]chan Event{},
	}
}

func (s *Store) Begin(kind Kind, host string, port int) *Flow {
	s.mu.Lock()
	s.seq++
	f := &Flow{
		ID: fmt.Sprintf("%d", s.seq), Seq: s.seq, Kind: kind,
		Start: time.Now(), Host: host, Port: port,
	}
	s.items = append(s.items, f)
	s.byID[f.ID] = f
	s.bytes += f.Size()
	s.evict()
	snap := clone(f)
	s.mu.Unlock()
	s.publish(Event{Type: EventFlowNew, Flow: snap})
	return f
}

// Touch applies fn to a live flow under the store lock and notifies subscribers.
func (s *Store) Touch(f *Flow, evt EventType, fn func(*Flow)) {
	s.mu.Lock()
	before := f.Size()
	fn(f)
	s.bytes += f.Size() - before
	s.evict()
	snap := clone(f)
	s.mu.Unlock()
	s.publish(Event{Type: evt, Flow: snap})
}

func (s *Store) Finish(f *Flow, err error) {
	s.Touch(f, EventFlowDone, func(f *Flow) {
		f.Done = true
		if f.MS == 0 {
			f.MS = time.Since(f.Start).Milliseconds()
		}
		if err != nil && f.Error == "" {
			f.Error = err.Error()
		}
	})
}

// Append adds a message to a streaming flow (websocket frame, tcp segment, datagram).
func (s *Store) Append(f *Flow, m Message) {
	if s.MaxBody > 0 && len(m.Data) > s.MaxBody {
		m.Data = m.Data[:s.MaxBody]
		m.Truncated = true
	}
	s.Touch(f, EventFlowUpdate, func(f *Flow) { f.Messages = append(f.Messages, m) })
}

// OverrideLastMessage replaces the stored, human-readable copy of the most recent message, so a
// script can redact what lands in the capture buffer while the real bytes still go on the wire. The
// raw copy is dropped, since the redacted rendering is now the record.
func (s *Store) OverrideLastMessage(f *Flow, decoded string) {
	s.Touch(f, EventFlowUpdate, func(f *Flow) {
		if n := len(f.Messages); n > 0 {
			f.Messages[n-1].Decoded = decoded
			f.Messages[n-1].Data = nil
		}
	})
}

func (s *Store) evict() {
	for s.bytes > s.maxBytes && len(s.items) > 1 {
		old := s.items[0]
		s.items = s.items[1:]
		delete(s.byID, old.ID)
		s.bytes -= old.Size()
	}
}

func clone(f *Flow) *Flow {
	c := *f
	if len(f.Messages) > 0 {
		c.Messages = append([]Message(nil), f.Messages...)
	}
	return &c
}

func (s *Store) Get(id string) (*Flow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.byID[id]
	if !ok {
		return nil, false
	}
	return clone(f), true
}

type Filter struct {
	Host   string
	Path   string
	Method string
	Kind   Kind
	Status int
	Grep   string
	Since  int64
	Limit  int
}

func (s *Store) List(f Filter) ([]*Flow, error) {
	var re *regexp.Regexp
	if f.Grep != "" {
		var err error
		if re, err = regexp.Compile(f.Grep); err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", f.Grep, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*Flow
	for _, fl := range s.items {
		if !match(fl, f, re) {
			continue
		}
		out = append(out, clone(fl))
	}
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[len(out)-f.Limit:]
	}
	return out, nil
}

func match(fl *Flow, f Filter, re *regexp.Regexp) bool {
	if f.Since > 0 && fl.Seq <= f.Since {
		return false
	}
	if f.Host != "" && !strings.Contains(strings.ToLower(fl.Host), strings.ToLower(f.Host)) {
		return false
	}
	if f.Path != "" && !strings.Contains(fl.Path, f.Path) {
		return false
	}
	if f.Method != "" && !strings.EqualFold(fl.Method, f.Method) {
		return false
	}
	if f.Kind != "" && fl.Kind != f.Kind {
		return false
	}
	if f.Status > 0 && fl.Status != f.Status {
		return false
	}
	if re != nil && !greps(fl, re) {
		return false
	}
	return true
}

func greps(fl *Flow, re *regexp.Regexp) bool {
	if re.MatchString(fl.Host) || re.MatchString(fl.Path) || re.MatchString(fl.URL) ||
		re.Match(fl.ReqBody) || re.Match(fl.ResBody) {
		return true
	}
	for k, vs := range fl.ReqHdr {
		if re.MatchString(k + ": " + strings.Join(vs, ",")) {
			return true
		}
	}
	for k, vs := range fl.ResHdr {
		if re.MatchString(k + ": " + strings.Join(vs, ",")) {
			return true
		}
	}
	for _, m := range fl.Messages {
		if re.Match(m.Data) || re.MatchString(m.Decoded) {
			return true
		}
	}
	return false
}

func (s *Store) Stats() (count, bytes int, seq int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items), s.bytes, s.seq
}

func (s *Store) Clear() {
	s.mu.Lock()
	s.items, s.byID, s.bytes = nil, map[string]*Flow{}, 0
	s.mu.Unlock()
}

// Subscribe returns a buffered channel of events. Slow subscribers drop rather than block the
// proxy; the UI resyncs from /flows when it notices a gap.
func (s *Store) Subscribe() (int, <-chan Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextSub++
	ch := make(chan Event, 256)
	s.subs[s.nextSub] = ch
	return s.nextSub, ch
}

func (s *Store) Unsubscribe(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.subs[id]; ok {
		delete(s.subs, id)
		close(ch)
	}
}

func (s *Store) publish(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range s.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

func (s *Store) Publish(e Event) { s.publish(e) }

// CapBody truncates a captured body to the configured ceiling.
func (s *Store) CapBody(b []byte) ([]byte, bool) {
	if s.MaxBody > 0 && len(b) > s.MaxBody {
		out := make([]byte, s.MaxBody)
		copy(out, b)
		return out, true
	}
	return b, false
}
