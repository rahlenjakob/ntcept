package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/decode"
	"github.com/rahlenjakob/ntcept/internal/script"
)

// maxFramePending bounds how much of one message is buffered while waiting for the rest of it. A
// message larger than this is streamed through untouched rather than held in memory — holding is
// message-level, and a multi-megabyte row or bulk copy is not something to pause on.
const maxFramePending = 4 << 20

// relayTCP handles a tunnel carrying something that is not HTTP: Redis, Postgres, MySQL, or
// anything else. When holding is off it is a passthrough with a decoder watching a copy; when a
// decodable protocol is recognised, each message is framed so it can be held, dropped, rewritten
// or answered locally on the way through.
func (s *Server) relayTCP(c net.Conn, br *bufio.Reader, t target) {
	f := s.Store.Begin(capture.KindTCP, t.host, t.port)
	started := time.Now()

	// Sniff on what the client has already sent, and wait for nothing.
	//
	// Asking for a fixed 64 bytes here used to stall the connection for the full read deadline
	// whenever the client opened with fewer and then waited for an answer — which is most of
	// them. Redis sends six bytes and waits; ten seconds of ntcept were added to every such
	// connection before anything was forwarded. The codec only decides how bytes are displayed,
	// never whether they are delivered, so a poorer guess is strictly better than a delay.
	first, _ := br.Peek(br.Buffered())
	codec := decode.Sniff(t.port, first)

	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.Proto, f.Via, f.Client = capture.ProtoTCP, t.via, c.RemoteAddr().String()
		f.Path = codec.Protocol()
	})

	dialCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	up, err := s.dialUpstream(dialCtx, t.addr())
	cancel()
	if err != nil {
		s.Store.Finish(f, err)
		return
	}
	defer up.Close()

	// c is written by both directions — the server->app forwarding and a locally-synthesized
	// answer to a held request — so those writes are serialized. up has a single writer.
	var appMu sync.Mutex
	writeApp := func(b []byte) error {
		appMu.Lock()
		defer appMu.Unlock()
		_, e := c.Write(b)
		return e
	}
	writeUp := func(b []byte) error { _, e := up.Write(b); return e }
	tear := func() { _ = c.Close(); _ = up.Close() }

	done := make(chan struct{}, 2)
	go func() {
		s.pump(pumpDir{
			f: f, dir: capture.Out, src: br, forward: writeUp, reply: writeApp,
			codec: codec, server: false, hold: &s.HoldRequests, tear: tear,
		})
		done <- struct{}{}
	}()
	go func() {
		s.pump(pumpDir{
			f: f, dir: capture.In, src: up, forward: writeApp, reply: nil,
			codec: codec, server: true, hold: &s.HoldResponses, tear: tear,
		})
		done <- struct{}{}
	}()
	<-done
	_ = c.SetDeadline(time.Now())
	_ = up.SetDeadline(time.Now())

	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.MS = time.Since(started).Milliseconds()
	})
	s.Store.Finish(f, nil)
}

// pumpDir is one direction of a relayed connection.
type pumpDir struct {
	f       *capture.Flow
	dir     capture.Dir
	src     io.Reader          // where this direction's bytes are read from
	forward func([]byte) error // send bytes on to the far end
	reply   func([]byte) error // answer the application locally (nil where respond is unsupported)
	codec   *decode.Codec
	server  bool         // true for the server->app direction
	hold    *atomic.Bool // whether this direction is currently held
	tear    func()       // tear the whole connection down (a drop)
}

// pump moves one direction of a relayed connection. Until the protocol is known — or for a stream
// nothing recognised — it is a passthrough that copies bytes on and feeds a decoder for display.
// Once a framer is available it switches, for the rest of the connection, to reading whole messages
// so each can be held; a stream that stops being decodable (a TLS upgrade) falls back to passthrough.
func (s *Server) pump(rd pumpDir) {
	stream := rd.codec.Client
	if rd.server {
		stream = rd.codec.Server
	}
	buf := make([]byte, 32*1024)
	var (
		framer  decode.Framer
		pending []byte
		opaque  bool // the stream can no longer be framed; copy the rest through
		st      pumpState
	)
	for {
		n, err := rd.src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			switch {
			case opaque:
				if rd.forward(chunk) != nil {
					return
				}
			case framer == nil && rd.codec.Framer(rd.server) == nil:
				// Undecided or a raw stream: forward now, decode a copy for display.
				if rd.forward(chunk) != nil {
					return
				}
				for _, msg := range stream.Feed(chunk) {
					s.Store.Append(rd.f, capture.Message{T: time.Now(), Dir: rd.dir, Decoded: msg})
				}
				s.relabel(rd)
			default:
				if framer == nil {
					framer = rd.codec.Framer(rd.server)
				}
				pending = append(pending, chunk...)
				frames, consumed, ok := framer.Frame(pending)
				keep, torn := s.handleFrames(rd, frames, &st)
				if torn {
					rd.tear()
					return
				}
				if !keep {
					return
				}
				pending = append(pending[:0], pending[consumed:]...)
				if !ok {
					if len(pending) > 0 && rd.forward(pending) != nil {
						return
					}
					pending, opaque = nil, true
				} else if len(pending) > maxFramePending {
					// A single message larger than the buffer: stop framing and stream the rest.
					if rd.forward(pending) != nil {
						return
					}
					pending, opaque = nil, true
				}
				s.relabel(rd)
			}
		}
		if err != nil {
			return
		}
	}
}

// pumpState is one direction's carry-over between reads: the multi-message bookkeeping that a
// single Frame batch cannot see on its own.
type pumpState struct {
	drain     bool // swallowing this direction's messages until an exchange terminator
	suppress  bool // requests: one hold per query, until the exchange terminates
	respHolds int  // responses: how many messages of this exchange are already held, to bound them
}

// maxRespHolds bounds how many result messages of one exchange are held, so editing a row does not
// mean answering a hold for every row of a large SELECT.
const maxRespHolds = 50

// handleFrames applies the verdict path to each framed message: record it, forward it, or — when
// this direction is held — park it and act on the answer. keep is false when the reader should stop;
// torn is true when a drop means the whole connection must come down.
func (s *Server) handleFrames(rd pumpDir, frames []decode.Frame, st *pumpState) (keep, torn bool) {
	proto := rd.codec.Protocol()
	var out []byte
	flush := func() bool {
		if len(out) > 0 {
			if rd.forward(out) != nil {
				return false
			}
			out = out[:0]
		}
		return true
	}
	for _, fr := range frames {
		s.append(rd, fr, false)

		// The end of an exchange lifts the request-side suppression and resets the response-side
		// hold budget for the next query on this connection.
		if endsPGExchange(proto, fr.Kind) {
			st.suppress, st.respHolds = false, 0
		}

		// After a locally-answered request, the client keeps talking (the extended protocol sends
		// its remaining messages and a Sync); swallow those until the exchange terminates, then
		// close it out. None of it reaches the server, which never saw the request.
		if st.drain {
			if decode.ExchangeTerminator(proto, fr.Kind) {
				if reply := decode.TerminatorReply(proto); reply != nil && rd.reply != nil {
					if rd.reply(reply) != nil {
						return false, false
					}
				}
				st.drain = false
			}
			continue
		}

		if fr.Holdable {
			// A loaded script gets first say — forward, delay, edit, drop, answer locally, or hand
			// the message to the manual queue with hold(), which falls through below.
			if s.Script.Enabled() {
				res, ok := s.Script.Eval(s.scriptEvent(rd, fr, proto))
				if ok && len(res.Logs) > 0 {
					s.attachScriptLogs(rd.f, res.Logs)
				}
				if ok && res.Action != script.Hold {
					if !flush() {
						return false, false
					}
					if res.DelayMS > 0 {
						time.Sleep(time.Duration(res.DelayMS) * time.Millisecond)
					}
					switch res.Action {
					case script.Drop:
						s.decide(rd.f, capture.DecisionDrop)
						return false, true
					case script.Respond:
						if s.respond(rd, fr, proto, verdictFromScript(res), &st.drain) {
							continue
						}
					case script.Edit:
						if repl, ok := editedBytes(proto, fr, verdictFromScript(res)); ok {
							out = append(out, repl...)
							s.decide(rd.f, capture.DecisionEdit)
							continue
						}
					case script.Record:
						// Forward the real bytes, but scrub the stored copy this frame just recorded.
						s.Store.OverrideLastMessage(rd.f, recordText(fr.Text, res))
					}
					// Pass, record, or an unhonoured verdict: forward the real bytes on.
					out = append(out, fr.Bytes...)
					continue
				}
			}
			// Manual hold.
			if rd.hold.Load() && s.mayHold(rd, st) {
				if !flush() {
					return false, false
				}
				if rd.dir == capture.Out && startsPGExchange(proto, fr.Kind) {
					st.suppress = true
				}
				if rd.dir == capture.In {
					st.respHolds++
				}
				v, ok := s.hold(rd.f, s.heldFrame(rd, fr, proto))
				if ok {
					switch v.Action {
					case capture.ActionDrop:
						s.decide(rd.f, capture.DecisionDrop)
						return false, true
					case capture.ActionRespond:
						if s.respond(rd, fr, proto, v, &st.drain) {
							continue // answered locally; the request is not forwarded
						}
					case capture.ActionEdit:
						if repl, ok := editedBytes(proto, fr, v); ok {
							out = append(out, repl...)
							s.decide(rd.f, capture.DecisionEdit)
							continue
						}
					}
				}
				// Forward on a timeout, an explicit forward, or a verdict this direction can't honour.
			}
		}
		out = append(out, fr.Bytes...)
	}
	if !flush() {
		return false, false
	}
	return true, false
}

// scriptEvent describes a framed message for the scripting engine, in the shape the Python hook sees.
func (s *Server) scriptEvent(rd pumpDir, fr decode.Frame, proto string) script.Event {
	dir, hook := "request", "on_request"
	if rd.dir == capture.In {
		dir, hook = "response", "on_response"
	}
	ev := script.Event{
		Hook: hook, Exchange: rd.f.ID, Kind: string(capture.KindTCP), Proto: proto,
		Host: rd.f.Host, Port: rd.f.Port, Direction: dir,
		MsgKind: fr.Kind, SQL: decode.QueryText(proto, fr.Kind, fr.Bytes), Text: fr.Text,
	}
	if row, ok := decode.RowValues(proto, fr.Kind, fr.Bytes); ok {
		ev.Row = row
	}
	if proto == "redis" {
		if f := strings.Fields(fr.Text); len(f) > 0 {
			ev.Cmd, ev.Args = f[0], f[1:]
		}
	}
	return ev
}

// recordText is the redacted rendering to store for a message the script chose to record: a full
// replacement when the script supplied one, otherwise the decode with the named substrings masked.
func recordText(orig string, res script.Result) string {
	if res.RecordText != nil {
		return *res.RecordText
	}
	out := orig
	for _, sub := range res.RecordRedact {
		if sub != "" {
			out = strings.ReplaceAll(out, sub, "«redacted»")
		}
	}
	return out
}

// attachScriptLogs records the lines a script logged for a message on its flow, so `ntcept show`
// can replay what the policy saw and decided.
func (s *Server) attachScriptLogs(f *capture.Flow, logs []string) {
	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.ScriptLog = append(f.ScriptLog, logs...)
	})
}

// verdictFromScript turns a script decision into the manual-verdict shape, so the same edit/respond
// code carries out both.
func verdictFromScript(res script.Result) capture.Verdict {
	v := capture.Verdict{
		SQL: res.SQL, Row: res.Row, Raw: res.Raw, Body: res.Body, Status: res.Status,
		Method: res.Method, URL: res.URL, SetHeaders: res.SetHeaders,
	}
	if res.PGCode != "" || res.PGMessage != "" {
		v.Error = &capture.ProtoError{Code: res.PGCode, Message: res.PGMessage}
	}
	return v
}

// mayHold decides whether another message of this exchange should be parked: on the request side one
// hold per query, on the response side up to a bounded number so a large result cannot flood.
func (s *Server) mayHold(rd pumpDir, st *pumpState) bool {
	if rd.dir == capture.In {
		return st.respHolds < maxRespHolds
	}
	return !st.suppress
}

// editedBytes produces the replacement bytes for an edit verdict: a rewritten statement or result
// row where the message carries one, otherwise the raw bytes the operator supplied.
func editedBytes(proto string, fr decode.Frame, v capture.Verdict) ([]byte, bool) {
	if v.SQL != nil {
		if b, ok := decode.RewriteQuery(proto, fr.Kind, fr.Bytes, *v.SQL); ok {
			return b, true
		}
	}
	if v.Row != nil {
		if b, ok := decode.RewriteRow(proto, fr.Kind, fr.Bytes, v.Row); ok {
			return b, true
		}
	}
	if v.Raw != nil {
		return capture.FromPrintable(*v.Raw), true
	}
	return nil, false
}

// startsPGExchange reports a held Postgres message that opens a multi-message exchange (the extended
// protocol), so further holds are suppressed until it ends. A simple Query stands alone.
func startsPGExchange(proto, kind string) bool {
	return proto == "postgres" && kind != "Query"
}

// endsPGExchange reports the message that closes a Postgres exchange: the client's Sync or the
// server's ReadyForQuery.
func endsPGExchange(proto, kind string) bool {
	return proto == "postgres" && (kind == "Sync" || kind == "ReadyForQuery")
}

// respond answers a held request locally instead of forwarding it. It returns false when the
// protocol or direction cannot be answered this way, so the caller forwards the request instead.
func (s *Server) respond(rd pumpDir, fr decode.Frame, proto string, v capture.Verdict, drain *bool) bool {
	if rd.reply == nil {
		return false
	}
	perr := decode.ProtoError{}
	if v.Error != nil {
		perr = decode.ProtoError{Code: v.Error.Code, Message: v.Error.Message, Severity: v.Error.Severity}
	}
	reply, awaitTerminator := decode.SynthError(proto, fr.Kind, perr)
	if reply == nil {
		return false
	}
	if rd.reply(reply) != nil {
		return false
	}
	if awaitTerminator {
		*drain = true
	}
	s.decide(rd.f, capture.DecisionRespond)
	return true
}

// heldFrame describes a database message parked for a verdict, the way Held describes a parked HTTP
// exchange.
func (s *Server) heldFrame(rd pumpDir, fr decode.Frame, proto string) *capture.Held {
	h := &capture.Held{
		FlowID: rd.f.ID, Host: rd.f.Host, Kind: capture.KindTCP, Proto: proto,
		Dir: rd.dir, MsgKind: fr.Kind, Text: fr.Text, Raw: capture.Printable(fr.Bytes),
		SQL: decode.QueryText(proto, fr.Kind, fr.Bytes),
	}
	if row, ok := decode.RowValues(proto, fr.Kind, fr.Bytes); ok {
		h.Row = row
	}
	return h
}

// append records one framed message on the flow. The raw bytes are kept only when the message was
// held, where they are wanted for inspection and were copied already.
func (s *Server) append(rd pumpDir, fr decode.Frame, keepBytes bool) {
	m := capture.Message{T: time.Now(), Dir: rd.dir, Decoded: fr.Text}
	if keepBytes {
		m.Data = append([]byte(nil), fr.Bytes...)
	}
	s.Store.Append(rd.f, m)
}

// relabel corrects the flow's protocol label once the decoder has worked out what it is. What a
// connection speaks is often unknown when it opens — a server that greets first says nothing until
// it does — so the label is fixed when the protocol gives itself away.
func (s *Server) relabel(rd pumpDir) {
	if name := rd.codec.Protocol(); name != rd.f.Path {
		s.Store.Touch(rd.f, capture.EventFlowUpdate, func(f *capture.Flow) { f.Path = name })
	}
}
