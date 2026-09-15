package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/redact"
	"github.com/rahlenjakob/ntcept/internal/script"
)

// Headers that belong to one hop and must not be forwarded.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

const maxHoldBody = 32 << 20

func (s *Server) handler(t target, proto capture.Proto) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := resolveURL(r, t)
		if isWebSocket(r) {
			s.proxyWebSocket(w, r, t, u)
			return
		}
		s.proxyHTTP(w, r, t, proto, u)
	})
}

func resolveURL(r *http.Request, t target) *url.URL {
	u := *r.URL
	if u.IsAbs() {
		return &u
	}
	u.Scheme = t.scheme()
	switch {
	case r.Host != "":
		u.Host = r.Host
	case t.host != "":
		u.Host = t.addr()
	}
	return &u
}

func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

func (s *Server) proxyHTTP(w http.ResponseWriter, r *http.Request, t target, proto capture.Proto, u *url.URL) {
	host, port := splitHostPort(u.Host, defaultPort(u.Scheme))
	f := s.Store.Begin(capture.KindHTTP, host, port)
	started := time.Now()

	reqBody, bodyReader, err := s.readRequestBody(r)
	if err != nil {
		s.fail(f, w, 400, "reading request body", err)
		return
	}
	contentType := r.Header.Get("Content-Type")

	// Redaction scans every captured byte, and Store.Touch holds the store's lock for as long as
	// the function it is given runs. Doing this work before the lock is taken keeps one large
	// body from stalling the capture of every other flow in the process.
	reqHdr, rep := redact.Headers(r.Header)
	reqCapped, reqTruncated := s.Store.CapBody(reqBody)
	reqStored, bodyRep := redact.Body(reqCapped, contentType)
	rep.Merge(bodyRep)

	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.Proto, f.TLS, f.Via = proto, t.tls, t.via
		f.Method, f.URL, f.Path, f.Query = r.Method, u.String(), u.Path, u.RawQuery
		f.ReqHdr, f.Redaction = reqHdr, rep
		f.Client = r.RemoteAddr
		if reqBody != nil {
			f.ReqBody, f.ReqTruncated = reqStored, reqTruncated
			f.ReqLen = len(reqBody)
		}
	})

	// What a holding operator is shown is the whole body rather than the capture-ceiling copy,
	// so it is redacted separately — and only when something is actually holding, because for
	// a large body it is a second full scan.
	reqView := reqStored
	if reqTruncated && (s.HoldRequests.Load() || s.HoldResponses.Load()) {
		reqView, _ = redact.Body(reqBody, contentType)
	}

	// A loaded script gets first say on the request. It can forward, delay, edit, drop, answer
	// locally, or hold() it for the manual queue (falling through to HoldRequests below).
	if s.Script.Enabled() {
		res, ok := s.Script.Eval(script.Event{
			Hook: "on_request", Exchange: f.ID, Kind: "http", Proto: "http",
			Host: host, Port: port, Direction: "request",
			Method: r.Method, URL: u.String(), Path: u.Path, Headers: reqHdr, Body: capture.Printable(reqView),
		})
		if ok && len(res.Logs) > 0 {
			s.attachScriptLogs(f, res.Logs)
		}
		if ok && res.Action != script.Hold {
			if res.DelayMS > 0 {
				time.Sleep(time.Duration(res.DelayMS) * time.Millisecond)
			}
			switch res.Action {
			case script.Drop:
				s.decide(f, capture.DecisionDrop)
				hijackClose(w)
				return
			case script.Respond:
				s.decide(f, capture.DecisionRespond)
				s.writeSynthetic(w, f, verdictFromScript(res), started)
				return
			case script.Edit:
				v := verdictFromScript(res)
				applyEdit(r.Header, v)
				if v.Method != "" {
					r.Method = v.Method
				}
				if v.URL != "" {
					if nu, err := url.Parse(v.URL); err == nil {
						u = nu
					}
				}
				if v.Body != nil {
					reqBody = []byte(*v.Body)
					bodyReader = io.NopCloser(bytes.NewReader(reqBody))
					r.Header.Set("Content-Length", strconv.Itoa(len(reqBody)))
					r.ContentLength = int64(len(reqBody))
				}
				s.decide(f, capture.DecisionEdit)
			}
		}
	}

	if s.HoldRequests.Load() {
		v, ok := s.hold(f, &capture.Held{
			FlowID: f.ID, Stage: capture.StageRequest, Host: host, Method: r.Method,
			URL: u.String(), Headers: reqHdr, Body: capture.Printable(reqView),
		})
		if ok {
			switch v.Action {
			case capture.ActionDrop:
				s.decide(f, capture.DecisionDrop)
				hijackClose(w)
				return
			case capture.ActionRespond:
				s.decide(f, capture.DecisionRespond)
				s.writeSynthetic(w, f, v, started)
				return
			case capture.ActionEdit:
				applyEdit(r.Header, v)
				if v.Method != "" {
					r.Method = v.Method
				}
				if v.URL != "" {
					if nu, err := url.Parse(v.URL); err == nil {
						u = nu
					}
				}
				if v.Body != nil {
					reqBody = []byte(*v.Body)
					bodyReader = io.NopCloser(bytes.NewReader(reqBody))
					// The replacement is almost never the same length as what the app sent.
					// Leaving the original Content-Length makes the upstream wait for bytes
					// that will never arrive, and the edit fails as a 502 the operator did
					// not ask for.
					r.Header.Set("Content-Length", strconv.Itoa(len(reqBody)))
					r.ContentLength = int64(len(reqBody))
				}
				s.decide(f, capture.DecisionEdit)
			}
		}
	}

	if s.Offline.Load() {
		s.decide(f, capture.DecisionOffline)
		s.fail(f, w, 502, "ntcept is offline", nil)
		return
	}

	out, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), bodyReader)
	if err != nil {
		s.fail(f, w, 400, "building upstream request", err)
		return
	}
	copyHeaders(out.Header, r.Header)
	for _, h := range hopByHop {
		out.Header.Del(h)
	}
	out.Host = r.Host
	if cl := r.Header.Get("Content-Length"); cl != "" {
		out.ContentLength, _ = strconv.ParseInt(cl, 10, 64)
	} else if reqBody != nil {
		out.ContentLength = int64(len(reqBody))
	}

	res, err := s.transport.RoundTrip(out)
	// A streamed request body only exists in the tee once the round trip has consumed it.
	s.recordStreamedBody(f, bodyReader, contentType, r.Header.Get("Content-Encoding"))
	if err != nil {
		s.fail(f, w, 502, "upstream", err)
		return
	}
	defer res.Body.Close()

	// A loaded script gets first say on the response too. It fully handles the response unless it
	// passes or holds, in which case it restores the body and the paths below take over.
	if s.Script.Enabled() {
		if s.scriptResponse(w, f, res, host, started, sentRequest{Method: r.Method, URL: u.String()}) {
			return
		}
	}

	if s.HoldResponses.Load() {
		// A streamed request body only lands in the tee once the round trip consumed it.
		sent := reqView
		if tee, ok := bodyReader.(*capturingReader); ok && tee.n > 0 {
			decoded, _ := decodeBody(tee.buf.Bytes(), r.Header.Get("Content-Encoding"))
			sent, _ = redact.Body(decoded, contentType)
		}
		s.holdResponse(w, f, res, host, started, sentRequest{
			Method: r.Method, URL: u.String(), Headers: reqHdr, Body: capture.Printable(sent),
		})
		return
	}

	for _, h := range hopByHop {
		res.Header.Del(h)
	}
	copyHeaders(w.Header(), res.Header)
	w.WriteHeader(res.StatusCode)

	n, truncated, captured, copyErr := streamAndCapture(w, res.Body, s.Store.MaxBody)
	enc := res.Header.Get("Content-Encoding")
	readable, _ := decodeBody(captured, enc)
	// Decoded, redacted and measured outside the store lock; see the request side above.
	resHdr, _ := redact.Headers(res.Header)
	resBody, resRep := redact.Body(readable, res.Header.Get("Content-Type"))
	note := ""
	if left := undecodable(enc); left != "" {
		note = "body is " + left + "-encoded; ntcept cannot decode it, so it is stored as received"
	}
	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.Status = res.StatusCode
		f.ResHdr = resHdr
		f.ResLen = n
		f.ResBody, f.ResTruncated = resBody, truncated
		f.Note = note
		f.Redaction.Merge(resRep)
		f.MS = time.Since(started).Milliseconds()
		if f.Decision == "" {
			f.Decision = capture.DecisionPass
		}
	})
	s.Store.Finish(f, copyErr)
}

func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

// readRequestBody buffers when a verdict may need to rewrite the body, and otherwise streams.
func (s *Server) readRequestBody(r *http.Request) ([]byte, io.ReadCloser, error) {
	if r.Body == nil {
		return nil, nil, nil
	}
	if s.HoldRequests.Load() {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxHoldBody))
		if err != nil {
			return nil, nil, err
		}
		return b, io.NopCloser(bytes.NewReader(b)), nil
	}
	tee := &capturingReader{src: r.Body, limit: s.Store.MaxBody}
	return nil, tee, nil
}

// recordStreamedBody folds a streamed request body into the flow after it has been sent.
func (s *Server) recordStreamedBody(f *capture.Flow, r io.ReadCloser, contentType, encoding string) {
	tee, ok := r.(*capturingReader)
	if !ok || tee.n == 0 {
		return
	}
	readable, _ := decodeBody(tee.buf.Bytes(), encoding)
	body, rep := redact.Body(readable, contentType)
	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.ReqBody, f.ReqTruncated, f.ReqLen = body, tee.trunc, tee.n
		f.Redaction.Merge(rep)
	})
}

type capturingReader struct {
	src   io.ReadCloser
	buf   bytes.Buffer
	limit int
	n     int
	trunc bool
}

func (c *capturingReader) Read(p []byte) (int, error) {
	n, err := c.src.Read(p)
	if n > 0 {
		c.n += n
		if room := c.limit - c.buf.Len(); room > 0 {
			c.buf.Write(p[:min(n, room)])
			if n > room {
				c.trunc = true
			}
		} else if c.limit > 0 {
			c.trunc = true
		}
	}
	return n, err
}

func (c *capturingReader) Close() error { return c.src.Close() }

// streamAndCapture forwards the body to the client as it arrives — so SSE and long polls keep
// working — while retaining a bounded copy.
func streamAndCapture(w http.ResponseWriter, src io.Reader, limit int) (n int, truncated bool, captured []byte, err error) {
	flusher, _ := w.(http.Flusher)
	var buf bytes.Buffer
	chunk := make([]byte, 32*1024)
	for {
		rn, rerr := src.Read(chunk)
		if rn > 0 {
			n += rn
			if room := limit - buf.Len(); room > 0 {
				buf.Write(chunk[:min(rn, room)])
				if rn > room {
					truncated = true
				}
			} else if limit > 0 {
				truncated = true
			}
			if _, werr := w.Write(chunk[:rn]); werr != nil {
				return n, truncated, buf.Bytes(), werr
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			return n, truncated, buf.Bytes(), rerr
		}
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func applyEdit(h http.Header, v capture.Verdict) {
	for _, k := range v.RemoveHeaders {
		h.Del(k)
	}
	for k, val := range v.SetHeaders {
		h.Set(k, val)
	}
}

func (s *Server) decide(f *capture.Flow, d capture.Decision) {
	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) { f.Decision = d })
}

// fail records why a flow could not complete and tells the client the same thing, so the app's
// own error message names the real cause instead of a bare connection reset.
func (s *Server) fail(f *capture.Flow, w http.ResponseWriter, status int, what string, err error) {
	msg := what
	if err != nil {
		msg += ": " + err.Error()
	}
	body, _ := json.Marshal(map[string]any{"error": "ntcept: " + msg})
	s.Store.Touch(f, capture.EventFlowUpdate, func(fl *capture.Flow) {
		fl.Status, fl.Error, fl.ResLen = status, msg, len(body)
		fl.ResBody = body
		fl.MS = time.Since(fl.Start).Milliseconds()
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Ntcept-Error", strings.ReplaceAll(msg, "\n", " "))
	w.WriteHeader(status)
	_, _ = w.Write(body)
	s.Store.Finish(f, nil)
}

func (s *Server) writeSynthetic(w http.ResponseWriter, f *capture.Flow, v capture.Verdict, started time.Time) {
	status := v.Status
	if status == 0 {
		status = 200
	}
	var body []byte
	if v.Body != nil {
		body = []byte(*v.Body)
	}
	for k, val := range v.SetHeaders {
		w.Header().Set(k, val)
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
	resHdr, _ := redact.Headers(w.Header())
	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.Status, f.ResLen, f.ResBody = status, len(body), body
		f.ResHdr = resHdr
		f.MS = time.Since(started).Milliseconds()
	})
	s.Store.Finish(f, nil)
}

// scriptResponse lets a loaded script judge an HTTP response. It buffers the body once and returns
// true when it has fully handled the response; false means pass or hold — the body is restored so
// the manual/normal paths can take over.
func (s *Server) scriptResponse(w http.ResponseWriter, f *capture.Flow, res *http.Response, host string, started time.Time, sent sentRequest) (done bool) {
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxHoldBody))
	readable, wasEncoded := decodeBody(body, res.Header.Get("Content-Encoding"))
	view, _ := redact.Body(readable, res.Header.Get("Content-Type"))
	resHdr, _ := redact.Headers(res.Header)

	r2, ok := s.Script.Eval(script.Event{
		Hook: "on_response", Exchange: f.ID, Kind: "http", Proto: "http", Host: host, Direction: "response",
		Method: sent.Method, URL: sent.URL, Status: res.StatusCode, Headers: resHdr, Body: capture.Printable(view),
	})
	if ok && len(r2.Logs) > 0 {
		s.attachScriptLogs(f, r2.Logs)
	}
	if !ok || r2.Action == script.Hold {
		res.Body = io.NopCloser(bytes.NewReader(body)) // restore for the caller
		return false
	}
	if r2.DelayMS > 0 {
		time.Sleep(time.Duration(r2.DelayMS) * time.Millisecond)
	}
	switch r2.Action {
	case script.Drop:
		s.decide(f, capture.DecisionDrop)
		hijackClose(w)
		s.Store.Finish(f, nil)
		return true
	case script.Record:
		// Forward the real body, but store the redacted rendering the script asked for.
		s.writeResponse(w, f, res, body, started, recordText(string(view), r2))
		return true
	case script.Edit, script.Respond:
		v := verdictFromScript(r2)
		applyEdit(res.Header, v)
		if v.Status != 0 {
			res.StatusCode = v.Status
		}
		if v.Body != nil {
			body = []byte(*v.Body)
			if wasEncoded {
				res.Header.Del("Content-Encoding")
			}
		}
		s.decide(f, capture.Decision(r2.Action))
		s.writeResponse(w, f, res, body, started, "")
		return true
	}
	res.Body = io.NopCloser(bytes.NewReader(body)) // pass: let the caller write it
	return false
}

// writeResponse sends a (possibly edited) response to the client and stores it, with an optional
// override for the stored body — used by record to keep the real body on the wire but a redacted
// copy in the buffer.
func (s *Server) writeResponse(w http.ResponseWriter, f *capture.Flow, res *http.Response, body []byte, started time.Time, storedOverride string) {
	for _, h := range hopByHop {
		res.Header.Del(h)
	}
	res.Header.Del("Content-Length")
	copyHeaders(w.Header(), res.Header)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(body)

	finalHdr, _ := redact.Headers(res.Header)
	stored, _ := decodeBody(body, res.Header.Get("Content-Encoding"))
	storedBody, storedRep := redact.Body(stored, res.Header.Get("Content-Type"))
	if storedOverride != "" {
		storedBody = []byte(storedOverride)
	}
	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.Status = res.StatusCode
		f.ResHdr = finalHdr
		f.ResLen = len(body)
		f.ResBody = storedBody
		f.Redaction.Merge(storedRep)
		f.MS = time.Since(started).Milliseconds()
	})
	s.Store.Finish(f, nil)
}

// sentRequest is what produced a held response.
type sentRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    string
}

func (s *Server) holdResponse(w http.ResponseWriter, f *capture.Flow, res *http.Response, host string, started time.Time, sent sentRequest) {
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxHoldBody))
	readable, wasEncoded := decodeBody(body, res.Header.Get("Content-Encoding"))
	heldHdr, _ := redact.Headers(res.Header)
	heldBody, _ := redact.Body(readable, res.Header.Get("Content-Type"))
	v, ok := s.hold(f, &capture.Held{
		FlowID: f.ID, Stage: capture.StageResponse, Host: host, Status: res.StatusCode,
		Headers: heldHdr, Body: capture.Printable(heldBody),
		Method: sent.Method, URL: sent.URL, ReqHeaders: sent.Headers, ReqBody: sent.Body,
	})
	decision := capture.DecisionPass
	if ok {
		switch v.Action {
		case capture.ActionDrop:
			s.decide(f, capture.DecisionDrop)
			hijackClose(w)
			s.Store.Finish(f, nil)
			return
		case capture.ActionRespond, capture.ActionEdit:
			decision = capture.Decision(v.Action)
			applyEdit(res.Header, v)
			if v.Status != 0 {
				res.StatusCode = v.Status
			}
			if v.Body != nil {
				// The replacement is plain text; whatever encoding the origin used no longer
				// describes it, and leaving the header would make the client fail to decode.
				body = []byte(*v.Body)
				if wasEncoded {
					res.Header.Del("Content-Encoding")
				}
			}
		}
	}
	for _, h := range hopByHop {
		res.Header.Del(h)
	}
	res.Header.Del("Content-Length")
	copyHeaders(w.Header(), res.Header)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(body)

	finalHdr, _ := redact.Headers(res.Header)
	stored, _ := decodeBody(body, res.Header.Get("Content-Encoding"))
	storedBody, storedRep := redact.Body(stored, res.Header.Get("Content-Type"))
	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.Status = res.StatusCode
		f.ResHdr = finalHdr
		f.ResLen = len(body)
		f.ResBody = storedBody
		f.Redaction.Merge(storedRep)
		f.Decision = decision
		f.MS = time.Since(started).Milliseconds()
	})
	s.Store.Finish(f, nil)
}

// hold parks an exchange and waits for a verdict. A hold that expires is recorded as such: a run
// where nobody answered is not the run anyone thinks it was.
func (s *Server) hold(f *capture.Flow, h *capture.Held) (capture.Verdict, bool) {
	ch := s.Queue.Park(h)
	s.Store.Publish(capture.Event{Type: capture.EventHeldNew, Held: h})
	budget := time.Duration(s.HoldMS.Load()) * time.Millisecond
	select {
	case v := <-ch:
		s.Store.Publish(capture.Event{Type: capture.EventHeldGone, Held: h})
		return v, true
	case <-time.After(budget):
		s.Queue.Forget(h.ID)
		s.Store.Publish(capture.Event{Type: capture.EventHeldGone, Held: h})
		s.decide(f, capture.DecisionHoldTimeout)
		return capture.Verdict{}, false
	}
}

// hijackClose kills the connection outright, the way a dropped packet would.
func hijackClose(w http.ResponseWriter) {
	if hj, ok := w.(http.Hijacker); ok {
		if c, _, err := hj.Hijack(); err == nil {
			_ = c.Close()
			return
		}
	}
	// HTTP/2 has no connection to drop; a stream error is the closest equivalent.
	panic(http.ErrAbortHandler)
}
