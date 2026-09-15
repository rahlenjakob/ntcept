package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/rahlenjakob/ntcept/internal/capture"
)

// proxyWebSocket completes the upgrade against the real server, then relays frames while
// decoding a copy of each one.
//
// The client's permessage-deflate offer is dropped on the way upstream: an inspector that can
// only show you compressed payloads is not an inspector. Everything else is passed verbatim.
func (s *Server) proxyWebSocket(w http.ResponseWriter, r *http.Request, t target, u *url.URL) {
	host, port := splitHostPort(u.Host, defaultPort(u.Scheme))
	f := s.Store.Begin(capture.KindWS, host, port)
	started := time.Now()
	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.Proto, f.TLS, f.Via = capture.ProtoWS, t.tls, t.via
		f.Method, f.URL, f.Path, f.Query = r.Method, u.String(), u.Path, u.RawQuery
		f.Client = r.RemoteAddr
	})

	dialCtx, cancelDial := context.WithTimeout(r.Context(), 20*time.Second)
	up, err := s.dialWebSocket(dialCtx, u.Scheme, u.Host)
	cancelDial()
	if err != nil {
		s.fail(f, w, 502, "websocket dial", err)
		return
	}
	defer up.Close()

	out := r.Clone(r.Context())
	out.URL = u
	out.RequestURI = ""
	out.Header = r.Header.Clone()
	out.Header.Del("Sec-WebSocket-Extensions")
	if err := out.Write(up); err != nil {
		s.fail(f, w, 502, "websocket handshake", err)
		return
	}
	upBuf := bufio.NewReader(up)
	res, err := http.ReadResponse(upBuf, out)
	if err != nil {
		s.fail(f, w, 502, "websocket handshake reply", err)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		s.fail(f, w, 500, "websocket needs HTTP/1.1", nil)
		return
	}
	client, clientBuf, err := hj.Hijack()
	if err != nil {
		s.fail(f, w, 500, "hijack", err)
		return
	}
	defer client.Close()

	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.Status = res.StatusCode
	})
	if err := res.Write(client); err != nil {
		s.Store.Finish(f, err)
		return
	}
	if res.StatusCode != http.StatusSwitchingProtocols {
		s.Store.Finish(f, nil)
		return
	}

	done := make(chan error, 2)
	go func() { done <- s.pumpFrames(f, capture.Out, clientBuf.Reader, up) }()
	go func() { done <- s.pumpFrames(f, capture.In, upBuf, client) }()
	<-done
	_ = client.SetReadDeadline(time.Now())
	_ = up.SetReadDeadline(time.Now())

	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.MS = time.Since(started).Milliseconds()
	})
	s.Store.Finish(f, nil)
}

// dialWebSocket opens the upstream half of an upgrade. It goes through dialUpstream like every
// other outbound connection, so host mapping and loopback resolution apply here too — a
// WebSocket to a service on localhost is as ordinary as an HTTP call to one.
func (s *Server) dialWebSocket(ctx context.Context, scheme, hostport string) (net.Conn, error) {
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		port := "80"
		if scheme == "https" || scheme == "wss" {
			port = "443"
		}
		hostport = net.JoinHostPort(hostport, port)
	}
	raw, err := s.dialUpstream(ctx, hostport)
	if err != nil {
		return nil, err
	}
	if scheme != "https" && scheme != "wss" {
		return raw, nil
	}
	host, _, _ := net.SplitHostPort(hostport)
	tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if s.upstreamTLS != nil {
		tc = s.upstreamTLS.Clone()
		if tc.ServerName == "" {
			tc.ServerName = host
		}
	}
	client := tls.Client(raw, tc)
	if err := client.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return client, nil
}

var opcodeNames = map[byte]capture.Opcode{
	0x1: capture.OpText, 0x2: capture.OpBinary,
	0x8: capture.OpClose, 0x9: capture.OpPing, 0xA: capture.OpPong,
}

// pumpFrames relays raw frames verbatim while recording a decoded copy of each payload.
func (s *Server) pumpFrames(f *capture.Flow, dir capture.Dir, src *bufio.Reader, dst io.Writer) error {
	var pending []byte
	var pendingOp byte
	var pendingAt time.Time
	for {
		raw, fin, opcode, payload, err := readFrame(src)
		if err != nil {
			return err
		}
		now := time.Now()
		// A fragment that does not complete a message is forwarded straight away and its arrival
		// time remembered; only the assembled message is recorded, on the final fragment.
		if opcode != 0x0 && !fin {
			pending, pendingOp, pendingAt = append([]byte(nil), payload...), opcode, now
			if _, err := dst.Write(raw); err != nil {
				return err
			}
			continue
		}
		if opcode == 0x0 && !fin {
			pending = append(pending, payload...)
			if _, err := dst.Write(raw); err != nil {
				return err
			}
			continue
		}

		op, data, at := opcode, payload, now
		if op == 0x0 {
			op, data, at = pendingOp, append(pending, payload...), pendingAt
			pending, pendingOp = nil, 0
		}
		name, ok := opcodeNames[op]
		if !ok {
			name = capture.OpBinary
		}
		// Record before forwarding the completing frame: once it reaches the peer, the peer can
		// reply and the other direction's goroutine can record that reply. Appending first keeps
		// a frame ahead of the response it provokes, instead of racing it.
		s.Store.Append(f, capture.Message{T: at, Dir: dir, Opcode: name, Data: data})
		if _, err := dst.Write(raw); err != nil {
			return err
		}
		if op == 0x8 {
			return nil
		}
	}
}

// readFrame returns the frame's original bytes alongside its unmasked payload.
func readFrame(r *bufio.Reader) (raw []byte, fin bool, opcode byte, payload []byte, err error) {
	var h [2]byte
	if _, err = io.ReadFull(r, h[:]); err != nil {
		return
	}
	raw = append(raw, h[:]...)
	fin = h[0]&0x80 != 0
	opcode = h[0] & 0x0F
	masked := h[1]&0x80 != 0
	n := uint64(h[1] & 0x7F)

	switch n {
	case 126:
		var ext [2]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return
		}
		raw = append(raw, ext[:]...)
		n = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err = io.ReadFull(r, ext[:]); err != nil {
			return
		}
		raw = append(raw, ext[:]...)
		n = binary.BigEndian.Uint64(ext[:])
	}
	if n > 64<<20 {
		return raw, fin, opcode, nil, io.ErrUnexpectedEOF
	}

	var key [4]byte
	if masked {
		if _, err = io.ReadFull(r, key[:]); err != nil {
			return
		}
		raw = append(raw, key[:]...)
	}
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return
	}
	raw = append(raw, payload...)
	if masked {
		unmasked := make([]byte, n)
		for i := range payload {
			unmasked[i] = payload[i] ^ key[i%4]
		}
		payload = unmasked
	}
	return raw, fin, opcode, payload, nil
}
