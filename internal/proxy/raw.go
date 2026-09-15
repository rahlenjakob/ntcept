package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"time"

	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/decode"
)

// relayTCP handles a tunnel carrying something that is not HTTP: Redis, Postgres, MySQL, or
// anything else. Bytes pass through untouched; a copy goes to a protocol decoder.
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

	done := make(chan struct{}, 2)
	go func() { s.pipe(f, capture.Out, br, up, codec.Client, codec); done <- struct{}{} }()
	go func() { s.pipe(f, capture.In, up, c, codec.Server, codec); done <- struct{}{} }()
	<-done
	_ = c.SetDeadline(time.Now())
	_ = up.SetDeadline(time.Now())

	s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) {
		f.MS = time.Since(started).Milliseconds()
	})
	s.Store.Finish(f, nil)
}

func (s *Server) pipe(f *capture.Flow, dir capture.Dir, src io.Reader, dst io.Writer,
	stream decode.Stream, codec *decode.Codec) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, werr := dst.Write(chunk); werr != nil {
				return
			}
			for _, msg := range stream.Feed(chunk) {
				s.Store.Append(f, capture.Message{T: time.Now(), Dir: dir, Decoded: msg})
			}
			// What a connection is speaking is often not known when it opens — a server that
			// greets first says nothing until it does, and the port may be anyone's choice. So
			// the label is corrected once the protocol gives itself away.
			if name := codec.Protocol(); name != f.Path {
				s.Store.Touch(f, capture.EventFlowUpdate, func(f *capture.Flow) { f.Path = name })
			}
		}
		if err != nil {
			return
		}
	}
}
