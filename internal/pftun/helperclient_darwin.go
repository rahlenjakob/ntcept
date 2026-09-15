//go:build darwin

package pftun

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// helperClient is ntcept's end of the channel to the privileged helper.
//
// Everything on it is lock-step: ntcept asks, the helper answers, and nothing else is written in
// between. That is enough because the only message that expects a reply is a NAT lookup — `tell`
// messages get none — so the reader in natlook only ever sees natlook replies, and h.mu keeps at
// most one outstanding. It saves carrying request ids across a privilege boundary for no benefit.
//
// INVARIANT: exactly one reply-bearing message type. If a second is ever added, this lock-step
// scheme breaks — a reply could be matched to the wrong request — and the channel must grow
// request ids before that change lands. Adding a `tell`-style (reply-less) message is fine.
type helperClient struct {
	mu   sync.Mutex
	conn *net.UnixConn
	r    *bufio.Reader
}

func newHelperClient(c *net.UnixConn) *helperClient {
	return &helperClient{conn: c, r: bufio.NewReader(c)}
}

// tell sends a message the helper does not answer.
func (h *helperClient) tell(m handover) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err = h.conn.Write(append(b, '\n'))
	return err
}

// natlook asks what a redirected connection was originally aimed at.
func (h *helperClient) natlook(req NatlookReq) (*net.TCPAddr, error) {
	b, err := json.Marshal(handover{Natlook: &req})
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := h.conn.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	_ = h.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer h.conn.SetReadDeadline(time.Time{})

	line, err := h.r.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	var reply NatlookReply
	if err := json.Unmarshal(line, &reply); err != nil {
		return nil, err
	}
	if !reply.OK {
		return nil, fmt.Errorf("%s", reply.Err)
	}
	return &net.TCPAddr{IP: net.ParseIP(reply.IP), Port: reply.Port}, nil
}
