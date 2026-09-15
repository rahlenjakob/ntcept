package proxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
)

// A minimal Postgres wire helper: the startup packet that identifies the protocol, and a simple
// Query message, are all the test needs to drive the framed hold path.
func pgStartupPkt() []byte {
	params := append([]byte("user\x00postgres\x00database\x00app\x00"), 0)
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body, 196608) // protocol 3.0
	copy(body[4:], params)
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(4+len(body)))
	copy(out[4:], body)
	return out
}

func pgQueryPkt(sql string) []byte {
	payload := append([]byte(sql), 0)
	out := make([]byte, 5+len(payload))
	out[0] = 'Q'
	binary.BigEndian.PutUint32(out[1:], uint32(4+len(payload)))
	copy(out[5:], payload)
	return out
}

// dbHarness stands up a proxy in front of a recording upstream and connects an "application" to it
// through relayTCP, exactly as an attached process's TCP connection would arrive.
type dbHarness struct {
	srv     *Server
	app     net.Conn
	upRecv  *recorder
	upReady chan net.Conn // the accepted upstream connection, so a test can send replies
}

type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// pgDataRow builds a DataRow message with the given text column values.
func pgDataRow(cols ...string) []byte {
	payload := []byte{byte(len(cols) >> 8), byte(len(cols))}
	for _, c := range cols {
		n := uint32(len(c))
		payload = append(payload, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		payload = append(payload, c...)
	}
	out := make([]byte, 5+len(payload))
	out[0] = 'D'
	binary.BigEndian.PutUint32(out[1:], uint32(4+len(payload)))
	copy(out[5:], payload)
	return out
}

func (r *recorder) bytesReceived() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}

func newDBHarness(t *testing.T) *dbHarness {
	t.Helper()
	authority, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := capture.NewStore(16<<20, 1<<20)
	srv := New(store, authority)

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	upReady := make(chan net.Conn, 1)
	go func() {
		uc, err := upLn.Accept()
		if err != nil {
			return
		}
		upReady <- uc
		buf := make([]byte, 4096)
		for {
			n, err := uc.Read(buf)
			if n > 0 {
				rec.mu.Lock()
				rec.buf.Write(buf[:n])
				rec.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	app, proxySide := net.Pipe()
	host, portStr, _ := net.SplitHostPort(upLn.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	go srv.HandleTransparent(proxySide, host, port)

	t.Cleanup(func() { app.Close(); upLn.Close() })
	return &dbHarness{srv: srv, app: app, upRecv: rec, upReady: upReady}
}

// waitHeld polls the hold queue until one message is parked, or fails.
func (h *dbHarness) waitHeld(t *testing.T) *capture.Held {
	t.Helper()
	for i := 0; i < 200; i++ {
		if held := h.srv.Queue.List(); len(held) > 0 {
			return held[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no message was held")
	return nil
}

// sendStartupAndQuery writes the two client messages, best-effort. It runs on its own goroutine
// (net.Pipe writes block until read), so it must not touch *testing.T; a lost write surfaces as the
// downstream assertion timing out instead.
func (h *dbHarness) sendStartupAndQuery(sql string) {
	_, _ = h.app.Write(pgStartupPkt())
	_, _ = h.app.Write(pgQueryPkt(sql))
}

func TestPostgresHoldForward(t *testing.T) {
	h := newDBHarness(t)
	h.srv.HoldRequests.Store(true)
	go h.sendStartupAndQuery("select 1")

	held := h.waitHeld(t)
	if held.Proto != "postgres" || held.MsgKind != "Query" {
		t.Fatalf("held the wrong message: proto=%q kind=%q", held.Proto, held.MsgKind)
	}
	h.srv.Queue.Release(held.ID, capture.Verdict{Action: capture.ActionForward})

	waitFor(t, func() bool { return bytes.Contains(h.upRecv.bytesReceived(), []byte("select 1")) },
		"upstream never received the forwarded query")
}

func TestPostgresHoldDropTearsDownConnection(t *testing.T) {
	h := newDBHarness(t)
	h.srv.HoldRequests.Store(true)
	go h.sendStartupAndQuery("delete from orders")

	held := h.waitHeld(t)
	h.srv.Queue.Release(held.ID, capture.Verdict{Action: capture.ActionDrop})

	// The connection is torn down, so a read on the app side ends.
	h.app.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := h.app.Read(make([]byte, 16)); err == nil {
		t.Fatal("expected the dropped connection to close")
	}
	if bytes.Contains(h.upRecv.bytesReceived(), []byte("delete from orders")) {
		t.Fatal("a dropped query still reached the server")
	}
}

func TestPostgresHoldEditRewritesQuery(t *testing.T) {
	h := newDBHarness(t)
	h.srv.HoldRequests.Store(true)
	go h.sendStartupAndQuery("select * from users")

	held := h.waitHeld(t)
	replacement := capture.Printable(pgQueryPkt("select * from users where id = 1"))
	h.srv.Queue.Release(held.ID, capture.Verdict{Action: capture.ActionEdit, Raw: &replacement})

	waitFor(t, func() bool { return bytes.Contains(h.upRecv.bytesReceived(), []byte("where id = 1")) },
		"upstream never received the edited query")
	if bytes.Contains(h.upRecv.bytesReceived(), []byte("from users\x00")) {
		t.Fatal("the original query reached the server as well as the edit")
	}
}

func TestPostgresHoldRespondAnswersLocally(t *testing.T) {
	h := newDBHarness(t)
	h.srv.HoldRequests.Store(true)

	got := make(chan []byte, 1)
	go func() {
		// Read the synthesized error the application should receive.
		buf := make([]byte, 4096)
		h.app.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := h.app.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
	}()
	go h.sendStartupAndQuery("select secret from vault")

	held := h.waitHeld(t)
	h.srv.Queue.Release(held.ID, capture.Verdict{
		Action: capture.ActionRespond,
		Error:  &capture.ProtoError{Code: "40001", Message: "injected by ntcept"},
	})

	select {
	case reply := <-got:
		if len(reply) == 0 || reply[0] != 'E' {
			t.Fatalf("expected an ErrorResponse ('E'), got %q", reply)
		}
		if !bytes.Contains(reply, []byte("injected by ntcept")) || !bytes.Contains(reply, []byte("40001")) {
			t.Fatalf("error did not carry the injected fields: %q", reply)
		}
		if !bytes.Contains(reply, []byte{'Z', 0, 0, 0, 5, 'I'}) {
			t.Fatalf("expected a trailing ReadyForQuery, got %q", reply)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("application never received a synthesized reply")
	}
	if bytes.Contains(h.upRecv.bytesReceived(), []byte("select secret")) {
		t.Fatal("an answered-locally query still reached the server")
	}
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}

func TestPostgresHoldResponseEditsRow(t *testing.T) {
	h := newDBHarness(t)
	h.srv.HoldResponses.Store(true) // hold what the server sends back, not the query
	go h.sendStartupAndQuery("select * from orders")

	uc := <-h.upReady
	waitFor(t, func() bool { return bytes.Contains(h.upRecv.bytesReceived(), []byte("select * from orders")) },
		"query never reached upstream")

	// The server returns one row; the app should see the edited version.
	go func() { _, _ = uc.Write(pgDataRow("1", "ada@example.com", "4900", "paid")) }()

	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		h.app.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := h.app.Read(buf)
		got <- append([]byte(nil), buf[:n]...)
	}()

	held := h.waitHeld(t)
	if held.MsgKind != "DataRow" || len(held.Row) != 4 {
		t.Fatalf("expected a 4-column DataRow, got kind=%q row=%d", held.MsgKind, len(held.Row))
	}
	if held.Row[2] == nil || *held.Row[2] != "4900" {
		t.Fatalf("row value not decoded: %v", held.Row[2])
	}
	newTotal := "999999"
	edited := []*string{held.Row[0], held.Row[1], &newTotal, held.Row[3]}
	h.srv.Queue.Release(held.ID, capture.Verdict{Action: capture.ActionEdit, Row: edited})

	select {
	case b := <-got:
		if !bytes.Contains(b, []byte("999999")) {
			t.Fatalf("app did not receive the edited row: %q", b)
		}
		if bytes.Contains(b, []byte("4900")) {
			t.Fatalf("the original value is still in the row: %q", b)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("app never received the row")
	}
}
