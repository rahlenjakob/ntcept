package decode

import (
	"fmt"
	"strings"
)

// MySQL's client/server protocol.
//
// Framing alone is not much use: every packet rendered as "cmd=0x03" tells you a query happened
// without saying what it was, and an error comes back as an unreadable blob rather than the
// message the server actually sent. What matters here is the command names, the errors, and
// prepared statements — which, as in postgres, are how anything using a driver actually talks,
// so the statement text and the values bound to it arrive in separate packets.
type mysql struct {
	buf    []byte
	client bool
	// expectStmtID is set after a COM_STMT_PREPARE, so the id the server hands back can be
	// tied to the SQL it was prepared from.
	// stmts maps a prepared statement id to its SQL, shared between the two directions.
	stmts *stmtTable
	// seenHandshake suppresses rendering the initial handshake as a command packet.
	seenHandshake bool
}

// stmtTable is shared by the two directions of one connection: the server assigns the id and the
// client uses it afterwards.
type stmtTable struct {
	byID map[uint32]string
	// pending holds the SQL of a prepare whose id has not come back yet.
	pending string
}

var mysqlCmds = map[byte]string{
	0x00: "Sleep", 0x01: "Quit", 0x02: "InitDB", 0x03: "Query", 0x04: "FieldList",
	0x05: "CreateDB", 0x06: "DropDB", 0x07: "Refresh", 0x08: "Shutdown", 0x09: "Statistics",
	0x0a: "ProcessInfo", 0x0c: "Kill", 0x0d: "Debug", 0x0e: "Ping", 0x11: "ChangeUser",
	0x12: "BinlogDump", 0x13: "TableDump", 0x15: "RegisterSlave", 0x16: "StmtPrepare",
	0x17: "StmtExecute", 0x18: "StmtSendLongData", 0x19: "StmtClose", 0x1a: "StmtReset",
	0x1b: "SetOption", 0x1c: "StmtFetch", 0x1d: "Daemon", 0x1f: "ResetConnection",
}

func (m *mysql) Feed(b []byte) []string {
	m.buf = append(m.buf, b...)
	var out []string
	for {
		text, _, n, _ := m.parseOne(m.buf)
		if n == 0 {
			break
		}
		m.buf = m.buf[n:]
		if text != "" {
			out = append(out, text)
		}
	}
	if len(m.buf) > 4<<20 {
		m.buf = nil
	}
	return out
}

// Frame parses complete MySQL packets from the front of buf, which the caller owns, so a command or
// an error can be held on its way through.
func (m *mysql) Frame(buf []byte) (frames []Frame, consumed int, ok bool) {
	for {
		text, kind, n, good := m.parseOne(buf[consumed:])
		if !good {
			return frames, consumed, false
		}
		if n == 0 {
			return frames, consumed, true
		}
		frames = append(frames, Frame{
			Bytes: buf[consumed : consumed+n], Text: text, Kind: kind, Holdable: m.holdable(kind),
		})
		consumed += n
	}
}

// parseOne reads one MySQL packet from the front of buf, advancing shared prepared-statement state.
// It is byte-stateless; the buffer belongs to the caller.
func (m *mysql) parseOne(buf []byte) (text, kind string, n int, ok bool) {
	if len(buf) < 4 {
		return "", "", 0, true
	}
	ln := int(buf[0]) | int(buf[1])<<8 | int(buf[2])<<16
	total := 4 + ln
	if len(buf) < total {
		return "", "", 0, true
	}
	text = m.render(buf[3], buf[4:total])
	return text, firstToken(text), total, true
}

// holdable pauses a client command or a server error, and lets acknowledgements and result rows
// through.
func (m *mysql) holdable(kind string) bool {
	if m.client {
		switch kind {
		case "Query", "Prepare", "StmtExecute", "InitDB":
			return true
		}
		return false
	}
	return kind == "Error"
}

func (m *mysql) render(seq byte, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if m.client {
		return m.renderClient(seq, body)
	}
	return m.renderServer(seq, body)
}

func (m *mysql) renderClient(seq byte, body []byte) string {
	// Sequence 1 on the client side is the handshake response, not a command.
	if seq == 1 && !m.seenHandshake {
		m.seenHandshake = true
		if user := handshakeUser(body); user != "" {
			return "Login " + user
		}
		return "Login"
	}
	cmd := body[0]
	arg := body[1:]
	name, known := mysqlCmds[cmd]
	if !known {
		return fmt.Sprintf("packet cmd=0x%02x (%d bytes)", cmd, len(body))
	}
	switch cmd {
	case 0x03: // COM_QUERY
		return "Query " + sql(string(arg))
	case 0x16: // COM_STMT_PREPARE
		if m.stmts != nil {
			m.stmts.pending = string(arg)
		}
		return "Prepare " + sql(string(arg))
	case 0x17: // COM_STMT_EXECUTE
		return m.execute(arg)
	case 0x19: // COM_STMT_CLOSE
		if id, ok := stmtID(arg); ok {
			return fmt.Sprintf("StmtClose #%d", id)
		}
	case 0x02: // COM_INIT_DB
		return "InitDB " + quote(string(arg))
	case 0x0e, 0x01: // COM_PING, COM_QUIT
		return name
	}
	if len(arg) > 0 && printable(string(arg)) {
		return name + " " + quote(string(arg))
	}
	return name
}

// execute renders a prepared-statement execution against the SQL it was prepared from, which is
// the only way the packet means anything: on its own it is an id and a blob of bound values.
func (m *mysql) execute(arg []byte) string {
	id, ok := stmtID(arg)
	if !ok {
		return "StmtExecute"
	}
	if m.stmts != nil {
		if q, known := m.stmts.byID[id]; known {
			return "StmtExecute " + sql(q)
		}
	}
	return fmt.Sprintf("StmtExecute #%d", id)
}

func stmtID(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, true
}

func (m *mysql) renderServer(seq byte, body []byte) string {
	if seq == 0 && !m.seenHandshake && body[0] >= 9 && body[0] <= 11 {
		m.seenHandshake = true
		return "Handshake " + serverVersion(body)
	}
	switch body[0] {
	case 0xff: // ERR
		return mysqlErr(body)
	case 0x00: // OK — or a prepared-statement response, which starts the same way
		if m.stmts != nil && m.stmts.pending != "" && len(body) >= 12 {
			if id, ok := stmtID(body[1:]); ok {
				if m.stmts.byID == nil {
					m.stmts.byID = map[uint32]string{}
				}
				m.stmts.byID[id] = m.stmts.pending
				m.stmts.pending = ""
				return fmt.Sprintf("PrepareOK #%d", id)
			}
		}
		return mysqlOK(body)
	case 0xfe:
		if len(body) < 9 {
			return "EOF"
		}
	}
	return ""
}

// mysqlErr reads the error packet: the code, the SQLSTATE and the message the server sent.
func mysqlErr(body []byte) string {
	if len(body) < 3 {
		return "Error"
	}
	code := int(body[1]) | int(body[2])<<8
	rest := body[3:]
	state := ""
	// A protocol-41 error carries "#" then a five-character SQLSTATE.
	if len(rest) >= 6 && rest[0] == '#' {
		state = string(rest[1:6])
		rest = rest[6:]
	}
	msg := strings.TrimRight(string(rest), "\x00")
	if state != "" {
		return fmt.Sprintf("Error %d (%s) %s", code, state, msg)
	}
	return fmt.Sprintf("Error %d %s", code, msg)
}

// mysqlOK reads the affected-row count and last insert id, which is what a write is asked for.
func mysqlOK(body []byte) string {
	rest := body[1:]
	affected, rest, ok := lenEncInt(rest)
	if !ok {
		return "OK"
	}
	insertID, _, ok := lenEncInt(rest)
	if !ok {
		return fmt.Sprintf("OK %d row(s)", affected)
	}
	if insertID > 0 {
		return fmt.Sprintf("OK %d row(s), insert id %d", affected, insertID)
	}
	return fmt.Sprintf("OK %d row(s)", affected)
}

// lenEncInt reads MySQL's length-encoded integer.
func lenEncInt(b []byte) (uint64, []byte, bool) {
	if len(b) == 0 {
		return 0, b, false
	}
	switch n := b[0]; {
	case n < 0xfb:
		return uint64(n), b[1:], true
	case n == 0xfc && len(b) >= 3:
		return uint64(b[1]) | uint64(b[2])<<8, b[3:], true
	case n == 0xfd && len(b) >= 4:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, b[4:], true
	case n == 0xfe && len(b) >= 9:
		var v uint64
		for i := 8; i >= 1; i-- {
			v = v<<8 | uint64(b[i])
		}
		return v, b[9:], true
	}
	return 0, b, false
}

func serverVersion(body []byte) string {
	if v, _, ok := cstring(body[1:]); ok && printable(v) {
		return v
	}
	return ""
}

// handshakeUser pulls the account out of the client's handshake response, which is the one
// readable thing in it; the rest is capability flags and an auth token.
func handshakeUser(body []byte) string {
	if len(body) < 36 {
		return ""
	}
	if u, _, ok := cstring(body[32:]); ok && printable(u) {
		return u
	}
	return ""
}
