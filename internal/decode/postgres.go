package decode

import (
	"fmt"
	"strconv"
	"strings"
)

// PostgreSQL's wire protocol, both directions.
//
// The extended query protocol is the one that matters. Almost nothing sends a plain Query any
// more — drivers and ORMs parse a statement once and then bind parameters to it, so the SQL says
// `where id = $1` and the value of $1 travels separately, in a Bind message. Rendering Bind as
// the word "Bind" is therefore a way of showing everything except the part someone is looking
// for, which is what this did before.
//
// Several message types share a letter between the two directions — D is Describe from the
// client and DataRow from the server, E is Execute and ErrorResponse, C is Close and
// CommandComplete, S is Sync and ParameterStatus — so nothing can be rendered without knowing
// which way it was travelling.

type pg struct {
	buf     []byte
	client  bool
	started bool
	// stmts remembers the SQL a prepared statement was parsed from, so a later Bind can be
	// read against the query it belongs to rather than as a bag of values.
	stmts map[string]string
	// portals maps a portal to the statement it was bound from, for the same reason.
	portals map[string]string
}

func (p *pg) Feed(b []byte) []string {
	p.buf = append(p.buf, b...)
	var out []string
	for {
		// The client's first message has no type byte: it is a length and a protocol version.
		if p.client && !p.started {
			if len(p.buf) < 8 {
				break
			}
			n := int(be32(p.buf))
			if n < 8 || len(p.buf) < n {
				break
			}
			out = append(out, p.startup(p.buf[:n]))
			p.buf = p.buf[n:]
			continue
		}
		if len(p.buf) < 5 {
			break
		}
		typ := p.buf[0]
		n := int(be32(p.buf[1:])) + 1
		if n < 5 || len(p.buf) < n {
			break
		}
		if s := p.render(typ, p.buf[5:n]); s != "" {
			out = append(out, s)
		}
		p.buf = p.buf[n:]
		p.started = true
	}
	if len(p.buf) > 4<<20 {
		p.buf = nil
	}
	return out
}

// startup renders the first client message, which also says whether the rest of this connection
// will be readable at all.
func (p *pg) startup(msg []byte) string {
	switch code := be32(msg[4:]); code {
	case 80877103:
		// Everything after this is TLS, and ntcept does not terminate it — the connection was
		// already inside a tunnel by the time it got here. Saying so is better than showing
		// the encrypted bytes that follow as an unreadable stream.
		return "SSLRequest (the rest of this connection is encrypted)"
	case 80877102:
		return "CancelRequest"
	case 80877104:
		return "GSSENCRequest"
	}
	p.started = true
	// Startup parameters are alternating key/value C strings: user, database, application_name.
	fields := cstrings(msg[8:])
	var parts []string
	for i := 0; i+1 < len(fields); i += 2 {
		switch fields[i] {
		case "user", "database", "application_name":
			parts = append(parts, fields[i]+"="+fields[i+1])
		}
	}
	if len(parts) == 0 {
		return "Startup"
	}
	return "Startup " + strings.Join(parts, " ")
}

var pgNames = map[byte]string{
	'S': "Sync", 'H': "Flush", 'X': "Terminate", 'c': "CopyDone", 'f': "CopyFail",
	'n': "NoData", 's': "PortalSuspended", '1': "ParseComplete", '2': "BindComplete",
	'3': "CloseComplete", 'I': "EmptyQueryResponse", 'G': "CopyInResponse",
	'W': "CopyBothResponse", 'v': "NegotiateProtocolVersion",
}

func (p *pg) render(typ byte, payload []byte) string {
	if p.client {
		return p.renderClient(typ, payload)
	}
	return p.renderServer(typ, payload)
}

func (p *pg) renderClient(typ byte, payload []byte) string {
	switch typ {
	case 'Q':
		return "Query " + sql(trimZero(payload))
	case 'P':
		return p.parse(payload)
	case 'B':
		return p.bind(payload)
	case 'E':
		s := cstrings(payload)
		portal := ""
		if len(s) > 0 {
			portal = s[0]
		}
		if q, ok := p.portals[portal]; ok {
			return "Execute " + sql(q)
		}
		if portal == "" {
			return "Execute"
		}
		return "Execute " + quote(portal)
	case 'D':
		if len(payload) > 1 {
			what, name := "statement", trimZero(payload[1:])
			if payload[0] == 'P' {
				what = "portal"
			}
			if name == "" {
				return "Describe " + what
			}
			return "Describe " + what + " " + quote(name)
		}
		return "Describe"
	case 'C':
		if len(payload) > 1 {
			what := "statement"
			if payload[0] == 'P' {
				what = "portal"
			}
			return "Close " + what
		}
		return "Close"
	case 'p':
		// The contents are a password, a SASL exchange or a GSS token. None of it should be
		// rendered, and the length alone says which stage authentication is at.
		return fmt.Sprintf("PasswordMessage (%d bytes, not shown)", len(payload))
	case 'd':
		return fmt.Sprintf("CopyData (%d bytes)", len(payload))
	}
	if name, ok := pgNames[typ]; ok {
		return name
	}
	return fmt.Sprintf("msg(%c)", typ)
}

// parse reads a Parse message and remembers the statement, so a later Bind can be shown against
// the SQL it fills in.
func (p *pg) parse(payload []byte) string {
	name, rest, ok := cstring(payload)
	if !ok {
		return "Parse"
	}
	query, _, ok := cstring(rest)
	if !ok {
		return "Parse"
	}
	if p.stmts == nil {
		p.stmts = map[string]string{}
	}
	// An unnamed statement is reused constantly; remembering it is what makes the next Bind
	// readable.
	p.stmts[name] = query
	if name == "" {
		return "Parse " + sql(query)
	}
	return "Parse " + quote(name) + " " + sql(query)
}

// bind reads a Bind message: which statement, into which portal, and the parameter values.
//
// The values are the point. A query logged as `where email = $1` says nothing about which user
// was being looked up; the Bind that follows says exactly that.
func (p *pg) bind(payload []byte) string {
	portal, rest, ok := cstring(payload)
	if !ok {
		return "Bind"
	}
	stmt, rest, ok := cstring(rest)
	if !ok {
		return "Bind"
	}
	if p.portals == nil {
		p.portals = map[string]string{}
	}
	if q, known := p.stmts[stmt]; known {
		p.portals[portal] = q
	}

	// Format codes for the parameters, then the parameters themselves.
	formats, rest, ok := readInt16s(rest)
	if !ok {
		return p.bindLabel(stmt, nil)
	}
	if len(rest) < 2 {
		return p.bindLabel(stmt, nil)
	}
	count := int(be16(rest))
	rest = rest[2:]
	params := make([]string, 0, count)
	for i := 0; i < count && len(rest) >= 4; i++ {
		n := int(int32(be32(rest)))
		rest = rest[4:]
		if n < 0 {
			params = append(params, "NULL")
			continue
		}
		if len(rest) < n {
			break
		}
		binary := len(formats) == 1 && formats[0] == 1
		if i < len(formats) {
			binary = formats[i] == 1
		}
		params = append(params, pgParam(rest[:n], binary))
		rest = rest[n:]
	}
	return p.bindLabel(stmt, params)
}

func (p *pg) bindLabel(stmt string, params []string) string {
	label := "Bind"
	if q, ok := p.stmts[stmt]; ok {
		label = "Bind " + sql(q)
	} else if stmt != "" {
		label = "Bind " + quote(stmt)
	}
	if len(params) == 0 {
		return label
	}
	var b strings.Builder
	b.WriteString(label)
	b.WriteString(" [")
	for i, v := range params {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "$%d=%s", i+1, v)
	}
	b.WriteString("]")
	return b.String()
}

// pgParam renders one bound value. Text parameters are what almost every driver sends; binary
// ones are shown as their bytes rather than guessed at, because the type is not in this message.
func pgParam(b []byte, binary bool) string {
	if !binary {
		return clip(quote(string(b)), 96)
	}
	switch len(b) {
	case 0:
		return `""`
	case 2:
		return strconv.Itoa(int(int16(be16(b))))
	case 4:
		return strconv.Itoa(int(int32(be32(b))))
	case 8:
		return strconv.FormatInt(int64(be64(b)), 10)
	}
	if printable(string(b)) {
		return clip(quote(string(b)), 96)
	}
	return fmt.Sprintf("0x%x", clipBytes(b, 16))
}

func (p *pg) renderServer(typ byte, payload []byte) string {
	switch typ {
	case 'E':
		return "ErrorResponse " + pgFields(payload)
	case 'N':
		return "Notice " + pgFields(payload)
	case 'C':
		return "CommandComplete " + trimZero(payload)
	case 'D':
		return pgDataRow(payload)
	case 'T':
		return pgRowDescription(payload)
	case 'Z':
		if len(payload) == 1 {
			switch payload[0] {
			case 'I':
				return "ReadyForQuery (idle)"
			case 'T':
				return "ReadyForQuery (in transaction)"
			case 'E':
				return "ReadyForQuery (transaction failed)"
			}
		}
		return "ReadyForQuery"
	case 'R':
		return pgAuth(payload)
	case 'S':
		f := cstrings(payload)
		if len(f) >= 2 {
			return "ParameterStatus " + f[0] + "=" + f[1]
		}
		return "ParameterStatus"
	case 'K':
		return "BackendKeyData"
	case 'A':
		f := cstrings(payload)
		if len(f) >= 1 {
			return "Notification " + strings.Join(f, " ")
		}
		return "Notification"
	case 't':
		return "ParameterDescription"
	case 'd':
		return fmt.Sprintf("CopyData (%d bytes)", len(payload))
	}
	if name, ok := pgNames[typ]; ok {
		return name
	}
	return fmt.Sprintf("msg(%c)", typ)
}

// pgFields renders an error or notice. The severity, the SQLSTATE and the message are what
// someone reads; the rest — file, line, routine — is about postgres's own source and is noise.
func pgFields(payload []byte) string {
	var severity, code, message, detail, hint string
	rest := payload
	for len(rest) > 1 {
		kind := rest[0]
		val, next, ok := cstring(rest[1:])
		if !ok {
			break
		}
		rest = next
		switch kind {
		case 'S':
			severity = val
		case 'C':
			code = val
		case 'M':
			message = val
		case 'D':
			detail = val
		case 'H':
			hint = val
		}
	}
	var parts []string
	if severity != "" {
		parts = append(parts, severity)
	}
	if code != "" {
		parts = append(parts, code)
	}
	if message != "" {
		parts = append(parts, message)
	}
	if detail != "" {
		parts = append(parts, "detail: "+detail)
	}
	if hint != "" {
		parts = append(parts, "hint: "+hint)
	}
	if len(parts) == 0 {
		return "(no detail)"
	}
	return strings.Join(parts, " ")
}

func pgAuth(payload []byte) string {
	if len(payload) < 4 {
		return "Auth"
	}
	switch be32(payload) {
	case 0:
		return "AuthOK"
	case 3:
		return "Auth cleartext password requested"
	case 5:
		return "Auth md5 password requested"
	case 10:
		return "Auth SASL requested (" + strings.Join(cstrings(payload[4:]), " ") + ")"
	case 11:
		return "Auth SASL continue"
	case 12:
		return "Auth SASL final"
	}
	return fmt.Sprintf("Auth (method %d)", be32(payload))
}

// pgRowDescription names the columns a result is about to arrive in.
func pgRowDescription(payload []byte) string {
	if len(payload) < 2 {
		return "RowDescription"
	}
	n := int(be16(payload))
	rest := payload[2:]
	cols := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name, next, ok := cstring(rest)
		if !ok || len(next) < 18 {
			break
		}
		cols = append(cols, name)
		rest = next[18:]
	}
	if len(cols) == 0 {
		return fmt.Sprintf("RowDescription (%d columns)", n)
	}
	return "RowDescription " + clip(strings.Join(cols, ", "), 120)
}

// pgDataRow renders a result row's values, which is the answer to whatever was asked.
func pgDataRow(payload []byte) string {
	if len(payload) < 2 {
		return "DataRow"
	}
	n := int(be16(payload))
	rest := payload[2:]
	vals := make([]string, 0, n)
	for i := 0; i < n && len(rest) >= 4; i++ {
		size := int(int32(be32(rest)))
		rest = rest[4:]
		if size < 0 {
			vals = append(vals, "NULL")
			continue
		}
		if len(rest) < size {
			break
		}
		vals = append(vals, pgParam(rest[:size], false))
		rest = rest[size:]
	}
	if len(vals) == 0 {
		return fmt.Sprintf("DataRow (%d columns)", n)
	}
	return "DataRow " + clip(strings.Join(vals, ", "), 120)
}
