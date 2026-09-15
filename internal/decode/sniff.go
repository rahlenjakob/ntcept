package decode

import (
	"strings"
	"sync"
)

// Deciding what a connection is speaking, when the port does not say.
//
// A port is a hint and nothing more. Databases run on whatever port compose mapped them to, a
// second postgres runs on 5433, and a managed service hands out something arbitrary — so a
// decoder chosen by port alone renders most real traffic as "raw". Recognising the protocol from
// what is actually on the wire is what makes this work on someone's machine rather than in an
// example.
//
// One protocol cannot be recognised from the client at all: MySQL's server greets first, so at
// the moment the client's opening bytes arrive there are none. That is why detection is not a
// function of the first packet but of the connection — either direction can be the one that
// gives it away, and until one of them does, both are held.

// resolver decides which protocol a connection is speaking, from whichever side speaks first.
type resolver struct {
	mu   sync.Mutex
	port int
	name string // empty until decided
	// held is what arrived before the decision, replayed once it is made.
	heldClient []byte
	heldServer []byte
	client     Stream
	server     Stream
}

// maxHeld bounds what is buffered while undecided. A protocol that has not identified itself in
// this many bytes is not going to.
const maxHeld = 16 << 10

// side is one direction of a connection, and what the relay actually feeds.
type side struct {
	r      *resolver
	server bool
}

func (s *side) Feed(b []byte) []string {
	r := s.r
	r.mu.Lock()
	if r.name == "" {
		r.hold(s.server, b)
		r.decide()
		if r.name == "" {
			r.mu.Unlock()
			return nil
		}
		// Decided: replay everything held, in the order each side received it.
		clientHeld, serverHeld := r.heldClient, r.heldServer
		r.heldClient, r.heldServer = nil, nil
		cs, ss := r.client, r.server
		r.mu.Unlock()
		var out []string
		if len(clientHeld) > 0 {
			out = append(out, cs.Feed(clientHeld)...)
		}
		if len(serverHeld) > 0 {
			out = append(out, ss.Feed(serverHeld)...)
		}
		return out
	}
	stream := r.client
	if s.server {
		stream = r.server
	}
	r.mu.Unlock()
	return stream.Feed(b)
}

func (r *resolver) hold(server bool, b []byte) {
	if server {
		if len(r.heldServer) < maxHeld {
			r.heldServer = append(r.heldServer, b...)
		}
		return
	}
	if len(r.heldClient) < maxHeld {
		r.heldClient = append(r.heldClient, b...)
	}
}

// decide picks a protocol once there is enough to go on, and gives up once there is clearly
// never going to be.
func (r *resolver) decide() {
	c, s := r.heldClient, r.heldServer
	switch {
	case looksRedis(r.port, c):
		r.use("redis", &resp{}, &resp{server: true})
	case looksPostgres(r.port, c):
		r.use("postgres", &pg{client: true}, &pg{})
	case looksMySQL(r.port, s):
		// The two directions share what they know about prepared statements: the client sends
		// the SQL, the server answers with an id, and every execution afterwards names only
		// the id. Neither side can render an execution alone.
		stmts := &stmtTable{}
		r.use("mysql", &mysql{client: true, stmts: stmts}, &mysql{stmts: stmts})
	case looksMongo(r.port, c):
		r.use("mongodb", &mongo{client: true}, &mongo{})
	case len(c)+len(s) >= maxHeld:
		r.use("raw", &raw{}, &raw{})
	}
}

func (r *resolver) use(name string, client, server Stream) {
	r.name, r.client, r.server = name, client, server
}

// Framer returns the message framer for one direction of the connection, or nil when this stream
// cannot be framed: while the protocol is still undecided, once it has resolved to the raw
// fallback, or for a decoder that does not implement framing. The relay reads this to decide
// whether a direction can be held and rewritten rather than only watched.
func (c *Codec) Framer(server bool) Framer {
	r := c.r
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.name == "" || r.name == "raw" {
		return nil
	}
	stream := r.client
	if server {
		stream = r.server
	}
	if fr, ok := stream.(Framer); ok {
		return fr
	}
	return nil
}

// Protocol is what the connection turned out to be speaking, or "raw" while it is still unclear.
// The relay reads this to label the flow, which is why it has to be answerable before the
// decision is made.
func (r *resolver) Protocol() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.name == "" {
		return "raw"
	}
	return r.name
}

func looksRedis(port int, b []byte) bool {
	if port == 6379 || port == 6380 {
		return true
	}
	// A command is an array of bulk strings.
	if len(b) > 3 && b[0] == '*' && b[1] >= '1' && b[1] <= '9' {
		return true
	}
	// An inline command, which is what a health check or redis-cli --pipe sends. Matched
	// against known verbs rather than "looks like text", because most protocols look like text.
	if i := indexCRLF(b); i > 0 && i < 64 {
		switch strings.ToUpper(strings.Fields(string(b[:i]))[0]) {
		case "PING", "SUBSCRIBE", "MONITOR", "INFO", "AUTH", "HELLO", "COMMAND", "SELECT":
			return true
		}
	}
	return false
}

func looksPostgres(port int, b []byte) bool {
	if port == 5432 || port == 5433 {
		return true
	}
	// The startup packet is a length followed by a protocol version or a request code. The
	// length has to agree with the version for this to be a coincidence worth acting on.
	if len(b) >= 8 {
		n := int(be32(b))
		switch be32(b[4:]) {
		case 196608: // 3.0
			return n >= 8 && n <= 10000
		case 80877103, 80877102, 80877104: // SSL, cancel, GSSENC
			return n == 8 || n == 16
		}
	}
	return false
}

// looksMySQL reads the server's greeting, because the client has nothing to say until it has
// been greeted. The first packet is a length, a sequence of zero, and protocol version 10,
// followed by a printable server version.
func looksMySQL(port int, server []byte) bool {
	if port == 3306 || port == 3307 || port == 33060 {
		return true
	}
	if len(server) < 6 || server[3] != 0 || server[4] != 0x0a {
		return false
	}
	n := int(server[0]) | int(server[1])<<8 | int(server[2])<<16
	if n < 10 || n > 1024 {
		return false
	}
	v, _, ok := cstring(server[5:])
	return ok && v != "" && printable(v) && strings.ContainsAny(v, "0123456789")
}

func looksMongo(port int, b []byte) bool {
	if port == 27017 || port == 27018 || port == 27019 {
		return true
	}
	if len(b) >= 16 {
		n := int(int32(be32le(b)))
		switch be32le(b[12:]) {
		case opMsg, opQuery:
			return n >= 16 && n <= 48<<20
		}
	}
	return false
}

func indexCRLF(b []byte) int {
	for i := 0; i+1 < len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' {
			return i
		}
	}
	return -1
}
