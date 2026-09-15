package capture

import (
	"encoding/json"
	"fmt"
)

// Kind is what sort of flow was captured.
type Kind string

const (
	KindHTTP Kind = "http"
	KindWS   Kind = "ws"
	KindTCP  Kind = "tcp"
	KindUDP  Kind = "udp"
)

func (k Kind) Valid() bool {
	switch k {
	case KindHTTP, KindWS, KindTCP, KindUDP:
		return true
	}
	return false
}

// Dir is which way a message travelled.
type Dir string

const (
	Out Dir = "out" // app -> upstream
	In  Dir = "in"  // upstream -> app
)

// Via is how a flow reached the proxy.
type Via string

const (
	ViaCONNECT Via = "connect"
	ViaSOCKS   Via = "socks"
	ViaSNI     Via = "sni"
	ViaPlain   Via = "plain"
	ViaTun     Via = "tun" // the child's own network namespace, via our userspace stack
)

// Proto is the wire protocol ntcept spoke with the application.
type Proto string

const (
	ProtoHTTP11 Proto = "http/1.1"
	ProtoH2     Proto = "h2"
	ProtoH2C    Proto = "h2c"
	ProtoWS     Proto = "ws"
	ProtoTCP    Proto = "tcp"
	ProtoUDP    Proto = "udp"
)

// Stage is the point in an exchange at which it was held.
type Stage string

const (
	StageRequest  Stage = "request"
	StageResponse Stage = "response"
)

func (s Stage) Valid() bool { return s == StageRequest || s == StageResponse }

// Action is a verdict on a held exchange.
type Action string

const (
	ActionForward Action = "forward"
	ActionDrop    Action = "drop"
	ActionRespond Action = "respond"
	ActionEdit    Action = "edit"
)

func (a Action) Valid() bool {
	switch a {
	case ActionForward, ActionDrop, ActionRespond, ActionEdit:
		return true
	}
	return false
}

func (a *Action) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if v := Action(s); v.Valid() {
		*a = v
		return nil
	}
	return fmt.Errorf("unknown action %q: want forward, drop, respond or edit", s)
}

// Decision records how a flow was ultimately answered.
type Decision string

const (
	DecisionPass        Decision = "pass"
	DecisionDrop        Decision = "drop"
	DecisionRespond     Decision = "respond"
	DecisionEdit        Decision = "edit"
	DecisionOffline     Decision = "offline"
	DecisionHoldTimeout Decision = "hold-timeout"
)

// EventType is what changed, for subscribers to the live stream.
type EventType string

const (
	EventFlowNew    EventType = "flow.new"
	EventFlowUpdate EventType = "flow.update"
	EventFlowDone   EventType = "flow.done"
	EventHeldNew    EventType = "held.new"
	EventHeldGone   EventType = "held.gone"
)

// Opcode is a WebSocket frame type.
type Opcode string

const (
	OpText   Opcode = "text"
	OpBinary Opcode = "binary"
	OpClose  Opcode = "close"
	OpPing   Opcode = "ping"
	OpPong   Opcode = "pong"
)
