package attach

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/rahlenjakob/ntcept/internal/ca"
	"github.com/rahlenjakob/ntcept/internal/capture"
	"github.com/rahlenjakob/ntcept/internal/control"
	"github.com/rahlenjakob/ntcept/internal/proxy"
)

type Options struct {
	ProxyPort   int
	ControlPort int
	BufferMB    int
	MaxBodyKB   int
	Args        []string // the command to launch; empty means serve and wait
	Name        string   // session name; empty derives one from the command
	Keep        bool     // stay up after the child exits
	Out         io.Writer
}

type Runtime struct {
	Store   *capture.Store
	Proxy   *proxy.Server
	Session Session

	proxyLn   net.Listener
	controlLn net.Listener
	httpSrv   *http.Server
}

// Start brings up the proxy and control plane on loopback. Nothing outside this process is
// touched: no trust store, no resolver, no firewall rule, no file outside ~/.ntcept.
func Start(opts Options) (*Runtime, error) {
	authority, err := ca.LoadOrCreate(ca.Home())
	if err != nil {
		return nil, fmt.Errorf("certificate authority: %w", err)
	}
	store := capture.NewStore(opts.BufferMB<<20, opts.MaxBodyKB<<10)
	px := proxy.New(store, authority)

	proxyLn, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.ProxyPort)))
	if err != nil {
		return nil, fmt.Errorf("proxy port: %w", err)
	}
	controlLn, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.ControlPort)))
	if err != nil {
		proxyLn.Close()
		return nil, fmt.Errorf("control port: %w", err)
	}

	rt := &Runtime{Store: store, Proxy: px, proxyLn: proxyLn, controlLn: controlLn}
	name := opts.Name
	if name == "" {
		name = NameFor(opts.Args, os.Getpid())
	} else {
		name = CleanName(name)
	}
	rt.Session = Session{
		Name:        name,
		PID:         os.Getpid(),
		ProxyPort:   port(proxyLn),
		ControlPort: port(controlLn),
		Started:     time.Now(),
	}
	if len(opts.Args) > 0 {
		rt.Session.Command = shellJoin(opts.Args)
	}

	cs := &control.Server{Store: store, Proxy: px, Info: control.SessionInfo{
		Name: rt.Session.Name, PID: rt.Session.PID, ProxyPort: rt.Session.ProxyPort,
		ControlPort: rt.Session.ControlPort, Started: rt.Session.Started,
		Command: rt.Session.Command,
	}}
	rt.httpSrv = &http.Server{Handler: cs.Handler()}

	go func() { _ = px.Serve(proxyLn) }()
	go func() { _ = rt.httpSrv.Serve(controlLn) }()

	if err := WriteSession(rt.Session); err != nil {
		return nil, err
	}
	return rt, nil
}

func (rt *Runtime) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = rt.httpSrv.Shutdown(ctx)
	_ = rt.proxyLn.Close()
	RemoveSession(rt.Session.Name)
}

func (rt *Runtime) ProxyURL() string {
	return "http://127.0.0.1:" + strconv.Itoa(rt.Session.ProxyPort)
}

func (rt *Runtime) ControlURL() string {
	return "http://127.0.0.1:" + strconv.Itoa(rt.Session.ControlPort)
}

func port(l net.Listener) int {
	if a, ok := l.Addr().(*net.TCPAddr); ok {
		return a.Port
	}
	return 0
}

func shellJoin(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
