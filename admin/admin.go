// Package admin exposes glider's forwarder-group availability over a small
// read-only HTTP endpoint.
//
// Why HTTP/Prometheus text rather than, say, a signal dump or a unix socket:
// whatever is already scraping the host almost certainly speaks it, so nothing
// downstream needs new plumbing, and a human can curl the same URL. The JSON
// /state endpoint carries the identical data for eyeballing and ad-hoc scripts.
//
// The endpoint is read-only — there is no way to enable, disable, or reconfigure
// a forwarder through it — and defaults to loopback so it cannot become a
// second, unauthenticated surface on a box whose proxy listener is already
// unauthenticated.
package admin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/rule"
)

// StatusFunc reports the current status of every forwarder group. It is
// rule.Proxy.Status; taking it as a function keeps this package from having to
// know anything about routing, and means the value captured at startup keeps
// following SIGHUP reloads (rule.Proxy swaps its state behind the method).
type StatusFunc func() []rule.GroupStatus

// Server serves the admin endpoints on an already-bound listener.
type Server struct {
	ln     net.Listener
	status StatusFunc
}

// New normalizes addr, binds it, and returns a Server ready to Serve.
//
// Binding here rather than inside Serve is deliberate: a typo'd or already-taken
// admin address must fail at startup, where the operator sees it, instead of
// silently costing observability from inside a goroutine.
func New(addr string, status StatusFunc) (*Server, error) {
	hostport, err := NormalizeAddr(addr)
	if err != nil {
		return nil, err
	}

	if host, _, _ := net.SplitHostPort(hostport); !isLoopbackHost(host) {
		log.Printf("[admin] WARNING: %s is not loopback; the admin endpoint is unauthenticated, restrict it at the network layer", hostport)
	}

	ln, err := net.Listen("tcp", hostport)
	if err != nil {
		return nil, fmt.Errorf("admin: listen on %s: %w", hostport, err)
	}
	return &Server{ln: ln, status: status}, nil
}

// Addr returns the address the admin endpoint is bound to.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Serve serves the admin endpoints until the listener fails. It is meant to be
// run in its own goroutine; a failure here is logged and never fatal, because
// losing observability must not take proxying down with it.
func (s *Server) Serve() {
	log.Printf("[admin] listening on %s", s.Addr())

	srv := &http.Server{
		Handler:           s.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := srv.Serve(s.ln); err != nil && err != http.ErrServerClosed {
		log.Printf("[admin] server stopped: %s", err)
	}
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", readOnly(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	}))
	mux.HandleFunc("/state", readOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(stateResponse{Groups: s.groups()})
	}))
	mux.HandleFunc("/metrics", readOnly(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(renderPrometheus(s.groups())))
	}))
	return mux
}

// groups returns the current status, never nil, so the JSON encoder emits an
// empty array rather than `null` for a consumer to trip over.
func (s *Server) groups() []rule.GroupStatus {
	if s.status == nil {
		return []rule.GroupStatus{}
	}
	if g := s.status(); g != nil {
		return g
	}
	return []rule.GroupStatus{}
}

// stateResponse is the shape of GET /state.
type stateResponse struct {
	Groups []rule.GroupStatus `json:"groups"`
}

// readOnly rejects anything but GET/HEAD. The endpoint mutates nothing, so this
// is only about keeping it obviously read-only to anyone (or anything) probing it.
func readOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

func renderPrometheus(groups []rule.GroupStatus) string {
	var b strings.Builder

	help(&b, "glider_group_forwarders_enabled", "gauge", "forwarders currently in the group's dial rotation")
	help(&b, "glider_group_forwarders_total", "gauge", "forwarders configured in the group")
	help(&b, "glider_forwarder_enabled", "gauge", "1 if the forwarder's enabled flag is set")
	help(&b, "glider_forwarder_failures", "gauge", "failures recorded since the forwarder was last enabled (resets on a passing check)")
	help(&b, "glider_forwarder_latency_ms", "gauge", "smoothed health-check latency in milliseconds")

	// Neither identity is guaranteed unique: a group name is a rule-file
	// basename, and two rule files in different directories can share one; a
	// forwarder's Addr() is host:port, and two forwarders can differ only by
	// password or SNI. A repeated label set makes Prometheus reject the whole
	// scrape, which would silently remove the very signal this endpoint exists
	// to serve — so collisions are disambiguated rather than emitted as-is.
	groupNames := newUniquer()

	for _, g := range groups {
		gl := label("group", groupNames.take(g.Group))
		gauge(&b, "glider_group_forwarders_enabled", "{"+gl+"}", float64(g.Enabled))
		gauge(&b, "glider_group_forwarders_total", "{"+gl+"}", float64(g.Total))

		// Addresses only have to be unique within their group, since the group
		// label is already unique.
		addrs := newUniquer()
		for _, f := range g.Forwarders {
			fl := "{" + gl + "," + label("addr", addrs.take(f.Addr)) + "}"
			gauge(&b, "glider_forwarder_enabled", fl, boolVal(f.Enabled))
			gauge(&b, "glider_forwarder_failures", fl, float64(f.Failures))
			gauge(&b, "glider_forwarder_latency_ms", fl, float64(f.LatencyMs))
		}
	}
	return b.String()
}

// uniquer hands out label values that are unique within one rendering.
type uniquer map[string]bool

func newUniquer() uniquer { return uniquer{} }

// take returns v, or the first "v#n" not already emitted, and reserves the
// result.
//
// Reserving the *output* is the point: counting repeats of the input is not
// enough, because a generated name can collide with a real one. Group names are
// rule-file basenames and '#' is a legal filename character, so the inputs
// `cn`, `cn`, `cn#1` would otherwise emit `cn#1` twice — the very duplicate this
// is here to prevent.
func (u uniquer) take(v string) string {
	if !u[v] {
		u[v] = true
		return v
	}
	for n := 1; ; n++ {
		if cand := fmt.Sprintf("%s#%d", v, n); !u[cand] {
			u[cand] = true
			return cand
		}
	}
}

func help(b *strings.Builder, name, typ, desc string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s %s\n", name, desc, name, typ)
}

func gauge(b *strings.Builder, name, labels string, val float64) {
	fmt.Fprintf(b, "%s%s %s\n", name, labels, strconv.FormatFloat(val, 'g', -1, 64))
}

func label(k, v string) string { return k + `="` + escapeLabel(v) + `"` }

func escapeLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

func boolVal(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// NormalizeAddr turns a user-supplied admin address into a concrete host:port.
//
// A bare port ("9091") or a host-less form (":9091") binds loopback rather than
// every interface — the opposite of how `listen=` behaves, and on purpose: the
// proxy listener is a deliberate service, the admin endpoint is a debug surface
// that should have to be asked for explicitly before it leaves the host.
func NormalizeAddr(addr string) (string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", fmt.Errorf("admin: empty address")
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No colon at all: treat the whole thing as a port.
		host, port = "", addr
	}
	if port == "" {
		return "", fmt.Errorf("admin: %q has no port", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("admin: %q is not a valid port", port)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// isLoopbackHost reports whether host is a loopback literal or "localhost". A
// name that is not "localhost" is treated as non-loopback: resolving it here
// would just make the warning depend on DNS.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
