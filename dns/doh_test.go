package dns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nadoo/glider/proxy"
)

// recordingDialer dials directly and records every address it is handed, so a
// test can tell which route a DoH connection took and that it got an IP.
type recordingDialer struct {
	addr  string
	mu    sync.Mutex
	dials []string
}

func (d *recordingDialer) Addr() string { return d.addr }

func (d *recordingDialer) Dial(network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.dials = append(d.dials, addr)
	d.mu.Unlock()
	return net.Dial(network, addr)
}

func (d *recordingDialer) DialUDP(network, addr string) (net.PacketConn, error) {
	return nil, proxy.ErrNotSupported
}

func (d *recordingDialer) dialed() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.dials)
}

// routeProxy routes each qname to its own dialer, as rule.Proxy does by domain.
type routeProxy map[string]proxy.Dialer

func (p routeProxy) Dial(network, addr string) (net.Conn, proxy.Dialer, error) {
	return nil, nil, proxy.ErrNotSupported
}

func (p routeProxy) DialUDP(network, addr string) (net.PacketConn, proxy.UDPDialer, error) {
	return nil, nil, proxy.ErrNotSupported
}

func (p routeProxy) NextDialer(dstAddr string) proxy.Dialer {
	host, _, _ := net.SplitHostPort(dstAddr)
	return p[host]
}

func (p routeProxy) Record(proxy.Dialer, bool) {}

// breakDefaultResolver fails the test on any lookup through net.DefaultResolver,
// which glider points at its own dns server.
func breakDefaultResolver(t *testing.T) {
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			t.Error("a lookup went through net.DefaultResolver")
			return nil, errors.New("net.DefaultResolver is glider's own dns server")
		},
	}
	t.Cleanup(func() { net.DefaultResolver = old })
}

// newDoHServer answers A and AAAA queries over RFC 8484 POST. Replies carry
// ID 0, so a test sees it if the server's ID reaches the client.
func newDoHServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != dohMediaType {
			http.Error(w, "want an RFC 8484 POST", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		req, err := UnmarshalMessage(body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ip := "192.0.2.1"
		if req.Question.QTYPE == QTypeAAAA {
			ip = "2001:db8::1"
		}
		m, _ := MakeResponse(req.Question.QNAME, ip, 300)
		m.ID = 0
		b, _ := m.Marshal()
		w.Header().Set("Content-Type", dohMediaType)
		w.Write(b)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// dohServer is srv written the way Clash nameserver-policy writes DoH servers,
// under a host name that only the test bootstrap resolves.
func dohServer(srv *httptest.Server) string {
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return "example.com:" + port + "/dns-query"
}

func newTestClient(t *testing.T, srv *httptest.Server, p proxy.Proxy, cfg *Config) *Client {
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 1800
	}
	if cfg.CacheSize == 0 {
		cfg.CacheSize = 64
	}
	c, err := NewClient(p, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// every httptest server shares this certificate, valid for example.com
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	c.dohTLS = &tls.Config{RootCAs: roots}
	c.dohBootstrap = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "example.com" {
			return nil, fmt.Errorf("unexpected bootstrap lookup of %s", host)
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return c
}

func query(t *testing.T, id uint16, qtype uint16, name string) []byte {
	m := NewMessage(id, QueryMsg)
	m.SetQuestion(NewQuestion(qtype, name))
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// exchange runs one query through c and returns the reply's ID and answers.
func exchange(t *testing.T, c *Client, id uint16, qtype uint16, name string) (uint16, []string) {
	t.Helper()
	respBytes, err := c.Exchange(query(t, id, qtype, name), "test", false)
	if err != nil {
		t.Fatalf("Exchange(%s): %v", name, err)
	}
	resp, err := UnmarshalMessage(respBytes)
	if err != nil {
		t.Fatalf("reply for %s: %v", name, err)
	}
	var ips []string
	for _, rr := range resp.Answers {
		ips = append(ips, rr.IP.String())
	}
	return resp.ID, ips
}

func TestNewUPStreamServerForms(t *testing.T) {
	cases := []struct{ in, want string }{
		{"8.8.8.8", "8.8.8.8:53"},
		{"8.8.8.8:5353", "8.8.8.8:5353"},
		{"dns.example", "dns.example:53"},
		{"[2001:db8::1]:53", "[2001:db8::1]:53"},
		{"dns.example/dns-query", "https://dns.example/dns-query"},
		{"dns.example:8443/dns-query", "https://dns.example:8443/dns-query"},
		{"https://dns.example/dns-query", "https://dns.example/dns-query"},
	}
	var in []string
	for _, tc := range cases {
		in = append(in, tc.in)
	}
	ups := NewUPStream(in)
	for i, tc := range cases {
		if got := ups.servers[i]; got != tc.want {
			t.Errorf("NewUPStream(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if in[i] != tc.in {
			t.Errorf("NewUPStream rewrote the caller's %q to %q", tc.in, in[i])
		}
	}
}

func TestDoHExchange(t *testing.T) {
	breakDefaultResolver(t)
	var hits atomic.Int32
	srv := newDoHServer(t, &hits)
	direct := &recordingDialer{addr: "DIRECT"}
	c := newTestClient(t, srv, routeProxy{"a.test": direct, "b.test": direct}, &Config{Timeout: 3})
	c.SetServers("test", []string{dohServer(srv)})

	id, ips := exchange(t, c, 0x1234, QTypeA, "a.test")
	if id != 0x1234 || !slices.Equal(ips, []string{"192.0.2.1"}) {
		t.Fatalf("a.test: got id %#x answers %v, want id 0x1234 answers [192.0.2.1]", id, ips)
	}

	if _, ips := exchange(t, c, 1, QTypeA, "a.test"); !slices.Equal(ips, []string{"192.0.2.1"}) || hits.Load() != 1 {
		t.Errorf("cached a.test: answers %v after %d server hits, want [192.0.2.1] from the cache", ips, hits.Load())
	}

	exchange(t, c, 2, QTypeA, "b.test")
	if hits.Load() != 2 {
		t.Errorf("server hits = %d, want 2", hits.Load())
	}
	if got, want := direct.dialed(), []string{srv.Listener.Addr().String()}; !slices.Equal(got, want) {
		t.Errorf("dials = %v, want %v: one connection to the bootstrapped ip, reused", got, want)
	}
}

func TestDoHConnectionsStayOnTheirRoute(t *testing.T) {
	breakDefaultResolver(t)
	srv := newDoHServer(t, new(atomic.Int32))
	viaA, viaB := &recordingDialer{addr: "fwd-a:1"}, &recordingDialer{addr: "fwd-b:1"}
	c := newTestClient(t, srv, routeProxy{"a.test": viaA, "b.test": viaB, "c.test": viaA}, &Config{Timeout: 3})
	c.SetServers("test", []string{dohServer(srv)})

	for _, name := range []string{"a.test", "b.test", "c.test"} {
		exchange(t, c, 1, QTypeA, name)
	}
	if len(viaA.dialed()) != 1 || len(viaB.dialed()) != 1 {
		t.Errorf("dials via A = %v, via B = %v; want one each: b.test must not reuse A's connection",
			viaA.dialed(), viaB.dialed())
	}
}

func TestDoHFailsOverToNextServer(t *testing.T) {
	breakDefaultResolver(t)
	var badHits, goodHits atomic.Int32
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badHits.Add(1)
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(bad.Close)
	good := newDoHServer(t, &goodHits)
	direct := &recordingDialer{addr: "DIRECT"}
	c := newTestClient(t, good, routeProxy{"a.test": direct}, &Config{Timeout: 3})
	c.SetServers("test", []string{dohServer(bad), dohServer(good)})

	if _, ips := exchange(t, c, 1, QTypeA, "a.test"); !slices.Equal(ips, []string{"192.0.2.1"}) {
		t.Errorf("answers = %v, want [192.0.2.1] from the second server", ips)
	}
	if badHits.Load() != 1 || goodHits.Load() != 1 {
		t.Errorf("hits: bad %d, good %d; want 1 each", badHits.Load(), goodHits.Load())
	}
}

func TestDoHHonorsTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	c := newTestClient(t, srv, routeProxy{"a.test": &recordingDialer{addr: "DIRECT"}}, &Config{Timeout: 1})
	c.SetServers("test", []string{dohServer(srv)})

	start := time.Now()
	_, err := c.Exchange(query(t, 1, QTypeA, "a.test"), "test", false)
	if err == nil {
		t.Fatal("Exchange succeeded against a server that never replies")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Exchange gave up after %s, want about dnstimeout=1s", elapsed)
	}
}

// A dnsrecord is served from the cache's permanent store, which Exchange reads
// before choosing an upstream, so it wins over a rule's DoH server for its own
// name and type; other types still go upstream.
func TestDNSRecordBeatsDoHForItsType(t *testing.T) {
	var hits atomic.Int32
	srv := newDoHServer(t, &hits)
	direct := &recordingDialer{addr: "DIRECT"}
	c := newTestClient(t, srv, routeProxy{"a.test": direct}, &Config{Timeout: 3, Records: []string{"a.test/10.0.0.1"}})
	c.SetServers("test", []string{dohServer(srv)})

	if _, ips := exchange(t, c, 1, QTypeA, "a.test"); !slices.Equal(ips, []string{"10.0.0.1"}) || hits.Load() != 0 {
		t.Errorf("A a.test = %v after %d DoH hits, want the dnsrecord 10.0.0.1 and no DoH query", ips, hits.Load())
	}
	if _, ips := exchange(t, c, 2, QTypeAAAA, "a.test"); !slices.Equal(ips, []string{"2001:db8::1"}) || hits.Load() != 1 {
		t.Errorf("AAAA a.test = %v after %d DoH hits, want 2001:db8::1 from DoH", ips, hits.Load())
	}
}
