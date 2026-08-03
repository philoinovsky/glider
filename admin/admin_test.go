package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nadoo/glider/rule"
)

func serve(t *testing.T, status StatusFunc, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{status: status}
	rec := httptest.NewRecorder()
	s.handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func sampleStatus() []rule.GroupStatus {
	return []rule.GroupStatus{{
		Group:   "main",
		Enabled: 52,
		Total:   129,
		Forwarders: []rule.ForwarderStatus{
			{Addr: "222.79.111.222:16302", Enabled: true, Failures: 0, LatencyMs: 180},
			{Addr: "222.79.111.222:16702", Enabled: false, Failures: 3, LatencyMs: 0},
		},
	}}
}

func TestMetricsRendersGroupAndForwarders(t *testing.T) {
	body := serve(t, sampleStatus, http.MethodGet, "/metrics").Body.String()

	for _, want := range []string{
		`glider_group_forwarders_enabled{group="main"} 52`,
		`glider_group_forwarders_total{group="main"} 129`,
		`glider_forwarder_enabled{group="main",addr="222.79.111.222:16302"} 1`,
		`glider_forwarder_enabled{group="main",addr="222.79.111.222:16702"} 0`,
		`glider_forwarder_failures{group="main",addr="222.79.111.222:16702"} 3`,
		`glider_forwarder_latency_ms{group="main",addr="222.79.111.222:16302"} 180`,
		"# TYPE glider_group_forwarders_enabled gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
}

func TestStateRendersJSON(t *testing.T) {
	rec := serve(t, sampleStatus, http.MethodGet, "/state")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	var got struct {
		Groups []rule.GroupStatus `json:"groups"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %s: %v", rec.Body.String(), err)
	}
	if len(got.Groups) != 1 || got.Groups[0].Enabled != 52 || got.Groups[0].Total != 129 {
		t.Fatalf("got %+v, want one group, 52 of 129", got.Groups)
	}
}

// Consumers decode `groups` as an array; a nil slice would encode as `null` and
// make every one of them special-case the empty case.
func TestStateEncodesEmptyGroupsAsArray(t *testing.T) {
	for name, status := range map[string]StatusFunc{
		"nil func":  nil,
		"nil slice": func() []rule.GroupStatus { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			body := serve(t, status, http.MethodGet, "/state").Body.String()
			if strings.Contains(body, "null") {
				t.Errorf("groups encoded as null:\n%s", body)
			}
			var got struct {
				Groups []rule.GroupStatus `json:"groups"`
			}
			if err := json.Unmarshal([]byte(body), &got); err != nil {
				t.Fatalf("decode %s: %v", body, err)
			}
		})
	}
}

func TestEndpointsAreReadOnly(t *testing.T) {
	for _, path := range []string{"/metrics", "/state", "/healthz"} {
		rec := serve(t, sampleStatus, http.MethodPost, path)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want 405", path, rec.Code)
		}
	}
}

func TestNormalizeAddr(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		// A bare or host-less port binds loopback, unlike `listen=`.
		{in: "1090", want: "127.0.0.1:1090"},
		{in: ":1090", want: "127.0.0.1:1090"},
		{in: "127.0.0.1:1090", want: "127.0.0.1:1090"},
		{in: "10.0.0.5:1090", want: "10.0.0.5:1090"},
		{in: "[::1]:1090", want: "[::1]:1090"},
		{in: " :1090 ", want: "127.0.0.1:1090"},
		{in: "", wantErr: true},
		{in: "127.0.0.1:", wantErr: true},
		{in: "127.0.0.1:abc", wantErr: true},
		{in: "127.0.0.1:0", wantErr: true},
		{in: "127.0.0.1:70000", wantErr: true},
	}
	for _, c := range cases {
		got, err := NormalizeAddr(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("NormalizeAddr(%q) = %q, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("NormalizeAddr(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("NormalizeAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// freePort returns a port that was free a moment ago. Port 0 is deliberately
// rejected by NormalizeAddr (it reads like "disabled" in a config file), so a
// test that wants an ephemeral port has to pick one this way.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestNewBindsLoopbackByDefault(t *testing.T) {
	s, err := New(":"+freePort(t), sampleStatus)
	if err != nil {
		t.Fatal(err)
	}
	defer s.ln.Close()

	if !strings.HasPrefix(s.Addr(), "127.0.0.1:") {
		t.Errorf("bound %q, want loopback", s.Addr())
	}
}

// A second bind on the same address must fail at construction — that is what
// turns a `admin=` / `listen=` collision into a startup error instead of a
// silently missing endpoint.
func TestNewFailsOnBusyAddress(t *testing.T) {
	first, err := New("127.0.0.1:"+freePort(t), sampleStatus)
	if err != nil {
		t.Fatal(err)
	}
	defer first.ln.Close()

	if _, err := New(first.Addr(), sampleStatus); err == nil {
		t.Error("New on an already-bound address succeeded")
	}
}

// A duplicated label set makes Prometheus reject the whole scrape, so neither a
// repeated group name (two rule files in different directories share a
// basename) nor a repeated forwarder address (two forwarders differing only by
// password or SNI) may emit the same series twice.
func TestPrometheusSeriesAreUnique(t *testing.T) {
	status := func() []rule.GroupStatus {
		return []rule.GroupStatus{
			{Group: "cn", Enabled: 1, Total: 2, Forwarders: []rule.ForwarderStatus{
				{Addr: "1.2.3.4:443", Enabled: true},
				{Addr: "1.2.3.4:443", Enabled: false}, // same host:port, different password
			}},
			{Group: "cn", Enabled: 1, Total: 1}, // same basename, different directory
		}
	}
	assertNoDuplicateSeries(t, serve(t, status, http.MethodGet, "/metrics").Body.String())

	// The un-collided values must still render plainly.
	body := serve(t, status, http.MethodGet, "/metrics").Body.String()
	if !strings.Contains(body, `glider_group_forwarders_enabled{group="cn"} 1`) {
		t.Errorf("first group was renamed:\n%s", body)
	}
}

// Counting repeats of the input is not enough: a generated name can collide
// with a real one. Group names are rule-file basenames and '#' is a legal
// filename character, so `cn`, `cn`, `cn#1` is a reachable configuration and
// naive suffixing emits `cn#1` twice.
func TestPrometheusSuffixDoesNotCollideWithARealName(t *testing.T) {
	status := func() []rule.GroupStatus {
		return []rule.GroupStatus{
			{Group: "cn", Enabled: 1, Total: 1},
			{Group: "cn", Enabled: 2, Total: 2},
			{Group: "cn#1", Enabled: 3, Total: 3},
		}
	}
	assertNoDuplicateSeries(t, serve(t, status, http.MethodGet, "/metrics").Body.String())
}

func TestUniquerReservesItsOwnOutput(t *testing.T) {
	u := newUniquer()
	got := []string{u.take("cn"), u.take("cn"), u.take("cn#1"), u.take("cn")}
	seen := map[string]bool{}
	for _, g := range got {
		if seen[g] {
			t.Errorf("take returned %q twice: %v", g, got)
		}
		seen[g] = true
	}
	if got[0] != "cn" {
		t.Errorf("first take = %q, want the value unchanged", got[0])
	}
}

// assertNoDuplicateSeries fails if any metric line repeats a name+label set,
// which makes Prometheus reject the entire scrape.
func assertNoDuplicateSeries(t *testing.T, body string) {
	t.Helper()
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		series := line[:strings.LastIndex(line, " ")]
		if seen[series] {
			t.Errorf("duplicate series %q in:\n%s", series, body)
		}
		seen[series] = true
	}
}

// Label values reach the exposition format verbatim, so a quote or backslash in
// a group name (rule files are operator-named) must not break the output.
func TestPrometheusEscapesLabels(t *testing.T) {
	status := func() []rule.GroupStatus {
		return []rule.GroupStatus{{Group: `we"ird\1`, Enabled: 1, Total: 2}}
	}
	body := serve(t, status, http.MethodGet, "/metrics").Body.String()
	if !strings.Contains(body, `glider_group_forwarders_enabled{group="we\"ird\\1"} 1`) {
		t.Errorf("label not escaped:\n%s", body)
	}
}
