package rule

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nadoo/glider/proxy"
)

var errDial = errors.New("dial failed")

// fakeDialer is one upstream. Each Forwarder in a test gets its OWN instance: a
// shared fake would make "the retry went to a different forwarder" and "each
// failure was charged to the forwarder it happened on" untestable, since both
// claims are about which instance was touched.
type fakeDialer struct {
	addr  string
	fail  bool
	delay time.Duration
	dials atomic.Int32
}

func (d *fakeDialer) Addr() string { return d.addr }

func (d *fakeDialer) Dial(network, addr string) (net.Conn, error) {
	d.dials.Add(1)
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	if d.fail {
		return nil, errDial
	}
	c, _ := net.Pipe()
	return c, nil
}

func (d *fakeDialer) DialUDP(network, addr string) (net.PacketConn, error) {
	return nil, proxy.ErrNotSupported
}

// newTestGroup builds a group over the given fakes. Forwarders are left in the
// zero (enabled) state so init() puts all of them in the rotation.
func newTestGroup(t *testing.T, cfg *Strategy, dialers ...*fakeDialer) *FwdrGroup {
	t.Helper()
	fwdrs := make([]*Forwarder, 0, len(dialers))
	for _, d := range dialers {
		f := &Forwarder{Dialer: d, addr: d.addr}
		f.SetMaxFailures(uint32(cfg.MaxFailures))
		fwdrs = append(fwdrs, f)
	}
	return newFwdrGroup("test", fwdrs, cfg)
}

// fwdr looks a forwarder up by address: newFwdrGroup sorts p.fwdrs, so index
// order is not the order the test passed them in.
func fwdr(t *testing.T, g *FwdrGroup, addr string) *Forwarder {
	t.Helper()
	for _, f := range g.fwdrs {
		if f.Addr() == addr {
			return f
		}
	}
	t.Fatalf("no forwarder %q in group", addr)
	return nil
}

func dialCounts(dialers ...*fakeDialer) map[string]int32 {
	out := make(map[string]int32, len(dialers))
	for _, d := range dialers {
		out[d.addr] = d.dials.Load()
	}
	return out
}

func totalDials(dialers ...*fakeDialer) int32 {
	var n int32
	for _, d := range dialers {
		n += d.dials.Load()
	}
	return n
}

func TestDialRetriesOnAnotherForwarder(t *testing.T) {
	a := &fakeDialer{addr: "a", fail: true}
	b := &fakeDialer{addr: "b", fail: true}
	c := &fakeDialer{addr: "c"}
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 3, MaxFailures: 3}, a, b, c)

	conn, dialer, err := g.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial: want success after retries, got %v (dials %v)", err, dialCounts(a, b, c))
	}
	conn.Close()

	if dialer.Addr() != "c" {
		t.Errorf("returned dialer = %q, want the one that succeeded (c)", dialer.Addr())
	}
	// Which forwarder round-robin starts on depends on the shared cursor, so
	// assert the property instead: reaching c means at least one retry happened,
	// and no forwarder was dialed twice — the retry moved to a different one.
	if totalDials(a, b, c) < 2 {
		t.Errorf("only %d dial(s); the success was not preceded by a retry (%v)", totalDials(a, b, c), dialCounts(a, b, c))
	}
	for _, d := range []*fakeDialer{a, b, c} {
		if d.dials.Load() > 1 {
			t.Errorf("forwarder %q dialed %d times; a retry must move to a different forwarder (%v)",
				d.addr, d.dials.Load(), dialCounts(a, b, c))
		}
	}
	if c.dials.Load() != 1 {
		t.Errorf("the healthy forwarder was dialed %d times, want 1", c.dials.Load())
	}
}

// A deterministic strategy returns the same forwarder for a given destination,
// so a retry that just re-asks the strategy would loop on one dead upstream.
func TestDialRetriesMoveOffDeterministicStrategies(t *testing.T) {
	for _, strategy := range []string{"ha", "dh", "lha"} {
		t.Run(strategy, func(t *testing.T) {
			a := &fakeDialer{addr: "a", fail: true}
			b := &fakeDialer{addr: "b", fail: true}
			c := &fakeDialer{addr: "c", fail: true}
			g := newTestGroup(t, &Strategy{Strategy: strategy, DialAttempts: 3, MaxFailures: 9}, a, b, c)

			if _, _, err := g.Dial("tcp", "example.com:443"); err == nil {
				t.Fatal("Dial: want failure, all forwarders fail")
			}
			for _, d := range []*fakeDialer{a, b, c} {
				if d.dials.Load() != 1 {
					t.Errorf("forwarder %q dialed %d times, want 1 (%v)", d.addr, d.dials.Load(), dialCounts(a, b, c))
				}
			}
		})
	}
}

func TestDialAttemptsBounded(t *testing.T) {
	dialers := make([]*fakeDialer, 6)
	for i := range dialers {
		dialers[i] = &fakeDialer{addr: string(rune('a' + i)), fail: true}
	}
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 2, MaxFailures: 9}, dialers...)

	if _, _, err := g.Dial("tcp", "example.com:443"); err == nil {
		t.Fatal("Dial: want failure")
	}
	if got := totalDials(dialers...); got != 2 {
		t.Errorf("total dials = %d, want 2 (dialattempts); %v", got, dialCounts(dialers...))
	}
}

// dialattempts=1 must reproduce the pre-retry behavior exactly: one dial, and
// the failing dialer handed back so the server can log which upstream it was.
func TestDialSingleAttemptIsUnchanged(t *testing.T) {
	a := &fakeDialer{addr: "a", fail: true}
	b := &fakeDialer{addr: "b", fail: true}
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 1, MaxFailures: 9}, a, b)

	_, dialer, err := g.Dial("tcp", "example.com:443")
	if !errors.Is(err, errDial) {
		t.Fatalf("Dial error = %v, want %v", err, errDial)
	}
	if got := totalDials(a, b); got != 1 {
		t.Errorf("total dials = %d, want 1", got)
	}
	if dialer == nil {
		t.Fatal("returned dialer is nil; the server logs dialer.Addr() on this path")
	}
	if n := dialCounts(a, b)[dialer.Addr()]; n != 1 {
		t.Errorf("returned dialer %q was dialed %d times, want the forwarder that failed", dialer.Addr(), n)
	}
}

// A zero DialAttempts (a Strategy built without the flag defaults) must not
// disable dialing altogether.
func TestDialZeroAttemptsStillDialsOnce(t *testing.T) {
	a := &fakeDialer{addr: "a"}
	g := newTestGroup(t, &Strategy{Strategy: "rr"}, a)

	conn, _, err := g.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()
	if a.dials.Load() != 1 {
		t.Errorf("dials = %d, want 1", a.dials.Load())
	}
}

// Every failed attempt must be charged to the forwarder it was made on — that is
// what lets real traffic (not just the 60s health check) walk a broken forwarder
// to maxfailures — and charged exactly once, or maxfailures would trip early.
func TestDialFailureChargedOncePerForwarder(t *testing.T) {
	a := &fakeDialer{addr: "a", fail: true}
	b := &fakeDialer{addr: "b", fail: true}
	c := &fakeDialer{addr: "c"}
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 3, MaxFailures: 3}, a, b, c)

	conn, _, err := g.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	// Round-robin decides where the attempt sequence starts, so pin the failure
	// count to the dial count: every forwarder that failed a dial owes exactly
	// one failure, and the one that succeeded owes none.
	for _, d := range []*fakeDialer{a, b, c} {
		want := uint32(0)
		if d.fail {
			want = uint32(d.dials.Load())
		}
		if got := fwdr(t, g, d.addr).Failures(); got != want {
			t.Errorf("forwarder %q: %d dial(s), failures = %d, want %d", d.addr, d.dials.Load(), got, want)
		}
	}
	if totalDials(a, b, c) < 2 {
		t.Fatalf("only %d dial(s); this test needs a retry to have happened (%v)", totalDials(a, b, c), dialCounts(a, b, c))
	}
}

func TestDialFailuresDisableForwarderAtMaxFailures(t *testing.T) {
	a := &fakeDialer{addr: "a", fail: true}
	b := &fakeDialer{addr: "b", fail: true}
	// "ha" always picks the head of the rotation and one attempt per Dial, so
	// both failures land on the same forwarder.
	g := newTestGroup(t, &Strategy{Strategy: "ha", DialAttempts: 1, MaxFailures: 2}, a, b)

	for i := 0; i < 2; i++ {
		if _, _, err := g.Dial("tcp", "example.com:443"); err == nil {
			t.Fatalf("Dial %d: want failure", i)
		}
	}

	st := g.Status()
	if st.Enabled != 1 || st.Total != 2 {
		t.Fatalf("Status() = %d of %d enabled, want 1 of 2: real-traffic dial failures are not reaching the health state", st.Enabled, st.Total)
	}
	// The forwarder that took both dials is the one that must be out.
	for _, d := range []*fakeDialer{a, b} {
		if d.dials.Load() == 2 && fwdr(t, g, d.addr).Enabled() {
			t.Errorf("forwarder %q failed %d dials at maxfailures=2 but is still enabled", d.addr, d.dials.Load())
		}
	}
}

func TestDialBudgetStopsRetries(t *testing.T) {
	dialers := make([]*fakeDialer, 5)
	for i := range dialers {
		dialers[i] = &fakeDialer{addr: string(rune('a' + i)), fail: true, delay: 40 * time.Millisecond}
	}
	// DialBudget is configured in seconds; set the resolved duration directly so
	// the test does not have to burn a whole second. 140ms fits three 40ms
	// attempts by elapsed time alone, but the gate also demands room for another
	// attempt as slow as the last, so it must stop earlier than that.
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 5, MaxFailures: 99}, dialers...)
	g.dialBudget = 140 * time.Millisecond

	start := time.Now()
	if _, _, err := g.Dial("tcp", "example.com:443"); err == nil {
		t.Fatal("Dial: want failure")
	}
	elapsed := time.Since(start)

	n := totalDials(dialers...)
	if n < 2 {
		t.Errorf("total dials = %d, want at least 2: the first attempt always runs, and one retry fits in the budget", n)
	}
	if n > 3 {
		t.Errorf("%d attempts ran in %s under a %s budget; the wall-clock gate did not bound the retries", n, elapsed, g.dialBudget)
	}
}

// The gate must leave room for another attempt as slow as the last one. A single
// attempt that alone eats most of the budget must not license a second one that
// carries the call past the caller's deadline — that is the whole point of the
// budget, and checking elapsed time alone does not achieve it.
func TestDialBudgetLeavesRoomForTheNextAttempt(t *testing.T) {
	slow := &fakeDialer{addr: "slow", fail: true, delay: 90 * time.Millisecond}
	b := &fakeDialer{addr: "b", fail: true}
	c := &fakeDialer{addr: "c", fail: true}
	g := newTestGroup(t, &Strategy{Strategy: "ha", DialAttempts: 3, MaxFailures: 99}, slow, b, c)
	g.dialBudget = 100 * time.Millisecond // "ha" always starts on avail[0]

	start := time.Now()
	if _, _, err := g.Dial("tcp", "example.com:443"); err == nil {
		t.Fatal("Dial: want failure")
	}
	elapsed := time.Since(start)

	if slow.dials.Load() != 1 {
		t.Fatalf("the slow forwarder was dialed %d times, want 1 (%v)", slow.dials.Load(), dialCounts(slow, b, c))
	}
	// 90ms elapsed is under the 100ms budget, so an elapsed-only gate would have
	// started another attempt.
	if n := totalDials(slow, b, c); n != 1 {
		t.Errorf("%d attempts in %s: a 90ms failure under a 100ms budget must not license a retry that could take another 90ms", n, elapsed)
	}
}

// A zero budget means "bounded by dialattempts only", not "no retries".
func TestDialZeroBudgetRunsAllAttempts(t *testing.T) {
	a := &fakeDialer{addr: "a", fail: true, delay: 5 * time.Millisecond}
	b := &fakeDialer{addr: "b", fail: true, delay: 5 * time.Millisecond}
	c := &fakeDialer{addr: "c", fail: true, delay: 5 * time.Millisecond}
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 3, DialBudget: 0, MaxFailures: 99}, a, b, c)

	if _, _, err := g.Dial("tcp", "example.com:443"); err == nil {
		t.Fatal("Dial: want failure")
	}
	if got := totalDials(a, b, c); got != 3 {
		t.Errorf("total dials = %d, want 3", got)
	}
}

// Retries must stay inside the rotation: a disabled forwarder is not a
// candidate, so a group with one available forwarder retries nothing.
func TestDialSkipsDisabledForwarders(t *testing.T) {
	a := &fakeDialer{addr: "a", fail: true}
	b := &fakeDialer{addr: "b", fail: true}
	c := &fakeDialer{addr: "c", fail: true}
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 3, MaxFailures: 99}, a, b, c)

	fwdr(t, g, "b").Disable()
	fwdr(t, g, "c").Disable()

	if _, _, err := g.Dial("tcp", "example.com:443"); err == nil {
		t.Fatal("Dial: want failure")
	}
	if b.dials.Load() != 0 || c.dials.Load() != 0 {
		t.Errorf("disabled forwarders were dialed: %v", dialCounts(a, b, c))
	}
	if a.dials.Load() != 1 {
		t.Errorf("available forwarder dialed %d times, want 1", a.dials.Load())
	}
}

// With nothing available, dialing must still be attempted (matching NextDialer's
// long-standing fallback) rather than failing outright.
func TestDialFallsBackWhenNothingAvailable(t *testing.T) {
	a := &fakeDialer{addr: "a", fail: true}
	b := &fakeDialer{addr: "b"}
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 3, MaxFailures: 99}, a, b)

	fwdr(t, g, "a").Disable()
	fwdr(t, g, "b").Disable()

	conn, _, err := g.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial: %v (dials %v)", err, dialCounts(a, b))
	}
	conn.Close()
}

func TestStatusReportsRotationSize(t *testing.T) {
	a := &fakeDialer{addr: "a"}
	b := &fakeDialer{addr: "b"}
	c := &fakeDialer{addr: "c"}
	g := newTestGroup(t, &Strategy{Strategy: "rr", MaxFailures: 3}, a, b, c)

	st := g.Status()
	if st.Group != "test" || st.Enabled != 3 || st.Total != 3 {
		t.Fatalf("Status() = %+v, want group test, 3 of 3", st)
	}
	if len(st.Forwarders) != 3 {
		t.Fatalf("Status().Forwarders = %d entries, want 3", len(st.Forwarders))
	}

	fwdr(t, g, "a").Disable()
	st = g.Status()
	if st.Enabled != 2 || st.Total != 3 {
		t.Errorf("after disable: Status() = %d of %d, want 2 of 3", st.Enabled, st.Total)
	}
	// Total counts configured forwarders, so a disabled one is still listed.
	if len(st.Forwarders) != 3 {
		t.Errorf("Status().Forwarders = %d entries, want all 3 listed", len(st.Forwarders))
	}
}

// Enable/Disable run their handlers AFTER the CAS that flipped the flag, so a
// late handler can arrive while the forwarder is (again) enabled and already in
// the rotation. That is what an interleaved Disable/Enable looks like from
// onStatusChanged's point of view, and it must not duplicate the entry: a
// duplicate skews round robin, lets a "retry on a different forwarder" land on
// the same one, and makes Status() report enabled > total.
func TestStatusChangeDoesNotDuplicateAvailEntry(t *testing.T) {
	a := &fakeDialer{addr: "a", fail: true}
	b := &fakeDialer{addr: "b"}
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 3, MaxFailures: 99}, a, b)

	f := fwdr(t, g, "a")
	// f is enabled and in avail; deliver the callback a raced Disable would have
	// delivered late, once its Enable had already put the flag back.
	g.onStatusChanged(f)
	g.onStatusChanged(f)

	if st := g.Status(); st.Enabled != 2 || st.Total != 2 {
		t.Fatalf("Status() = %d of %d, want 2 of 2 (a duplicated rotation entry)", st.Enabled, st.Total)
	}

	// And a retry must still move to the other forwarder rather than re-dialing
	// the duplicated one.
	conn, _, err := g.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial: %v (dials %v)", err, dialCounts(a, b))
	}
	conn.Close()
	if a.dials.Load() > 1 {
		t.Errorf("forwarder %q dialed %d times; the retry re-used a duplicated rotation entry", a.addr, a.dials.Load())
	}
}

// A fat-fingered dialattempts must not be used as a slice capacity.
func TestDialAttemptsClampedToPoolSize(t *testing.T) {
	a := &fakeDialer{addr: "a", fail: true}
	b := &fakeDialer{addr: "b", fail: true}
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 1 << 40, MaxFailures: 99}, a, b)

	cands := g.dialCandidates("example.com:443", g.dialAttempts)
	if len(cands) != 2 || cap(cands) != 2 {
		t.Errorf("candidates len=%d cap=%d, want 2/2: attempts must be clamped to the pool size", len(cands), cap(cands))
	}
	if _, _, err := g.Dial("tcp", "example.com:443"); err == nil {
		t.Fatal("Dial: want failure")
	}
	if got := totalDials(a, b); got != 2 {
		t.Errorf("total dials = %d, want 2", got)
	}
}

// A budget big enough to overflow the conversion to time.Duration must not wrap
// negative and silently read as "no clock bound".
func TestDialBudgetOverflowClamped(t *testing.T) {
	a := &fakeDialer{addr: "a"}
	g := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 2, DialBudget: 1 << 40}, a)
	if g.dialBudget <= 0 {
		t.Errorf("dialBudget = %v, want a positive clamped duration", g.dialBudget)
	}

	g2 := newTestGroup(t, &Strategy{Strategy: "rr", DialAttempts: 2, DialBudget: -5}, a)
	if g2.dialBudget != 0 {
		t.Errorf("dialBudget = %v for a negative config, want 0 (no clock bound)", g2.dialBudget)
	}
}

// The forwarder URL carries the upstream credential, so it must never reach a
// serialized status payload.
func TestStatusOmitsForwarderURL(t *testing.T) {
	a := &fakeDialer{addr: "a"}
	g := newTestGroup(t, &Strategy{Strategy: "rr"}, a)
	fwdr(t, g, "a").url = "trojan://secret-password@host:443?serverName=x"

	blob, err := json.Marshal(g.Status())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "secret-password") {
		t.Errorf("Status() serialized the forwarder URL: %s", blob)
	}
}

func TestProxyStatusCoversEveryGroup(t *testing.T) {
	main := &Strategy{Strategy: "rr", DialAttempts: 3, MaxFailures: 3, Check: "disable"}
	p, err := NewProxy(nil, main, []*Config{{RulePath: "cn.rule", Strategy: *main}})
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	got := p.Status()
	if len(got) != 2 {
		t.Fatalf("Status() returned %d groups, want main + 1 rule group: %+v", len(got), got)
	}
	if got[0].Group != "main" {
		t.Errorf("first group = %q, want main", got[0].Group)
	}
	if got[1].Group != "cn" {
		t.Errorf("second group = %q, want cn (rule file basename)", got[1].Group)
	}
}
