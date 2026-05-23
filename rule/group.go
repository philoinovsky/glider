package rule

import (
	"errors"
	"hash/fnv"
	"net"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/proxy"
)

// forwarder slice orderd by priority.
type priSlice []*Forwarder

func (p priSlice) Len() int           { return len(p) }
func (p priSlice) Less(i, j int) bool { return p[i].Priority() > p[j].Priority() }
func (p priSlice) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

// FwdrGroup is a forwarder group.
type FwdrGroup struct {
	name     string
	config   *Strategy
	fwdrs    priSlice
	avail    []*Forwarder // available forwarders
	mu       sync.RWMutex
	index    uint32
	priority uint32
	next     func(addr string) *Forwarder
	// done is closed by stop() to signal all running check() goroutines
	// (started by startCheckers / legacy Check) to exit. Created lazily in
	// startCheckers; stop() is a no-op if checkers were never started.
	done      chan struct{}
	doneOnce  sync.Once
}

// NewFwdrGroup returns a new forward group. Returns an error on malformed
// forwarder URLs so the SIGHUP reload path can keep the existing config
// alive instead of dying via log.Fatal.
func NewFwdrGroup(rulePath string, s []string, c *Strategy) (*FwdrGroup, error) {
	var fwdrs []*Forwarder
	for _, chain := range s {
		fwdr, err := ForwarderFromURL(chain, c.IntFace,
			time.Duration(c.DialTimeout)*time.Second, time.Duration(c.RelayTimeout)*time.Second)
		if err != nil {
			return nil, err
		}
		fwdr.SetMaxFailures(uint32(c.MaxFailures))
		fwdrs = append(fwdrs, fwdr)
	}

	if len(fwdrs) == 0 {
		// direct forwarder
		direct, err := DirectForwarder(c.IntFace,
			time.Duration(c.DialTimeout)*time.Second, time.Duration(c.RelayTimeout)*time.Second)
		if err != nil {
			return nil, err
		}
		fwdrs = append(fwdrs, direct)
		c.Strategy = "rr"
	}

	name := strings.TrimSuffix(filepath.Base(rulePath), filepath.Ext(rulePath))
	return newFwdrGroup(name, fwdrs, c), nil
}

// newFwdrGroup returns a new FwdrGroup.
func newFwdrGroup(name string, fwdrs []*Forwarder, c *Strategy) *FwdrGroup {
	p := &FwdrGroup{name: name, fwdrs: fwdrs, config: c}
	sort.Sort(p.fwdrs)

	p.init()

	// default scheduler
	p.next = p.scheduleRR

	// if there're more than 1 forwarders, we care about the strategy.
	if count := len(fwdrs); count > 1 {
		switch c.Strategy {
		case "rr":
			p.next = p.scheduleRR
			log.F("[strategy] %s: %d forwarders forward in round robin mode.", name, count)
		case "ha":
			p.next = p.scheduleHA
			log.F("[strategy] %s: %d forwarders forward in high availability mode.", name, count)
		case "lha":
			p.next = p.scheduleLHA
			log.F("[strategy] %s: %d forwarders forward in latency based high availability mode.", name, count)
		case "dh":
			p.next = p.scheduleDH
			log.F("[strategy] %s: %d forwarders forward in destination hashing mode.", name, count)
		default:
			p.next = p.scheduleRR
			log.F("[strategy] %s: not supported forward mode '%s', use round robin mode for %d forwarders.", name, c.Strategy, count)
		}
	}

	for _, f := range fwdrs {
		f.AddHandler(p.onStatusChanged)
	}

	return p
}

// Dial connects to the address addr on the network net.
func (p *FwdrGroup) Dial(network, addr string) (net.Conn, proxy.Dialer, error) {
	nd := p.NextDialer(addr)
	c, err := nd.Dial(network, addr)
	return c, nd, err
}

// DialUDP connects to the given address.
func (p *FwdrGroup) DialUDP(network, addr string) (pc net.PacketConn, dialer proxy.UDPDialer, err error) {
	nd := p.NextDialer(addr)
	pc, err = nd.DialUDP(network, addr)
	return pc, nd, err
}

// NextDialer returns the next dialer.
func (p *FwdrGroup) NextDialer(dstAddr string) proxy.Dialer {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.avail) == 0 {
		return p.fwdrs[atomic.AddUint32(&p.index, 1)%uint32(len(p.fwdrs))]
	}

	return p.next(dstAddr)
}

// Priority returns the active priority of dialer.
func (p *FwdrGroup) Priority() uint32 { return atomic.LoadUint32(&p.priority) }

// SetPriority sets the active priority of daler.
func (p *FwdrGroup) SetPriority(pri uint32) { atomic.StoreUint32(&p.priority, pri) }

// init traverse d.fwdrs and init the available forwarder slice.
func (p *FwdrGroup) init() {
	for _, f := range p.fwdrs {
		if f.Enabled() {
			p.SetPriority(f.Priority())
			break
		}
	}

	p.avail = nil
	for _, f := range p.fwdrs {
		if f.Enabled() && f.Priority() >= p.Priority() {
			p.avail = append(p.avail, f)
		}
	}

	if len(p.avail) == 0 {
		// no available forwarders, set priority to 0 to check all forwarders in check func
		p.SetPriority(0)
		// log.F("[group] no available forwarders, please check your config file or network settings")
	}
}

// onStatusChanged will be called when fwdr's status changed.
func (p *FwdrGroup) onStatusChanged(fwdr *Forwarder) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if fwdr.Enabled() {
		if fwdr.Priority() == p.Priority() {
			p.avail = append(p.avail, fwdr)
		} else if fwdr.Priority() > p.Priority() {
			p.init()
		}
		log.F("[group] %s: %s(%d) changed status from DISABLED to ENABLED (%d of %d currently enabled)",
			p.name, fwdr.Addr(), fwdr.Priority(), len(p.avail), len(p.fwdrs))
	} else {
		for i, f := range p.avail {
			if f == fwdr {
				p.avail[i], p.avail = p.avail[len(p.avail)-1], p.avail[:len(p.avail)-1]
				break
			}
		}
		log.F("[group] %s: %s(%d) changed status from ENABLED to DISABLED (%d of %d currently enabled)",
			p.name, fwdr.Addr(), fwdr.Priority(), len(p.avail), len(p.fwdrs))
	}

	if len(p.avail) == 0 {
		p.init()
	}
}

// buildChecker constructs the Checker described by p.config.Check, or
// returns nil if checking is disabled (single forwarder, unparseable URL,
// or unknown scheme). Logging is preserved in the disabled cases so
// behavior matches the historical Check() entry point.
func (p *FwdrGroup) buildChecker() Checker {
	if len(p.fwdrs) == 1 {
		log.F("[group] %s: only 1 forwarder found, disable health checking", p.name)
		return nil
	}

	if !strings.Contains(p.config.Check, "://") {
		p.config.Check += "://"
	}

	u, err := url.Parse(p.config.Check)
	if err != nil {
		log.F("[group] %s: parse check config error: %s, disable health checking", p.name, err)
		return nil
	}

	addr := u.Host
	timeout := time.Duration(p.config.CheckTimeout) * time.Second

	var checker Checker
	switch u.Scheme {
	case "tcp":
		checker = newTcpChecker(addr, timeout)
	case "http", "https":
		expect := "HTTP" // default: check the first 4 chars in response
		params, _ := url.ParseQuery(u.Fragment)
		if ex := params.Get("expect"); ex != "" {
			expect = ex
		}
		checker = newHttpChecker(addr, u.RequestURI(), expect, timeout, u.Scheme == "https")
	case "file":
		checker = newFileChecker(u.Host + u.Path)
	default:
		log.F("[group] %s: unknown scheme in check config `%s`, disable health checking", p.name, p.config.Check)
		return nil
	}

	log.F("[group] %s: using check config: %s", p.name, p.config.Check)
	return checker
}

// warmCheck runs one pass of the checker against every forwarder in the
// group, concurrently, and waits for all results before returning. Used by
// Proxy.Reload to bring a freshly-built FwdrGroup's forwarders from the
// default DISABLED state to ENABLED before the new proxyState is published,
// so the next Dial does not pick a forwarder whose health is still unknown.
//
// If checking is disabled for this group (buildChecker returns nil), every
// forwarder is enabled unconditionally so single-forwarder/no-check groups
// remain reachable. Errors from the checker keep the forwarder disabled;
// the long-running checker started afterwards will retry on its schedule.
func (p *FwdrGroup) warmCheck(wg *sync.WaitGroup) {
	checker := p.buildChecker()
	if checker == nil {
		for _, f := range p.fwdrs {
			f.Enable()
		}
		return
	}
	for i := range p.fwdrs {
		wg.Add(1)
		go func(fwdr *Forwarder) {
			defer wg.Done()
			elapsed, err := checker.Check(fwdr)
			if err != nil {
				log.F("[warmcheck] %s: %s(%d), FAILED. error: %s", p.name, fwdr.Addr(), fwdr.Priority(), err)
				return
			}
			p.setLatency(fwdr, elapsed)
			log.F("[warmcheck] %s: %s(%d), SUCCESS. Elapsed: %dms",
				p.name, fwdr.Addr(), fwdr.Priority(), elapsed.Milliseconds())
			fwdr.Enable()
		}(p.fwdrs[i])
	}
}

// startCheckers starts one long-running check goroutine per forwarder.
// Each goroutine watches p.done and exits when it is closed, so a reload
// that builds a new FwdrGroup can stop the old group's checkers and let
// it (and the old proxyState) be garbage collected.
func (p *FwdrGroup) startCheckers() {
	checker := p.buildChecker()
	if checker == nil {
		return
	}
	p.done = make(chan struct{})
	for i := range p.fwdrs {
		go p.check(p.fwdrs[i], checker)
	}
}

// stop signals all running check goroutines to exit. Safe to call on a
// group whose checkers never started (no-op).
func (p *FwdrGroup) stop() {
	if p.done == nil {
		return
	}
	p.doneOnce.Do(func() { close(p.done) })
}

func (p *FwdrGroup) check(fwdr *Forwarder, checker Checker) {
	wait := uint8(0)
	intval := time.Duration(p.config.CheckInterval) * time.Second

	for {
		// Block until the next check interval or until stop() closes p.done.
		// p.done is created in startCheckers before any goroutine is spawned,
		// so it is non-nil here.
		if d := intval * time.Duration(wait); d > 0 {
			select {
			case <-p.done:
				return
			case <-time.After(d):
			}
		} else {
			// First iteration: no sleep, but still bail if stop() already fired.
			select {
			case <-p.done:
				return
			default:
			}
		}

		// check all forwarders at least one time
		if wait > 0 && (fwdr.Priority() < p.Priority()) {
			continue
		}

		if fwdr.Enabled() && p.config.CheckDisabledOnly {
			continue
		}

		elapsed, err := checker.Check(fwdr)
		if err != nil {
			if errors.Is(err, proxy.ErrNotSupported) {
				fwdr.SetMaxFailures(0)
				log.F("[check] %s: %s(%d), %s, stop checking", p.name, fwdr.Addr(), fwdr.Priority(), err)
				fwdr.Enable()
				break
			}

			wait++
			if wait > 16 {
				wait = 16
			}

			log.F("[check] %s: %s(%d), FAILED. error: %s", p.name, fwdr.Addr(), fwdr.Priority(), err)
			fwdr.Disable()
			continue
		}

		wait = 1
		p.setLatency(fwdr, elapsed)
		log.F("[check] %s: %s(%d), SUCCESS. Elapsed: %dms, Latency: %dms.",
			p.name, fwdr.Addr(), fwdr.Priority(), elapsed.Milliseconds(), time.Duration(fwdr.Latency()).Milliseconds())
		fwdr.Enable()
	}
}

func (p *FwdrGroup) setLatency(fwdr *Forwarder, elapsed time.Duration) {
	newLatency := int64(elapsed)
	if cnt := p.config.CheckLatencySamples; cnt > 1 {
		if lastLatency := fwdr.Latency(); lastLatency > 0 {
			newLatency = (lastLatency*(int64(cnt)-1) + int64(elapsed)) / int64(cnt)
		}
	}
	fwdr.SetLatency(newLatency)
}

// Round Robin.
func (p *FwdrGroup) scheduleRR(dstAddr string) *Forwarder {
	return p.avail[atomic.AddUint32(&p.index, 1)%uint32(len(p.avail))]
}

// High Availability.
func (p *FwdrGroup) scheduleHA(dstAddr string) *Forwarder {
	return p.avail[0]
}

// Latency based High Availability.
func (p *FwdrGroup) scheduleLHA(dstAddr string) *Forwarder {
	oldfwdr, newfwdr := p.avail[0], p.avail[0]
	lowest := oldfwdr.Latency()
	for _, f := range p.avail {
		if f.Latency() < lowest {
			lowest = f.Latency()
			newfwdr = f
		}
	}
	tolerance := int64(p.config.CheckTolerance) * int64(time.Millisecond)
	if newfwdr.Latency() < (oldfwdr.Latency() - tolerance) {
		return newfwdr
	}
	return oldfwdr
}

// Destination Hashing.
func (p *FwdrGroup) scheduleDH(dstAddr string) *Forwarder {
	fnv1a := fnv.New32a()
	fnv1a.Write([]byte(dstAddr))
	return p.avail[fnv1a.Sum32()%uint32(len(p.avail))]
}
