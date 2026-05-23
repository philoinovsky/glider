package rule

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/proxy"
)

// Proxy implements the proxy.Proxy interface with rule support.
//
// The routing tables live inside an atomically swappable proxyState, so the
// outer *Proxy pointer that Servers / DNS / IPSet hold stays valid across a
// hot reload while the underlying forwarders and maps are replaced.
type Proxy struct {
	state atomic.Pointer[proxyState]
}

// proxyState holds the routing tables and forwarder groups for one
// generation of the config. On reload a fresh proxyState is built and
// swapped in; the old state is dropped (existing connections are unaffected
// because they no longer consult the Proxy after Dial returns).
type proxyState struct {
	main      *FwdrGroup
	all       []*FwdrGroup
	domainMap sync.Map
	ipMap     sync.Map
	cidrMap   sync.Map
}

// NewProxy returns a new rule proxy. Returns an error on malformed forwarder
// URLs so callers can decide whether to abort (startup) or keep an older
// state alive (SIGHUP reload).
//
// Forwarders start in the DISABLED state (see forward.go); NewProxy runs a
// synchronous warmCheck so the first Dial does not pick an unverified
// forwarder, then starts long-running health checkers. Callers must not
// also invoke Check() — this used to be required and is now a no-op.
func NewProxy(mainForwarders []string, mainStrategy *Strategy, rules []*Config) (*Proxy, error) {
	state, err := buildState(mainForwarders, mainStrategy, rules)
	if err != nil {
		return nil, err
	}
	state.warmCheck()
	p := &Proxy{}
	p.state.Store(state)
	state.startCheckers()
	return p, nil
}

// Reload atomically swaps the routing state with one built from the given
// forwarders, strategy, and rules. Connections that have already completed
// Dial keep relaying on the old state's dialers; only new Dial calls see the
// new state.
//
// Sequence:
//  1. Build the new state. On error the old state is preserved untouched.
//  2. warmCheck the new state synchronously so its forwarders move from the
//     default DISABLED to ENABLED (per result) before being published. This
//     blocks the caller (the SIGHUP signal goroutine) for up to
//     max(checktimeout); existing and new connections continue on the old
//     state during this window because p.state has not yet been swapped.
//  3. Swap state, then startCheckers on the new state and stopCheckers on
//     the old. The old state's checker goroutines exit and the old state
//     becomes garbage-collectable.
func (p *Proxy) Reload(mainForwarders []string, mainStrategy *Strategy, rules []*Config) error {
	state, err := buildState(mainForwarders, mainStrategy, rules)
	if err != nil {
		return err
	}
	state.warmCheck()
	oldState := p.state.Swap(state)
	state.startCheckers()
	if oldState != nil {
		oldState.stopCheckers()
	}
	return nil
}

func buildState(mainForwarders []string, mainStrategy *Strategy, rules []*Config) (*proxyState, error) {
	mainGroup, err := NewFwdrGroup("main", mainForwarders, mainStrategy)
	if err != nil {
		return nil, fmt.Errorf("main forwarders: %w", err)
	}
	s := &proxyState{main: mainGroup}

	for _, r := range rules {
		group, err := NewFwdrGroup(r.RulePath, r.Forward, &r.Strategy)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.RulePath, err)
		}
		s.all = append(s.all, group)

		for _, domain := range r.Domain {
			s.domainMap.Store(strings.ToLower(domain), group)
		}

		for _, ipS := range r.IP {
			ip, err := netip.ParseAddr(ipS)
			if err != nil {
				log.F("[rule] parse ip error: %s", err)
				continue
			}
			s.ipMap.Store(ip, group)
		}

		for _, cidrS := range r.CIDR {
			cidr, err := netip.ParsePrefix(cidrS)
			if err != nil {
				log.F("[rule] parse cidr error: %s", err)
				continue
			}
			s.cidrMap.Store(cidr, group)
		}
	}

	// "direct" pseudo-group has no forwarders, so NewFwdrGroup falls back to
	// a direct forwarder via DirectForwarder, which can't fail on URL parse.
	// Any error here would come from the interface lookup, so still propagate.
	direct, err := NewFwdrGroup("", nil, mainStrategy)
	if err != nil {
		return nil, fmt.Errorf("direct forwarder: %w", err)
	}
	s.domainMap.Store("direct", direct)

	// if there's any forwarder defined in main config, make sure they will be accessed directly.
	if len(mainForwarders) > 0 {
		for _, f := range s.main.fwdrs {
			addr := strings.Split(f.addr, ",")[0]
			host, _, _ := net.SplitHostPort(addr)
			if _, err := netip.ParseAddr(host); err != nil {
				s.domainMap.Store(strings.ToLower(host), direct)
			}
		}
	}

	return s, nil
}

// warmCheck runs one synchronous pass of every group's health check across
// every forwarder in this state. Successful checks Enable the forwarder.
// Callers should run this before publishing the state via p.state.Store so
// the first post-swap Dial sees only verified-healthy forwarders.
//
// Concurrency: each forwarder check is its own goroutine; warmCheck blocks
// until they all complete (or hit checktimeout). Total wall-clock is
// bounded by max(checktimeout) regardless of forwarder count.
func (s *proxyState) warmCheck() {
	var wg sync.WaitGroup
	s.main.warmCheck(&wg)
	for _, g := range s.all {
		g.warmCheck(&wg)
	}
	wg.Wait()
}

// startCheckers spins up the long-running health-check goroutines for every
// group in this state. Safe to call exactly once per state.
func (s *proxyState) startCheckers() {
	s.main.startCheckers()
	for _, g := range s.all {
		g.startCheckers()
	}
}

// stopCheckers signals every group's health-check goroutines to exit. After
// this returns the state has no live goroutines holding it, so it can be
// garbage-collected once the last in-flight connection releases its
// reference to its forwarder.
func (s *proxyState) stopCheckers() {
	s.main.stop()
	for _, g := range s.all {
		g.stop()
	}
}

// Dial dials to targer addr and return a conn.
func (p *Proxy) Dial(network, addr string) (net.Conn, proxy.Dialer, error) {
	s := p.state.Load()
	return s.findDialer(addr).Dial(network, addr)
}

// DialUDP connects to the given address via the proxy.
func (p *Proxy) DialUDP(network, addr string) (pc net.PacketConn, dialer proxy.UDPDialer, err error) {
	s := p.state.Load()
	return s.findDialer(addr).DialUDP(network, addr)
}

// findDialer returns a dialer by dstAddr according to rule.
func (s *proxyState) findDialer(dstAddr string) *FwdrGroup {
	host, _, err := net.SplitHostPort(dstAddr)
	if err != nil {
		return s.main
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		// check ip
		if proxy, ok := s.ipMap.Load(ip); ok {
			return proxy.(*FwdrGroup)
		}

		// check cidr
		var ret *FwdrGroup
		s.cidrMap.Range(func(key, value any) bool {
			if key.(netip.Prefix).Contains(ip) {
				ret = value.(*FwdrGroup)
				return false
			}
			return true
		})

		if ret != nil {
			return ret
		}
	}

	// check host
	host = strings.ToLower(host)
	for i := len(host); i != -1; {
		i = strings.LastIndexByte(host[:i], '.')
		if proxy, ok := s.domainMap.Load(host[i+1:]); ok {
			return proxy.(*FwdrGroup)
		}
	}

	return s.main
}

// NextDialer returns next dialer according to rule.
func (p *Proxy) NextDialer(dstAddr string) proxy.Dialer {
	s := p.state.Load()
	return s.findDialer(dstAddr).NextDialer(dstAddr)
}

// Record records result while using the dialer from proxy.
func (p *Proxy) Record(dialer proxy.Dialer, success bool) {
	if fwdr, ok := dialer.(*Forwarder); ok {
		if !success {
			fwdr.IncFailures()
			return
		}
		fwdr.Enable()
	}
}

// AddDomainIP used to update ipMap rules according to domainMap rule.
func (p *Proxy) AddDomainIP(domain string, ip netip.Addr) error {
	s := p.state.Load()
	domain = strings.ToLower(domain)
	for i := len(domain); i != -1; {
		i = strings.LastIndexByte(domain[:i], '.')
		if dialer, ok := s.domainMap.Load(domain[i+1:]); ok {
			s.ipMap.Store(ip, dialer)
			// log.F("[rule] update map: %s/%s based on rule: domain=%s\n", domain, ip, domain[i+1:])
		}
	}
	return nil
}

