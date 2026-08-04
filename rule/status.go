package rule

import "time"

// ForwarderStatus is a point-in-time view of one forwarder.
//
// The forwarder's URL is deliberately absent: it carries the upstream
// credentials (trojan/anytls passwords), and this struct is meant to be
// serialized onto an observability endpoint. Addr() is the host:port only.
type ForwarderStatus struct {
	Addr      string `json:"addr"`
	Enabled   bool   `json:"enabled"`
	Priority  uint32 `json:"priority"`
	Failures  uint32 `json:"failures"`
	LatencyMs int64  `json:"latency_ms"`
}

// GroupStatus is a point-in-time view of one forwarder group's availability.
//
// Enabled is the size of the rotation a Dial actually picks from — the same
// number the "(%d of %d currently enabled)" status-change log reports — not a
// count of forwarders whose enabled flag is set. The two differ only when
// forwarder priorities are in use: a forwarder below the group's active
// priority is enabled but not in the rotation. Consumers want the rotation
// size, since that is what capacity means for routing.
type GroupStatus struct {
	Group      string            `json:"group"`
	Enabled    int               `json:"enabled"`
	Total      int               `json:"total"`
	Forwarders []ForwarderStatus `json:"forwarders"`
}

// Status returns the group's current availability.
func (p *FwdrGroup) Status() GroupStatus {
	p.mu.RLock()
	defer p.mu.RUnlock()

	st := GroupStatus{
		Group:      p.name,
		Enabled:    len(p.avail),
		Total:      len(p.fwdrs),
		Forwarders: make([]ForwarderStatus, 0, len(p.fwdrs)),
	}
	for _, f := range p.fwdrs {
		st.Forwarders = append(st.Forwarders, ForwarderStatus{
			Addr:      f.Addr(),
			Enabled:   f.Enabled(),
			Priority:  f.Priority(),
			Failures:  f.Failures(),
			LatencyMs: time.Duration(f.Latency()).Milliseconds(),
		})
	}
	return st
}

// Status returns the availability of every forwarder group in the live routing
// state: the main group first, then one entry per rule group.
//
// It reads through the atomically-swapped proxyState, so it follows a SIGHUP
// reload without any wiring of its own — a caller that captured this method
// value at startup keeps reporting on the current generation.
//
// The internal "direct" pseudo-group is omitted: it has no forwarders to be
// available or not, and reporting it would just be a constant 1-of-1.
func (p *Proxy) Status() []GroupStatus {
	s := p.state.Load()
	if s == nil {
		return nil
	}

	out := make([]GroupStatus, 0, len(s.all)+1)
	out = append(out, s.main.Status())
	for _, g := range s.all {
		out = append(out, g.Status())
	}
	return out
}
