package dns

import (
	"net"
	"slices"
	"strings"
	"sync/atomic"
)

// UPStream is a dns upstream.
type UPStream struct {
	index   uint32
	servers []string
}

// NewUPStream returns a new UpStream.
//
// A server with a path is a DoH (RFC 8484) endpoint: `host/path`,
// `host:port/path` and `https://host[:port]/path` are all stored as the
// https URL. Anything else is a udp/tcp `host[:port]`, port 53 by default.
func NewUPStream(servers []string) *UPStream {
	// cloned: the caller's slice is the parsed config, which reload diffs
	servers = slices.Clone(servers)
	for i, server := range servers {
		switch {
		case isDoH(server):
		case strings.Contains(server, "/"):
			servers[i] = "https://" + server
		default:
			if _, port, _ := net.SplitHostPort(server); port == "" {
				servers[i] = net.JoinHostPort(server, "53")
			}
		}
	}
	return &UPStream{servers: servers}
}

func isDoH(server string) bool { return strings.HasPrefix(server, "https://") }

// Server returns a dns server.
func (u *UPStream) Server() string {
	return u.servers[atomic.LoadUint32(&u.index)%uint32(len(u.servers))]
}

// Switch switches to the next dns server.
func (u *UPStream) Switch() string {
	return u.servers[atomic.AddUint32(&u.index, 1)%uint32(len(u.servers))]
}

// SwitchIf switches to the next dns server if needed.
func (u *UPStream) SwitchIf(server string) string {
	if u.Server() == server {
		return u.Switch()
	}
	return u.Server()
}

// Len returns the number of dns servers.
func (u *UPStream) Len() int {
	return len(u.servers)
}
