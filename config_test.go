package main

import "testing"

func TestListenHostPort(t *testing.T) {
	cases := []struct {
		in         string
		host, port string
		ok         bool
	}{
		{in: ":1080", host: "", port: "1080", ok: true},
		{in: "socks5://:1080", host: "", port: "1080", ok: true},
		{in: "http://127.0.0.1:8080", host: "127.0.0.1", port: "8080", ok: true},
		{in: "socks5://user:pa@ss@1.2.3.4:1080", host: "1.2.3.4", port: "1080", ok: true},
		{in: "tls://:443?cert=/x/y.pem&key=/x/y.key,http://", host: "", port: "443", ok: true},
		{in: "mixed://[::1]:1080", host: "::1", port: "1080", ok: true},
		// A path-bearing listener still binds its host:port.
		{in: "ws://127.0.0.1:1090/path", host: "127.0.0.1", port: "1090", ok: true},
		// Non-TCP listeners can share a port number with the TCP admin endpoint.
		{in: "udp://:1090", ok: false},
		{in: "kcp://:1090", ok: false},
		{in: "vsock://:1090", ok: false},
		// Unrecognized shapes report false so the caller skips rather than guesses.
		{in: "unix:///var/run/glider.sock", ok: false},
		{in: "http://127.0.0.1:notaport", ok: false},
		{in: "", ok: false},
	}
	for _, c := range cases {
		host, port, ok := listenHostPort(c.in)
		if ok != c.ok {
			t.Errorf("listenHostPort(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (host != c.host || port != c.port) {
			t.Errorf("listenHostPort(%q) = %q/%q, want %q/%q", c.in, host, port, c.host, c.port)
		}
	}
}

func TestCheckAdminAddr(t *testing.T) {
	cases := []struct {
		name    string
		admin   string
		listens []string
		wantErr bool
	}{
		{name: "distinct port", admin: "1090", listens: []string{":1080"}},
		{name: "same port as wildcard listen", admin: "1080", listens: []string{":1080"}, wantErr: true},
		{name: "same host and port", admin: "127.0.0.1:1080", listens: []string{"socks5://127.0.0.1:1080"}, wantErr: true},
		// A wildcard admin bind covers a listener on a specific address.
		{name: "wildcard admin over specific listen", admin: "0.0.0.0:1080", listens: []string{"http://127.0.0.1:1080"}, wantErr: true},
		// Different interfaces on the same port do not collide.
		{name: "different host same port", admin: "10.0.0.5:1080", listens: []string{"http://127.0.0.1:1080"}},
		{name: "chained listen", admin: "443", listens: []string{"tls://:443?cert=c&key=k,http://"}, wantErr: true},
		{name: "invalid admin addr", admin: "not-a-port", listens: []string{":1080"}, wantErr: true},
		// Same port number, different transport: not a collision. Rejecting these
		// would refuse a config that works.
		{name: "udp listener same port", admin: "1090", listens: []string{"udp://:1090"}},
		{name: "kcp listener same port", admin: "1090", listens: []string{"kcp://:1090"}},
		{name: "vsock listener same port", admin: "1090", listens: []string{"vsock://:1090"}},
		// A path-bearing TCP listener is still a collision.
		{name: "ws listener with path", admin: "1090", listens: []string{"ws://127.0.0.1:1090/path"}, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkAdminAddr(c.admin, c.listens)
			if (err != nil) != c.wantErr {
				t.Errorf("checkAdminAddr(%q, %v) = %v, wantErr %v", c.admin, c.listens, err, c.wantErr)
			}
		})
	}
}
