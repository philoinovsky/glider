package dns

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/nadoo/glider/proxy"
)

const dohMediaType = "application/dns-message"

// dohMaxLen bounds a DoH response body to the largest dns message.
const dohMaxLen = 65535

type dohDialerKey struct{}

// exchangeDoH sends reqBytes to the DoH server url as an RFC 8484 POST, over
// a connection dialed through dialer.
func (c *Client) exchangeDoH(dialer proxy.Dialer, url string, reqBytes []byte) ([]byte, error) {
	ctx := context.WithValue(context.Background(), dohDialerKey{}, dialer)
	if c.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.config.Timeout)*time.Second)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dohMediaType)
	req.Header.Set("Accept", dohMediaType)

	resp, err := c.dohClient(dialer).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh server replied %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxLen+1))
	if err != nil {
		return nil, err
	}
	if len(body) < HeaderLen || len(body) > dohMaxLen {
		return nil, fmt.Errorf("doh response of %d bytes is not a dns message", len(body))
	}

	respBytes := valCopy(body)
	// our client matches the reply by its own ID, whatever the server echoed
	copy(respBytes[:2], reqBytes[:2])
	return respBytes, nil
}

// dohClient returns the http client for queries routed through dialer. Clients
// are kept per dialer Addr so a pooled connection is only reused on the route
// it was dialed on.
func (c *Client) dohClient(dialer proxy.Dialer) *http.Client {
	if hc, ok := c.dohClients.Load(dialer.Addr()); ok {
		return hc.(*http.Client)
	}
	hc := &http.Client{Transport: &http.Transport{
		DialContext:         c.dialDoH,
		TLSClientConfig:     c.dohTLS,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	}}
	actual, _ := c.dohClients.LoadOrStore(dialer.Addr(), hc)
	return actual.(*http.Client)
}

// dialDoH resolves the DoH server's host with dohBootstrap rather than
// net.DefaultResolver, which glider points at its own dns server: the query
// being answered may be the one that needs this host.
func (c *Client) dialDoH(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := ctx.Value(dohDialerKey{}).(proxy.Dialer)

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := c.dohLookup(ctx, host)
	if err != nil {
		return nil, err
	}

	for _, ip := range ips {
		var rc net.Conn
		if rc, err = dialer.Dial(network, net.JoinHostPort(ip.String(), port)); err == nil {
			return rc, nil
		}
	}
	return nil, err
}

func (c *Client) dohLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	return c.dohBootstrap(ctx, host)
}

var bootstrapResolver = &net.Resolver{PreferGo: true}

// systemLookup resolves host with /etc/hosts and the nameservers in
// /etc/resolv.conf.
func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return bootstrapResolver.LookupNetIP(ctx, "ip", host)
}
