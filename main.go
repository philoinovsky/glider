package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"reflect"
	"syscall"
	"time"

	"github.com/nadoo/glider/admin"
	"github.com/nadoo/glider/dns"
	"github.com/nadoo/glider/ipset"
	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/rule"
	"github.com/nadoo/glider/service"
)

var version = "0.17.0"

// startupArgs is the original os.Args captured at startup so SIGHUP reload
// can re-parse against the same -config file (and the same CLI flags).
var startupArgs []string

// startupBind captures the bind-time configuration as observed at startup.
// reload() diffs incoming newCfg against this and warns the user when a
// field that reload does not honor has changed.
var startupBind bindSnapshot

func main() {
	startupArgs = append([]string(nil), os.Args...)

	config, err := parseConfig(startupArgs)
	if err != nil {
		// `-h`/`-help` flows through flag.ErrHelp after the flag package has
		// already printed usage to stdout. Exit 0 so scripts that probe with
		// `glider -h && ...` still chain correctly. The ContinueOnError mode
		// is otherwise required so a malformed flag during SIGHUP reload
		// does not kill the process via os.Exit(2).
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		os.Exit(-1)
	}

	// CLI help-text flags. parseConfig parses them into Config but does not
	// act on them; the startup path here is the only place that honors them.
	// SIGHUP reload ignores both.
	if config.helpScheme != "" {
		fmt.Fprint(os.Stdout, proxy.Usage(config.helpScheme))
		os.Exit(0)
	}
	if config.helpExample {
		fmt.Fprint(os.Stdout, examples)
		os.Exit(0)
	}

	// Apply Config-derived package-level globals (logger verbosity, relay
	// buffer sizes). Reload only re-applies these on a fully successful
	// pxy.Reload, so the running process never sees a half-applied state.
	applyGlobals(config)

	// Snapshot the bind-time settings so reload() can diff and warn the user
	// that a `listen=` / `dns=` / `service=` change requires a process
	// restart (Round 2 deliberately scopes reload to the routing layer only).
	startupBind = newBindSnapshot(config)

	// global rule proxy
	pxy, err := rule.NewProxy(config.Forwards, &config.Strategy, config.rules)
	if err != nil {
		log.Fatal(err)
	}

	// ipset manager
	ipsetM, _ := ipset.NewManager(config.rules)

	// check and setup dns server
	if config.DNS != "" {
		d, err := dns.NewServer(config.DNS, pxy, &config.DNSConfig)
		if err != nil {
			log.Fatal(err)
		}

		// rules
		for _, r := range config.rules {
			if len(r.DNSServers) > 0 {
				for _, domain := range r.Domain {
					d.SetServers(domain, r.DNSServers)
				}
			}
		}

		// add a handler to update proxy rules when a domain resolved
		d.AddHandler(pxy.AddDomainIP)
		if ipsetM != nil {
			d.AddHandler(ipsetM.AddDomainIP)
		}

		d.Start()

		// custom resolver
		net.DefaultResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: time.Second * 3}
				return d.DialContext(ctx, "udp", config.DNS)
			},
		}
	}

	for _, r := range config.rules {
		r.IP, r.CIDR, r.Domain = nil, nil, nil
	}

	// Read-only status endpoint. Bound before the proxy listeners so a bad
	// admin address is a startup error rather than a lost signal, and passed
	// pxy.Status as a func so it keeps reporting the live routing state across
	// SIGHUP reloads.
	if config.Admin != "" {
		a, err := admin.New(config.Admin, pxy.Status)
		if err != nil {
			log.Fatal(err)
		}
		go a.Serve()
	}

	// run proxy servers
	for _, listen := range config.Listens {
		local, err := proxy.ServerFromURL(listen, pxy)
		if err != nil {
			log.Fatal(err)
		}
		go local.ListenAndServe()
	}

	// run services
	for _, s := range config.Services {
		service, err := service.New(s)
		if err != nil {
			log.Fatal(err)
		}
		go service.Run()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		sig := <-sigCh
		if sig == syscall.SIGHUP {
			reload(pxy)
			continue
		}
		log.F("[main] received %s, exiting", sig)
		return
	}
}

// reload re-parses the original startup arguments (re-reading the -config
// file and any rule files) and atomically swaps the rule.Proxy's routing
// state. Existing connections in Relay phase are unaffected; only new Dial
// calls after the swap see the new state.
//
// Scope: routing layer only (Forwards / Strategy / RuleFiles -> rules).
// Listeners, DNS server, IPSet, and Services are not reloaded; changes to
// those require a process restart.
//
// On any parse error the old config keeps serving traffic.
func reload(pxy *rule.Proxy) {
	log.F("[main] SIGHUP received, reloading config")

	newCfg, err := parseConfig(startupArgs)
	if err != nil {
		log.F("[main] reload failed: %s; keeping existing config", err)
		return
	}

	// Warn on bind-time fields the user changed but reload cannot honor.
	// Routing still reloads; the user just needs to restart for the change
	// to a listener / DNS server / service to take effect.
	startupBind.warnDiff(newCfg)

	if err := pxy.Reload(newCfg.Forwards, &newCfg.Strategy, newCfg.rules); err != nil {
		log.F("[main] reload failed: %s; keeping existing config", err)
		return
	}
	// Globals are only swapped after Reload succeeded so a build error
	// leaves verbose / bufsize matching the still-serving old routing state.
	applyGlobals(newCfg)

	log.F("[main] reload complete: %d main forwarders, %d rule groups",
		len(newCfg.Forwards), len(newCfg.rules))
}

// bindSnapshot captures the fields that are baked in at process start
// (sockets bound, DNS server started, services launched) and therefore
// cannot be reloaded by SIGHUP. reload() uses warnDiff to surface these
// changes to the operator without affecting routing reload itself.
type bindSnapshot struct {
	listens  []string
	admin    string
	dns      string
	services []string
	dnsCfg   dns.Config
}

func newBindSnapshot(c *Config) bindSnapshot {
	return bindSnapshot{
		listens:  append([]string(nil), c.Listens...),
		admin:    c.Admin,
		dns:      c.DNS,
		services: append([]string(nil), c.Services...),
		dnsCfg:   c.DNSConfig,
	}
}

// warnDiff logs a one-line warning per field where the reloaded config
// disagrees with the bind-time snapshot, telling the operator that a
// restart is required for the change to take effect. Returns nothing
// because reload should proceed regardless — only routing actually
// reloads.
func (b bindSnapshot) warnDiff(c *Config) {
	if !stringSliceEqual(b.listens, c.Listens) {
		log.F("[main] listen= changed; reload refreshes routes only, restart required to rebind listeners")
	}
	if b.admin != c.Admin {
		log.F("[main] admin= changed; reload does not rebind the status endpoint, restart required")
	}
	if b.dns != c.DNS {
		log.F("[main] dns= changed; reload does not restart the DNS server, restart required")
	}
	if !stringSliceEqual(b.services, c.Services) {
		log.F("[main] service= changed; reload does not restart services, restart required")
	}
	if !reflect.DeepEqual(b.dnsCfg, c.DNSConfig) {
		log.F("[main] dns* settings changed; reload does not refresh the DNS server config, restart required")
	}
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
