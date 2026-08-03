package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"strings"

	"github.com/nadoo/conflag"

	"github.com/nadoo/glider/admin"
	"github.com/nadoo/glider/dns"
	"github.com/nadoo/glider/pkg/log"
	"github.com/nadoo/glider/proxy"
	"github.com/nadoo/glider/rule"
)

// Config is global config struct.
type Config struct {
	Verbose    bool
	LogFlags   int
	TCPBufSize int
	UDPBufSize int

	Listens []string

	// Admin is the address of the read-only status endpoint ("" disables it).
	// Bind-time like Listens: SIGHUP reload warns instead of rebinding it.
	Admin string

	Forwards []string
	Strategy rule.Strategy

	RuleFiles []string
	RulesDir  string

	DNS       string
	DNSConfig dns.Config

	rules []*rule.Config

	Services []string

	// helpScheme / helpExample are CLI help-text intents. parseConfig parses
	// them but does not act on them; the caller (main.go startup) checks and
	// exits with help output. SIGHUP reload ignores them entirely so that a
	// stray "scheme=" line in glider.conf cannot kill a running glider.
	helpScheme  string
	helpExample bool
}

// parseConfig parses args (must include args[0] as the program name) into a
// new Config. A fresh conflag instance is created on every call, so this is
// safe to invoke at startup and again from a SIGHUP reload path.
//
// Errors are returned rather than terminating the process so that reload
// failures can be logged while the existing config keeps serving traffic.
// Note: conflag's underlying FlagSet still uses flag.ExitOnError, so a
// malformed -flag in the config file can still kill the process on reload.
func parseConfig(args []string) (*Config, error) {
	conf := &Config{}

	f := conflag.New(args...)
	// conflag defaults the underlying FlagSet to ExitOnError, which would
	// kill the process on a bad flag during SIGHUP reload. Flip it to
	// ContinueOnError so Parse returns an error we can recover from.
	// FlagSet.Init only updates name + errorHandling; registered flags
	// (including conflag's own "config"/"include") are preserved.
	f.FlagSet.Init(f.FlagSet.Name(), flag.ContinueOnError)
	f.SetOutput(os.Stdout)

	f.StringVar(&conf.helpScheme, "scheme", "", "show help message of proxy scheme, use 'all' to see all schemes")
	f.BoolVar(&conf.helpExample, "example", false, "show usage examples")

	f.BoolVar(&conf.Verbose, "verbose", false, "verbose mode")
	f.IntVar(&conf.LogFlags, "logflags", 19, "do not change it if you do not know what it is, ref: https://pkg.go.dev/log#pkg-constants")
	f.IntVar(&conf.TCPBufSize, "tcpbufsize", 32768, "tcp buffer size in Bytes")
	f.IntVar(&conf.UDPBufSize, "udpbufsize", 2048, "udp buffer size in Bytes")
	f.StringSliceUniqVar(&conf.Listens, "listen", nil, "listen url, see the URL section below")
	f.StringVar(&conf.Admin, "admin", "", "listen address of the read-only status endpoint (/metrics, /state, /healthz); a bare port binds 127.0.0.1, empty disables")

	f.StringSliceVar(&conf.Forwards, "forward", nil, "forward url, see the URL section below")
	f.StringVar(&conf.Strategy.Strategy, "strategy", "rr", `rr: Round Robin mode
ha: High Availability mode
lha: Latency based High Availability mode
dh: Destination Hashing mode`)
	f.StringVar(&conf.Strategy.Check, "check", "http://www.msftconnecttest.com/connecttest.txt#expect=200",
		`check=tcp[://HOST:PORT]: tcp port connect check
check=http://HOST[:PORT][/URI][#expect=REGEX_MATCH_IN_RESP_LINE]
check=https://HOST[:PORT][/URI][#expect=REGEX_MATCH_IN_RESP_LINE]
check=file://SCRIPT_PATH: run a check script, healthy when exitcode=0, env vars: FORWARDER_ADDR,FORWARDER_URL
check=disable: disable health check`)
	f.IntVar(&conf.Strategy.CheckInterval, "checkinterval", 30, "fowarder check interval(seconds)")
	f.IntVar(&conf.Strategy.CheckTimeout, "checktimeout", 10, "fowarder check timeout(seconds)")
	f.IntVar(&conf.Strategy.CheckTolerance, "checktolerance", 0, "fowarder check tolerance(ms), switch only when new_latency < old_latency - tolerance, only used in lha mode")
	f.IntVar(&conf.Strategy.CheckLatencySamples, "checklatencysamples", 10, "use the average latency of the latest N checks")
	f.BoolVar(&conf.Strategy.CheckDisabledOnly, "checkdisabledonly", false, "check disabled fowarders only")
	f.IntVar(&conf.Strategy.MaxFailures, "maxfailures", 3, "max failures to change forwarder status to disabled")
	f.IntVar(&conf.Strategy.DialTimeout, "dialtimeout", 3, "dial timeout(seconds)")
	f.IntVar(&conf.Strategy.RelayTimeout, "relaytimeout", 0, "relay timeout(seconds)")
	f.IntVar(&conf.Strategy.DialAttempts, "dialattempts", rule.DefaultDialAttempts, "max forwarders to try for one dial, a failed dial retries on the next forwarder")
	f.IntVar(&conf.Strategy.DialBudget, "dialbudget", rule.DefaultDialBudget, "wall-clock budget for dial retries(seconds), 0 to bound by dialattempts only; keep it below the downstream client's dial timeout")
	f.StringVar(&conf.Strategy.IntFace, "interface", "", "source ip or source interface")

	f.StringSliceUniqVar(&conf.RuleFiles, "rulefile", nil, "rule file path")
	f.StringVar(&conf.RulesDir, "rules-dir", "", "rule file folder")

	// dns configs
	f.StringVar(&conf.DNS, "dns", "", "local dns server listen address")
	f.StringSliceUniqVar(&conf.DNSConfig.Servers, "dnsserver", []string{"8.8.8.8:53"}, "remote dns server address")
	f.BoolVar(&conf.DNSConfig.AlwaysTCP, "dnsalwaystcp", false, "always use tcp to query upstream dns servers no matter there is a forwarder or not")
	f.IntVar(&conf.DNSConfig.Timeout, "dnstimeout", 3, "timeout value used in multiple dnsservers switch(seconds)")
	f.IntVar(&conf.DNSConfig.MaxTTL, "dnsmaxttl", 1800, "maximum TTL value for entries in the CACHE(seconds)")
	f.IntVar(&conf.DNSConfig.MinTTL, "dnsminttl", 0, "minimum TTL value for entries in the CACHE(seconds)")
	f.IntVar(&conf.DNSConfig.CacheSize, "dnscachesize", 4096, "max number of dns response in CACHE")
	f.BoolVar(&conf.DNSConfig.CacheLog, "dnscachelog", false, "show query log of dns cache")
	f.BoolVar(&conf.DNSConfig.NoAAAA, "dnsnoaaaa", false, "disable AAAA query")
	f.StringSliceUniqVar(&conf.DNSConfig.Records, "dnsrecord", nil, "custom dns record, format: domain/ip")

	// service configs
	f.StringSliceUniqVar(&conf.Services, "service", nil, "run specified services, format: SERVICE_NAME[,SERVICE_CONFIG]")

	f.Usage = func() {
		fmt.Fprint(f.Output(), usage1)
		f.PrintDefaults()
		fmt.Fprintf(f.Output(), usage2, proxy.ServerSchemes(), proxy.DialerSchemes(), version)
	}
	if err := f.Parse(); err != nil {
		return nil, err
	}

	// helpScheme / helpExample are honored only by the startup caller (main),
	// not here. parseConfig never calls os.Exit so that a stray "scheme=" or
	// "example=" line in a reloaded config cannot kill the running process.

	if len(conf.Listens) == 0 && conf.DNS == "" && len(conf.Services) == 0 {
		return nil, fmt.Errorf("listen url must be specified")
	}

	if conf.Admin != "" {
		if err := checkAdminAddr(conf.Admin, conf.Listens); err != nil {
			return nil, err
		}
	}

	if err := loadRules(conf, f.ConfDir()); err != nil {
		return nil, err
	}
	return conf, nil
}

// checkAdminAddr validates the admin address and rejects one that would collide
// with a proxy listener.
//
// The kernel would catch the collision anyway, but as an EADDRINUSE on whichever
// of the two listeners loses the race — a confusing way to learn that `admin=`
// was pointed at the same port as `listen=`. Failing here names both sides.
func checkAdminAddr(adminAddr string, listens []string) error {
	hostport, err := admin.NormalizeAddr(adminAddr)
	if err != nil {
		return err
	}
	aHost, aPort, err := net.SplitHostPort(hostport)
	if err != nil {
		return fmt.Errorf("admin: %q is not a valid address", adminAddr)
	}

	for _, l := range listens {
		lHost, lPort, ok := listenHostPort(l)
		if !ok || lPort != aPort {
			continue
		}
		// A wildcard bind on either side covers the other's address.
		if wildcardHost(lHost) || wildcardHost(aHost) || lHost == aHost {
			return fmt.Errorf("admin address %s collides with listen %q; give the admin endpoint its own port", hostport, l)
		}
	}
	return nil
}

// listenHostPort extracts the host:port a `-listen` URL binds. It reports false
// for a form it does not recognize, so the caller skips the collision check
// rather than guessing at it — a missed collision still surfaces as a bind error.
func listenHostPort(s string) (host, port string, ok bool) {
	s, _, _ = strings.Cut(s, ",") // protocol chain: only the first element binds
	s, _, _ = strings.Cut(s, "?") // strip query params (cert=, key=, ...)
	if _, rest, found := strings.Cut(s, "://"); found {
		s = rest
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:] // strip userinfo (last '@': a password may contain one)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", false
	}
	return host, port, true
}

// wildcardHost reports whether host binds every interface.
func wildcardHost(host string) bool {
	return host == "" || host == "0.0.0.0" || host == "::"
}

// applyGlobals pushes the Config-derived values that live in package-level
// globals (logger verbosity, relay buffer sizes) into their destinations.
// Kept out of parseConfig so a reload that fails after a successful parse
// leaves the previous globals intact instead of half-applying new values.
func applyGlobals(conf *Config) {
	log.Set(conf.Verbose, conf.LogFlags)
	if conf.TCPBufSize > 0 {
		proxy.TCPBufSize = conf.TCPBufSize
	}
	if conf.UDPBufSize > 0 {
		proxy.UDPBufSize = conf.UDPBufSize
	}
}

func loadRules(conf *Config, confDir string) error {
	// rulefiles
	for _, ruleFile := range conf.RuleFiles {
		if !path.IsAbs(ruleFile) {
			ruleFile = path.Join(confDir, ruleFile)
		}

		r, err := rule.NewConfFromFile(ruleFile)
		if err != nil {
			return err
		}

		conf.rules = append(conf.rules, r)
	}

	if conf.RulesDir != "" {
		rulesDir := conf.RulesDir
		if !path.IsAbs(rulesDir) {
			rulesDir = path.Join(confDir, rulesDir)
		}

		ruleFolderFiles, _ := rule.ListDir(rulesDir, ".rule")
		for _, ruleFile := range ruleFolderFiles {
			r, err := rule.NewConfFromFile(ruleFile)
			if err != nil {
				return err
			}
			conf.rules = append(conf.rules, r)
		}
	}
	return nil
}

var usage1 = `
Usage: glider [-listen URL]... [-forward URL]... [OPTION]...

  e.g. glider -config /etc/glider/glider.conf
       glider -listen :8443 -forward socks5://serverA:1080 -forward socks5://serverB:1080 -verbose

OPTION:
`

var usage2 = `
URL:
   proxy: SCHEME://[USER:PASS@][HOST]:PORT
   chain: proxy,proxy[,proxy]...

    e.g. -listen socks5://:1080
         -listen tls://:443?cert=crtFilePath&key=keyFilePath,http://    (protocol chain)

    e.g. -forward socks5://server:1080
         -forward tls://server.com:443,http://                          (protocol chain)
         -forward socks5://serverA:1080,socks5://serverB:1080           (proxy chain)

SCHEME:
   listen : %s
   forward: %s

   Note: use 'glider -scheme all' or 'glider -scheme SCHEME' to see help info for the scheme.

--
Forwarder Options: FORWARD_URL#OPTIONS
   priority : the priority of that forwarder, the larger the higher, default: 0
   interface: the local interface or ip address used to connect remote server.

   e.g. -forward socks5://server:1080#priority=100
        -forward socks5://server:1080#interface=eth0
        -forward socks5://server:1080#priority=100&interface=192.168.1.99

Services:
   dhcpd: service=dhcpd,INTERFACE,START_IP,END_IP,LEASE_MINUTES[,MAC=IP,MAC=IP...]
          service=dhcpd-failover,INTERFACE,START_IP,END_IP,LEASE_MINUTES[,MAC=IP,MAC=IP...]
     e.g. service=dhcpd,eth1,192.168.1.100,192.168.1.199,720

--
Help:
   glider -help
   glider -scheme all
   glider -example

see README.md and glider.conf.example for more details.
--
glider %s, https://github.com/nadoo/glider (glider.proxy@gmail.com)
`

var examples = `
Examples:
  glider -config glider.conf
    -run glider with specified config file.

  glider -listen :8443 -verbose
    -listen on :8443, serve as http/socks5 proxy on the same port, in verbose mode.

  glider -listen socks5://:1080 -listen http://:8080 -verbose
    -multiple listeners: listen on :1080 as socks5 proxy server, and on :8080 as http proxy server.

  glider -listen :8443 -forward direct://#interface=eth0 -forward direct://#interface=eth1
    -multiple forwarders: listen on 8443 and forward requests via interface eth0 and eth1 in round robin mode.

  glider -listen tls://:443?cert=crtFilePath&key=keyFilePath,http:// -verbose
    -protocol chain: listen on :443 as a https(http over tls) proxy server.

  glider -listen http://:8080 -forward socks5://serverA:1080,socks5://serverB:1080
    -proxy chain: listen on :8080 as a http proxy server, forward all requests via forward chain.

  glider -listen :8443 -forward socks5://serverA:1080 -forward socks5://serverB:1080#priority=10 -forward socks5://serverC:1080#priority=10
    -forwarder priority: serverA will only be used when serverB and serverC are not available.

  glider -listen tcp://:80 -forward tcp://serverA:80
    -tcp tunnel: listen on :80 and forward all requests to serverA:80.

  glider -listen udp://:53 -forward socks5://serverA:1080,udp://8.8.8.8:53
    -udp tunnel: listen on :53 and forward all udp requests to 8.8.8.8:53 via remote socks5 server.

  glider -verbose -dns=:53 -dnsserver=8.8.8.8:53 -forward socks5://serverA:1080 -dnsrecord=abc.com/1.2.3.4
    -dns over proxy: listen on :53 as dns server, forward to 8.8.8.8:53 via socks5 server.
`
