package rule

import (
	"flag"
	"os"
	"strings"

	"github.com/nadoo/conflag"
)

// Config is config of rule.
type Config struct {
	RulePath string

	Forward  []string
	Strategy Strategy

	DNSServers []string
	IPSet      string

	Domain []string
	IP     []string
	CIDR   []string
}

// Strategy configurations.
type Strategy struct {
	Strategy            string
	Check               string
	CheckInterval       int
	CheckTimeout        int
	CheckTolerance      int
	CheckLatencySamples int
	CheckDisabledOnly   bool
	MaxFailures         int
	DialTimeout         int
	RelayTimeout        int
	IntFace             string

	// DialAttempts is how many forwarders one Dial may try before it gives up,
	// and DialBudget (seconds; 0 = no clock bound) caps the wall clock those
	// retries may spend. See FwdrGroup.Dial for why both bounds are needed.
	DialAttempts int
	DialBudget   int
}

// NewConfFromFile returns a new config from file.
func NewConfFromFile(ruleFile string) (*Config, error) {
	p := &Config{RulePath: ruleFile}

	f := conflag.NewFromFile("rule", ruleFile)
	// See config.go for rationale: switch FlagSet to ContinueOnError so a
	// malformed rule file returns an error on SIGHUP reload instead of
	// killing the process via os.Exit.
	f.FlagSet.Init(f.FlagSet.Name(), flag.ContinueOnError)
	f.StringSliceUniqVar(&p.Forward, "forward", nil, "forward url, format: SCHEME://[USER|METHOD:PASSWORD@][HOST]:PORT?PARAMS[,SCHEME://[USER|METHOD:PASSWORD@][HOST]:PORT?PARAMS]")
	f.StringVar(&p.Strategy.Strategy, "strategy", "rr", "forward strategy, default: rr")
	f.StringVar(&p.Strategy.Check, "check", "http://www.msftconnecttest.com/connecttest.txt#expect=200", "check=tcp[://HOST:PORT]: tcp port connect check\ncheck=http://HOST[:PORT][/URI][#expect=STRING_IN_RESP_LINE]\ncheck=file://SCRIPT_PATH: run a check script, healthy when exitcode=0, environment variables: FORWARDER_ADDR\ncheck=disable: disable health check")
	f.IntVar(&p.Strategy.CheckInterval, "checkinterval", 30, "fowarder check interval(seconds)")
	f.IntVar(&p.Strategy.CheckTimeout, "checktimeout", 10, "fowarder check timeout(seconds)")
	f.IntVar(&p.Strategy.CheckLatencySamples, "checklatencysamples", 10, "use the average latency of the latest N checks")
	f.IntVar(&p.Strategy.CheckTolerance, "checktolerance", 0, "fowarder check tolerance(ms), switch only when new_latency < old_latency - tolerance, only used in lha mode")
	f.BoolVar(&p.Strategy.CheckDisabledOnly, "checkdisabledonly", false, "check disabled fowarders only")
	f.IntVar(&p.Strategy.MaxFailures, "maxfailures", 3, "max failures to change forwarder status to disabled")
	f.IntVar(&p.Strategy.DialTimeout, "dialtimeout", 3, "dial timeout(seconds)")
	f.IntVar(&p.Strategy.RelayTimeout, "relaytimeout", 0, "relay timeout(seconds)")
	f.IntVar(&p.Strategy.DialAttempts, "dialattempts", DefaultDialAttempts, "max forwarders to try for one dial, a failed dial retries on the next forwarder")
	f.IntVar(&p.Strategy.DialBudget, "dialbudget", DefaultDialBudget, "wall-clock budget for dial retries(seconds), 0 to bound by dialattempts only; keep it below the downstream client's dial timeout")
	f.StringVar(&p.Strategy.IntFace, "interface", "", "source ip or source interface")

	f.StringSliceUniqVar(&p.DNSServers, "dnsserver", nil, "remote dns server")
	f.StringVar(&p.IPSet, "ipset", "", "ipset NAME, will create 2 sets: NAME for ipv4 and NAME6 for ipv6")

	f.StringSliceVar(&p.Domain, "domain", nil, "domain")
	f.StringSliceVar(&p.IP, "ip", nil, "ip")
	f.StringSliceVar(&p.CIDR, "cidr", nil, "cidr")

	err := f.Parse()
	if err != nil {
		return nil, err
	}

	return p, err
}

// ListDir returns file list named with suffix in dirPth.
func ListDir(dirPth string, suffix string) (files []string, err error) {
	files = make([]string, 0, 10)
	dir, err := os.ReadDir(dirPth)
	if err != nil {
		return nil, err
	}
	PthSep := string(os.PathSeparator)
	suffix = strings.ToLower(suffix)
	for _, fi := range dir {
		if fi.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(fi.Name()), suffix) {
			files = append(files, dirPth+PthSep+fi.Name())
		}
	}
	return files, nil
}
