// Package dstp runs parallel connectivity checks against a host or IP.
package dstp

import (
	"context"
	"errors"
	"sync"

	"github.com/DivyendraPatil/dstp/config"
	"github.com/DivyendraPatil/dstp/pkg/common"
	"github.com/DivyendraPatil/dstp/pkg/lookup"
	"github.com/DivyendraPatil/dstp/pkg/ping"
)

// ErrChecksFailed is returned when one or more connectivity checks failed.
var ErrChecksFailed = errors.New("one or more checks failed")

// RunAllTests executes selected checks against the given domain or IP.
func RunAllTests(ctx context.Context, cfg config.Config) error {
	common.InitColor()

	target, err := parseTarget(cfg.Addr)
	if err != nil {
		return err
	}
	addr := target.Host

	timeout := cfg.TimeoutDuration()
	port := cfg.Port
	if port == "" {
		if target.Port != "" && (target.Scheme == "https" || target.Scheme == "") {
			port = target.Port
		} else {
			port = "443"
		}
	}
	tcpPort := cfg.TCPPort
	if tcpPort == "" {
		tcpPort = port
	}
	udpPort := cfg.UDPPort
	if udpPort == "" {
		udpPort = "53"
	}
	httpPort := cfg.HTTPPort
	if httpPort == "" {
		if target.Scheme == "http" && target.Port != "" {
			httpPort = target.Port
		} else {
			httpPort = "80"
		}
	}

	var result common.Result
	progress := newProgress(!cfg.Quiet && cfg.Output != "json")

	type job struct {
		name string
		run  func()
	}

	// When neither --dns nor --doh is set, ConfiguredDNS duplicates system DNS — skip it.
	skipConfiguredDup := cfg.CustomDnsServer == "" && !cfg.DoH

	jobs := []job{
		{"ping", func() {
			jctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			progress.start("ping")
			_ = ping.RunTest(jctx, common.Address(addr), cfg.PingCount, timeout, &result)
			progress.done("ping", snapshot(&result, "ping"))
		}},
		{"dns", func() {
			jctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			progress.start("dns")
			_ = lookup.Default(jctx, common.Address(addr), timeout, cfg.DoH, cfg.DoHURL, &result)
			progress.done("dns", snapshot(&result, "dns"))
		}},
		{"configured_dns", func() {
			jctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			progress.start("configured_dns")
			_ = lookup.Host(jctx, common.Address(addr), cfg.CustomDnsServer, timeout, &result)
			progress.done("configured_dns", snapshot(&result, "configured_dns"))
		}},
		{"records", func() {
			jctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			progress.start("records")
			_ = lookup.Records(jctx, common.Address(addr), cfg.CustomDnsServer, cfg.DoH, cfg.DoHURL, timeout, &result)
			progress.done("records", snapshot(&result, "records"))
		}},
		{"tcp", func() {
			progress.start("tcp")
			_ = testTCP(ctx, common.Address(addr), tcpPort, timeout, &result)
			progress.done("tcp", snapshot(&result, "tcp"))
		}},
		{"udp", func() {
			progress.start("udp")
			_ = testUDP(ctx, common.Address(addr), udpPort, timeout, &result)
			progress.done("udp", snapshot(&result, "udp"))
		}},
		{"tls", func() {
			progress.start("tls")
			_ = testTLS(ctx, common.Address(addr), port, timeout, cfg.Insecure, &result)
			progress.done("tls", snapshot(&result, "tls"))
		}},
		{"http", func() {
			progress.start("http")
			_ = testHTTP(ctx, target, httpPort, timeout, cfg.HTTPMethod, cfg.FollowRedirects, &result)
			progress.done("http", snapshot(&result, "http"))
		}},
		{"https", func() {
			progress.start("https")
			_ = testHTTPS(ctx, target, port, timeout, cfg.HTTPMethod, cfg.FollowRedirects, cfg.Insecure, &result)
			progress.done("https", snapshot(&result, "https"))
		}},
		{"traceroute", func() {
			progress.start("traceroute")
			_ = testTraceroute(ctx, common.Address(addr), timeout, &result)
			progress.done("traceroute", snapshot(&result, "traceroute"))
		}},
		{"whois", func() {
			progress.start("whois")
			_ = testWhois(ctx, common.Address(addr), timeout, &result)
			progress.done("whois", snapshot(&result, "whois"))
		}},
		{"mtu", func() {
			progress.start("mtu")
			_ = testMTU(ctx, common.Address(addr), timeout, &result)
			progress.done("mtu", snapshot(&result, "mtu"))
		}},
	}

	var wg sync.WaitGroup
	for _, j := range jobs {
		j := j
		if isExtraCheck(j.name) && !cfg.Extra {
			continue
		}
		if j.name == "configured_dns" && skipConfiguredDup {
			continue // omit duplicate of system DNS when no --dns/--doh
		}
		if shouldSkip(cfg, j.name) {
			setSkipped(&result, j.name)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			j.run()
		}()
	}
	wg.Wait()

	out := result.Output(cfg.Output)
	if cfg.Output == "json" {
		printWithColor(out + "\n")
	} else {
		printWithColor(out)
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if result.Failed() {
		return ErrChecksFailed
	}
	return nil
}

func shouldSkip(cfg config.Config, name string) bool {
	if cfg.ShouldSkip(name) {
		return true
	}
	return name == "configured_dns" && cfg.ShouldSkip("system_dns")
}

func isExtraCheck(name string) bool {
	switch name {
	case "traceroute", "whois", "mtu":
		return true
	default:
		return false
	}
}

func snapshot(result *common.Result, name string) common.ResultPart {
	result.Mu.Lock()
	defer result.Mu.Unlock()
	switch name {
	case "ping":
		return result.Ping
	case "dns":
		return result.DNS
	case "configured_dns":
		return result.SystemDNS
	case "records":
		return result.Records
	case "tcp":
		return result.TCP
	case "udp":
		return result.UDP
	case "tls":
		return result.TLS
	case "http":
		return result.HTTP
	case "https":
		return result.HTTPS
	case "traceroute":
		return result.Traceroute
	case "whois":
		return result.Whois
	case "mtu":
		return result.MTU
	default:
		return common.ResultPart{}
	}
}

func setSkipped(result *common.Result, name string) {
	s := common.Skipped()
	switch name {
	case "ping":
		result.Store(&result.Ping, s)
	case "dns":
		result.Store(&result.DNS, s)
	case "configured_dns":
		result.Store(&result.SystemDNS, s)
	case "records":
		result.Store(&result.Records, s)
	case "tcp":
		result.Store(&result.TCP, s)
	case "udp":
		result.Store(&result.UDP, s)
	case "tls":
		result.Store(&result.TLS, s)
	case "http":
		result.Store(&result.HTTP, s)
	case "https":
		result.Store(&result.HTTPS, s)
	case "traceroute":
		result.Store(&result.Traceroute, s)
	case "whois":
		result.Store(&result.Whois, s)
	case "mtu":
		result.Store(&result.MTU, s)
	}
}
