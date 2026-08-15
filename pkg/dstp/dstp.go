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
// It prints results to stdout. Returns ErrChecksFailed if any check failed.
func RunAllTests(ctx context.Context, cfg config.Config) error {
	common.InitColor()

	addr, err := getAddr(cfg.Addr)
	if err != nil {
		return err
	}

	timeout := cfg.TimeoutDuration()
	port := cfg.Port
	if port == "" {
		port = "443"
	}
	tcpPort := cfg.TCPPort
	if tcpPort == "" {
		tcpPort = port
	}

	var result common.Result
	progress := newProgress(!cfg.Quiet && cfg.Output != "json")

	type job struct {
		name string
		run  func()
	}

	jobs := []job{
		{"ping", func() {
			progress.start("ping")
			_ = ping.RunTest(ctx, common.Address(addr), cfg.PingCount, timeout, &result)
			progress.done("ping", snapshot(&result, "ping"))
		}},
		{"dns", func() {
			progress.start("dns")
			_ = lookup.Default(ctx, common.Address(addr), timeout, cfg.DoH, cfg.DoHURL, &result)
			progress.done("dns", snapshot(&result, "dns"))
		}},
		{"configured_dns", func() {
			progress.start("configured_dns")
			_ = lookup.Host(ctx, common.Address(addr), cfg.CustomDnsServer, timeout, &result)
			progress.done("configured_dns", snapshot(&result, "configured_dns"))
		}},
		{"records", func() {
			progress.start("records")
			_ = lookup.Records(ctx, common.Address(addr), timeout, &result)
			progress.done("records", snapshot(&result, "records"))
		}},
		{"tcp", func() {
			progress.start("tcp")
			_ = testTCP(ctx, common.Address(addr), tcpPort, timeout, &result)
			progress.done("tcp", snapshot(&result, "tcp"))
		}},
		{"tls", func() {
			progress.start("tls")
			_ = testTLS(ctx, common.Address(addr), port, timeout, &result)
			progress.done("tls", snapshot(&result, "tls"))
		}},
		{"https", func() {
			progress.start("https")
			_ = testHTTPS(ctx, common.Address(addr), port, timeout, cfg.HTTPMethod, cfg.FollowRedirects, &result)
			progress.done("https", snapshot(&result, "https"))
		}},
	}

	var wg sync.WaitGroup
	for _, j := range jobs {
		j := j
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

	if result.Failed() {
		return ErrChecksFailed
	}
	return nil
}

func shouldSkip(cfg config.Config, name string) bool {
	if cfg.ShouldSkip(name) {
		return true
	}
	// legacy alias
	return name == "configured_dns" && cfg.ShouldSkip("system_dns")
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
	case "tls":
		return result.TLS
	case "https":
		return result.HTTPS
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
	case "tls":
		result.Store(&result.TLS, s)
	case "https":
		result.Store(&result.HTTPS, s)
	}
}
