package dstp

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/DivyendraPatil/dstp/config"
	"github.com/DivyendraPatil/dstp/pkg/common"
	"github.com/DivyendraPatil/dstp/pkg/lookup"
	"github.com/DivyendraPatil/dstp/pkg/ping"
)

// ErrChecksFailed is returned when one or more connectivity checks failed.
var ErrChecksFailed = errors.New("one or more checks failed")

// Runner executes checks and optionally renders output.
type Runner struct {
	Stdout io.Writer
	Stderr io.Writer
	// PingFunc overrides the default ping implementation (tests).
	PingFunc func(ctx context.Context, addr common.Address, count int, timeout time.Duration, result *common.Result) error
}

// DefaultRunner writes to stdout/stderr.
func DefaultRunner() *Runner {
	return &Runner{Stdout: os.Stdout, Stderr: os.Stderr}
}

// Run executes selected checks and returns the aggregated result.
// It does not write output; call Render separately or use RunAllTests.
func (rn *Runner) Run(ctx context.Context, cfg config.Config) (*common.Result, error) {
	result := &common.Result{}

	target, err := parseTarget(cfg.Addr)
	if err != nil {
		return result, err
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

	progress := newProgress(!cfg.Quiet && cfg.Output != "json")
	if rn.Stderr != nil {
		progress.w = rn.Stderr
	}

	skipConfiguredDup := cfg.CustomDnsServer == "" && !cfg.DoH
	pingFn := rn.PingFunc
	if pingFn == nil {
		pingFn = ping.RunTest
	}

	type job struct {
		meta CheckMeta
		run  func()
	}

	jobs := []job{
		{lookupMetaMust(CheckPing), func() {
			jctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			progress.start(string(CheckPing))
			_ = pingFn(jctx, common.Address(addr), cfg.PingCount, timeout, result)
			progress.done(string(CheckPing), getByID(result, CheckPing))
		}},
		{lookupMetaMust(CheckDNS), func() {
			jctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			progress.start(string(CheckDNS))
			_ = lookup.Default(jctx, common.Address(addr), timeout, cfg.DoH, cfg.DoHURL, cfg.DoHBootstrap, lookup.DoHFormat(cfg.DoHFormat), result)
			progress.done(string(CheckDNS), getByID(result, CheckDNS))
		}},
		{lookupMetaMust(CheckConfiguredDNS), func() {
			jctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			progress.start(string(CheckConfiguredDNS))
			_ = lookup.Host(jctx, common.Address(addr), cfg.CustomDnsServer, timeout, result)
			progress.done(string(CheckConfiguredDNS), getByID(result, CheckConfiguredDNS))
		}},
		{lookupMetaMust(CheckRecords), func() {
			jctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			progress.start(string(CheckRecords))
			_ = lookup.Records(jctx, common.Address(addr), cfg.CustomDnsServer, cfg.DoH, cfg.DoHURL, lookup.DoHFormat(cfg.DoHFormat), timeout, result)
			progress.done(string(CheckRecords), getByID(result, CheckRecords))
		}},
		{lookupMetaMust(CheckMail), func() {
			jctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			progress.start(string(CheckMail))
			_ = lookup.MailAuth(jctx, common.Address(addr), cfg.CustomDnsServer, timeout, result)
			progress.done(string(CheckMail), getByID(result, CheckMail))
		}},
		{lookupMetaMust(CheckDNSSEC), func() {
			jctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			progress.start(string(CheckDNSSEC))
			_ = lookup.DNSSEC(jctx, common.Address(addr), cfg.CustomDnsServer, timeout, result)
			progress.done(string(CheckDNSSEC), getByID(result, CheckDNSSEC))
		}},
		{lookupMetaMust(CheckTCP), func() {
			progress.start(string(CheckTCP))
			_ = testTCP(ctx, common.Address(addr), tcpPort, timeout, result)
			progress.done(string(CheckTCP), getByID(result, CheckTCP))
		}},
		{lookupMetaMust(CheckUDP), func() {
			progress.start(string(CheckUDP))
			_ = testUDPSmart(ctx, common.Address(addr), udpPort, cfg.CustomDnsServer, timeout, result)
			progress.done(string(CheckUDP), getByID(result, CheckUDP))
		}},
		{lookupMetaMust(CheckTLS), func() {
			progress.start(string(CheckTLS))
			_ = testTLS(ctx, common.Address(addr), port, timeout, cfg.Insecure, result)
			progress.done(string(CheckTLS), getByID(result, CheckTLS))
		}},
		{lookupMetaMust(CheckHTTP), func() {
			progress.start(string(CheckHTTP))
			_ = testHTTP(ctx, target, httpPort, timeout, cfg.HTTPMethod, cfg.FollowRedirects, result)
			progress.done(string(CheckHTTP), getByID(result, CheckHTTP))
		}},
		{lookupMetaMust(CheckHTTPS), func() {
			progress.start(string(CheckHTTPS))
			_ = testHTTPS(ctx, target, port, timeout, cfg.HTTPMethod, cfg.FollowRedirects, cfg.Insecure, result)
			progress.done(string(CheckHTTPS), getByID(result, CheckHTTPS))
		}},
		{lookupMetaMust(CheckHTTP3), func() {
			progress.start(string(CheckHTTP3))
			_ = testHTTP3(ctx, target, port, timeout, cfg.HTTPMethod, cfg.Insecure, result)
			progress.done(string(CheckHTTP3), getByID(result, CheckHTTP3))
		}},
		{lookupMetaMust(CheckCDN), func() {
			progress.start(string(CheckCDN))
			_ = testCDN(ctx, target, port, timeout, cfg.Insecure, result)
			progress.done(string(CheckCDN), getByID(result, CheckCDN))
		}},
		{lookupMetaMust(CheckTraceroute), func() {
			progress.start(string(CheckTraceroute))
			_ = testTraceroute(ctx, common.Address(addr), timeout, result)
			progress.done(string(CheckTraceroute), getByID(result, CheckTraceroute))
		}},
		{lookupMetaMust(CheckWhois), func() {
			progress.start(string(CheckWhois))
			_ = testWhois(ctx, common.Address(addr), timeout, result)
			progress.done(string(CheckWhois), getByID(result, CheckWhois))
		}},
		{lookupMetaMust(CheckMTU), func() {
			progress.start(string(CheckMTU))
			_ = testMTU(ctx, common.Address(addr), timeout, result)
			progress.done(string(CheckMTU), getByID(result, CheckMTU))
		}},
	}

	var wg sync.WaitGroup
	for _, j := range jobs {
		j := j
		if j.meta.Extra && !cfg.Extra {
			continue
		}
		if j.meta.ID == CheckConfiguredDNS && skipConfiguredDup {
			continue
		}
		if shouldSkip(cfg, string(j.meta.ID)) {
			setByID(result, j.meta.ID, common.Skipped())
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			j.run()
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if result.Failed() {
		return result, ErrChecksFailed
	}
	return result, nil
}

// Render writes the result to Stdout using cfg.Output.
func (rn *Runner) Render(cfg config.Config, result *common.Result) {
	if result == nil {
		return
	}
	out := result.Output(cfg.Output)
	w := rn.Stdout
	if w == nil {
		if cfg.Output == "json" {
			printWithColor(out + "\n")
		} else {
			printWithColor(out)
		}
		return
	}
	if cfg.Output == "json" {
		_, _ = io.WriteString(w, out+"\n")
	} else {
		_, _ = io.WriteString(w, out)
	}
}

// RunAllTests executes selected checks and prints output (CLI compatibility).
func RunAllTests(ctx context.Context, cfg config.Config) error {
	common.InitColor()
	rn := DefaultRunner()
	result, err := rn.Run(ctx, cfg)
	rn.Render(cfg, result)
	return err
}

func lookupMetaMust(id CheckID) CheckMeta {
	m, ok := lookupMeta(string(id))
	if !ok {
		return CheckMeta{ID: id, Label: string(id), JSONKey: string(id)}
	}
	return m
}

func shouldSkip(cfg config.Config, name string) bool {
	if cfg.ShouldSkip(name) {
		return true
	}
	m, ok := lookupMeta(name)
	if !ok {
		return false
	}
	for _, a := range m.Aliases {
		if cfg.ShouldSkip(a) {
			return true
		}
	}
	return false
}

func isExtraCheck(name string) bool {
	m, ok := lookupMeta(name)
	return ok && m.Extra
}
