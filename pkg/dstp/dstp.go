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
	"github.com/DivyendraPatil/dstp/pkg/routing"
	"github.com/DivyendraPatil/dstp/pkg/routing/cymru"
	"github.com/DivyendraPatil/dstp/pkg/routing/rdap"
	"github.com/DivyendraPatil/dstp/pkg/routing/ripestat"
)

// ErrChecksFailed is returned when one or more connectivity checks failed.
var ErrChecksFailed = errors.New("one or more checks failed")

// Runner executes checks and optionally renders output.
type Runner struct {
	Stdout io.Writer
	Stderr io.Writer
	// PingFunc overrides the default ping implementation (tests).
	PingFunc func(ctx context.Context, addr common.Address, count int, timeout time.Duration, result *common.Result) error
	// Optional injectable providers (defaults: RIPEstat, RDAP.org, Team Cymru DNS).
	RoutingProvider routing.RoutingProvider
	RDAPProvider    routing.RDAPProvider
	HopASNProvider  routing.ASNProvider
}

// DefaultRunner writes to stdout/stderr.
func DefaultRunner() *Runner {
	return &Runner{Stdout: os.Stdout, Stderr: os.Stderr}
}

func (rn *Runner) routingProvider() routing.RoutingProvider {
	if rn != nil && rn.RoutingProvider != nil {
		return rn.RoutingProvider
	}
	return ripestat.New()
}

func (rn *Runner) rdapProvider() routing.RDAPProvider {
	if rn != nil && rn.RDAPProvider != nil {
		return rn.RDAPProvider
	}
	return rdap.New()
}

func (rn *Runner) hopASNProvider() routing.ASNProvider {
	if rn != nil && rn.HopASNProvider != nil {
		return rn.HopASNProvider
	}
	return cymru.New()
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

	// One run func per CheckID — Registry drives Extra/skip/order.
	runners := map[CheckID]func(context.Context){
		CheckPing: func(jctx context.Context) {
			jctx, cancel := context.WithTimeout(jctx, timeout)
			defer cancel()
			_ = pingFn(jctx, common.Address(addr), cfg.PingCount, timeout, result)
		},
		CheckDNS: func(jctx context.Context) {
			jctx, cancel := context.WithTimeout(jctx, timeout)
			defer cancel()
			_ = lookup.Default(jctx, common.Address(addr), timeout, cfg.DoH, cfg.DoHURL, cfg.DoHBootstrap, lookup.DoHFormat(cfg.DoHFormat), result)
		},
		CheckConfiguredDNS: func(jctx context.Context) {
			jctx, cancel := context.WithTimeout(jctx, timeout)
			defer cancel()
			_ = lookup.Host(jctx, common.Address(addr), cfg.CustomDnsServer, timeout, result)
		},
		CheckRecords: func(jctx context.Context) {
			jctx, cancel := context.WithTimeout(jctx, timeout)
			defer cancel()
			_ = lookup.Records(jctx, common.Address(addr), cfg.CustomDnsServer, cfg.DoH, cfg.DoHURL, lookup.DoHFormat(cfg.DoHFormat), timeout, result)
		},
		CheckMail: func(jctx context.Context) {
			jctx, cancel := context.WithTimeout(jctx, timeout)
			defer cancel()
			_ = lookup.MailAuth(jctx, common.Address(addr), cfg.CustomDnsServer, timeout, result)
		},
		CheckDNSSEC: func(jctx context.Context) {
			jctx, cancel := context.WithTimeout(jctx, timeout)
			defer cancel()
			_ = lookup.DNSSEC(jctx, common.Address(addr), cfg.CustomDnsServer, timeout, result)
		},
		CheckRouting: func(jctx context.Context) {
			_ = rn.testRouting(jctx, common.Address(addr), timeout, result)
		},
		CheckRDAP: func(jctx context.Context) {
			_ = rn.testRDAPCheck(jctx, common.Address(addr), timeout, result)
		},
		CheckTCP: func(jctx context.Context) {
			_ = testTCP(jctx, common.Address(addr), tcpPort, timeout, result)
		},
		CheckUDP: func(jctx context.Context) {
			_ = testUDPSmart(jctx, common.Address(addr), udpPort, cfg.CustomDnsServer, timeout, result)
		},
		CheckTLS: func(jctx context.Context) {
			_ = testTLS(jctx, common.Address(addr), port, timeout, cfg.Insecure, result)
		},
		CheckHTTP: func(jctx context.Context) {
			_ = testHTTP(jctx, target, httpPort, timeout, cfg.HTTPMethod, cfg.FollowRedirects, result)
		},
		CheckHTTPS: func(jctx context.Context) {
			_ = testHTTPS(jctx, target, port, timeout, cfg.HTTPMethod, cfg.FollowRedirects, cfg.Insecure, result)
		},
		CheckHTTP3: func(jctx context.Context) {
			_ = testHTTP3(jctx, target, port, timeout, cfg.HTTPMethod, cfg.Insecure, result)
		},
		CheckCDN: func(jctx context.Context) {
			_ = testCDN(jctx, target, port, timeout, cfg.Insecure, result)
		},
		CheckTraceroute: func(jctx context.Context) {
			_ = rn.testTraceroute(jctx, common.Address(addr), timeout, result)
		},
		CheckWhois: func(jctx context.Context) {
			_ = testWhois(jctx, common.Address(addr), timeout, result)
		},
		CheckMTU: func(jctx context.Context) {
			_ = testMTU(jctx, common.Address(addr), timeout, result)
		},
	}

	var wg sync.WaitGroup
	for _, meta := range Registry {
		run, ok := runners[meta.ID]
		if !ok {
			continue
		}
		if meta.Extra && !cfg.Extra {
			continue
		}
		if meta.ID == CheckConfiguredDNS && skipConfiguredDup {
			continue
		}
		if shouldSkip(cfg, string(meta.ID)) {
			setByID(result, meta.ID, common.Skipped())
			continue
		}
		wg.Add(1)
		meta, run := meta, run
		go func() {
			defer wg.Done()
			progress.start(string(meta.ID))
			run(ctx)
			progress.done(string(meta.ID), getByID(result, meta.ID))
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
