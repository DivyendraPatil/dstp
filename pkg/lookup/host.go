// Package lookup resolves hosts via the system resolver, a custom DNS server, or DoH.
package lookup

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

// Default resolves addr with the system default resolver, optionally via DoH.
func Default(ctx context.Context, addr common.Address, timeout time.Duration, doh bool, dohURL, dohBootstrap string, result *common.Result) error {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host := addr.String()
	if ip := net.ParseIP(host); ip != nil {
		result.Store(&result.DNS, common.Inconclusive("forward DNS not applicable for literal IP (use PTR via records)"))
		return nil
	}

	var addrs []string
	var err error
	if doh {
		addrs, err = lookupDoH(lookupCtx, dohURL, host, dohBootstrap, timeout)
	} else {
		addrs, err = net.DefaultResolver.LookupHost(lookupCtx, host)
	}
	if err != nil {
		result.Store(&result.DNS, common.Fail(err))
		return err
	}

	result.Store(&result.DNS, common.OK(formatAddrs(addrs)))
	return nil
}

// Host resolves via the configured resolver (system or custom --dns).
func Host(ctx context.Context, addr common.Address, customDnsServer string, timeout time.Duration, result *common.Result) error {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host := addr.String()
	if ip := net.ParseIP(host); ip != nil {
		result.Store(&result.SystemDNS, common.Inconclusive("forward DNS not applicable for literal IP"))
		return nil
	}

	r := resolverFor(customDnsServer, timeout)
	addrs, err := r.LookupHost(lookupCtx, host)
	if err != nil {
		result.Store(&result.SystemDNS, common.Fail(err))
		return err
	}

	result.Store(&result.SystemDNS, common.OK(formatAddrs(addrs)))
	return nil
}

// Records looks up A/AAAA/CNAME/MX/NS/TXT (or PTR for literal IPs) via the selected backend.
func Records(ctx context.Context, addr common.Address, customDNS string, doh bool, dohURL string, timeout time.Duration, result *common.Result) error {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host := addr.String()
	if ip := net.ParseIP(host); ip != nil {
		names, err := net.DefaultResolver.LookupAddr(lookupCtx, host)
		if err != nil {
			result.Store(&result.Records, common.Fail(err))
			return err
		}
		for i := range names {
			names[i] = strings.TrimSuffix(names[i], ".")
		}
		sort.Strings(names)
		result.Store(&result.Records, common.OK("PTR="+strings.Join(uniqueSorted(names), ",")))
		return nil
	}

	r := resolverFor(customDNS, timeout)
	if doh && customDNS == "" {
		// Prefer DoH for A/AAAA; other types still use system unless custom DNS set.
		addrs, err := lookupDoH(lookupCtx, dohURL, host, "", timeout)
		if err != nil {
			result.Store(&result.Records, common.Fail(err))
			return err
		}
		result.Store(&result.Records, common.OK(formatAddrs(addrs)+" (DoH A/AAAA)"))
		return nil
	}

	var (
		mu    sync.Mutex
		parts []string
		errs  []error
	)
	add := func(label string, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
			return
		}
		if label != "" {
			parts = append(parts, label)
		}
	}

	var wg sync.WaitGroup
	wg.Add(6)
	go func() {
		defer wg.Done()
		ips, err := r.LookupIP(lookupCtx, "ip4", host)
		if err != nil {
			add("A", err)
			return
		}
		if len(ips) > 0 {
			add("A="+joinIPs(ips), nil)
		}
	}()
	go func() {
		defer wg.Done()
		ips, err := r.LookupIP(lookupCtx, "ip6", host)
		if err != nil {
			add("AAAA", err)
			return
		}
		if len(ips) > 0 {
			add("AAAA="+joinIPs(ips), nil)
		}
	}()
	go func() {
		defer wg.Done()
		cname, err := r.LookupCNAME(lookupCtx, host)
		if err != nil {
			add("CNAME", err)
			return
		}
		trimmed := strings.TrimSuffix(cname, ".")
		if trimmed != "" && !strings.EqualFold(trimmed, host) {
			add("CNAME="+trimmed, nil)
		}
	}()
	go func() {
		defer wg.Done()
		mx, err := r.LookupMX(lookupCtx, host)
		if err != nil {
			add("MX", err)
			return
		}
		if len(mx) == 0 {
			return
		}
		var hosts []string
		for _, m := range mx {
			h := strings.TrimSuffix(m.Host, ".")
			if h == "" {
				h = "."
			}
			hosts = append(hosts, fmt.Sprintf("%s(pri=%d)", h, m.Pref))
		}
		add("MX="+strings.Join(hosts, ","), nil)
	}()
	go func() {
		defer wg.Done()
		ns, err := r.LookupNS(lookupCtx, host)
		if err != nil {
			add("NS", err)
			return
		}
		if len(ns) == 0 {
			return
		}
		var hosts []string
		for _, n := range ns {
			hosts = append(hosts, strings.TrimSuffix(n.Host, "."))
		}
		sort.Strings(hosts)
		add("NS="+strings.Join(uniqueSorted(hosts), ","), nil)
	}()
	go func() {
		defer wg.Done()
		txt, err := r.LookupTXT(lookupCtx, host)
		if err != nil {
			add("TXT", err)
			return
		}
		if len(txt) == 0 {
			return
		}
		clipped := txt
		if len(clipped) > 3 {
			clipped = append(append([]string{}, txt[:3]...), fmt.Sprintf("…(+%d)", len(txt)-3))
		}
		add("TXT="+strings.Join(clipped, " | "), nil)
	}()
	wg.Wait()

	if len(parts) == 0 {
		err := fmt.Errorf("no DNS records found")
		if len(errs) > 0 {
			err = fmt.Errorf("%w (%v)", err, errs)
		}
		result.Store(&result.Records, common.Fail(err))
		return err
	}
	sort.Strings(parts)
	content := strings.Join(parts, "; ")
	if len(errs) > 0 {
		content += fmt.Sprintf(" (partial; %d lookup errors)", len(errs))
		result.Store(&result.Records, common.Warn(content))
		return nil
	}
	result.Store(&result.Records, common.OK(content))
	return nil
}

func resolverFor(customDnsServer string, timeout time.Duration) *net.Resolver {
	if customDnsServer == "" {
		return net.DefaultResolver
	}
	customDnsServer = formatDNSServer(customDnsServer)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			// Honor the network Go requests (udp/tcp) for truncated-response fallback.
			return d.DialContext(ctx, network, customDnsServer)
		},
	}
}

func formatAddrs(addrs []string) string {
	seen := map[string]struct{}{}
	var v4, v6, other []string
	for _, a := range addrs {
		a = strings.TrimSuffix(strings.TrimSpace(a), ".")
		if a == "" {
			continue
		}
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		ip := net.ParseIP(a)
		switch {
		case ip == nil:
			other = append(other, a)
		case ip.To4() != nil:
			v4 = append(v4, a)
		default:
			v6 = append(v6, a)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	sort.Strings(other)
	var parts []string
	if len(v4) > 0 {
		parts = append(parts, "IPv4="+strings.Join(v4, ","))
	}
	if len(v6) > 0 {
		parts = append(parts, "IPv6="+strings.Join(v6, ","))
	}
	if len(other) > 0 {
		parts = append(parts, "other="+strings.Join(other, ","))
	}
	if len(parts) == 0 {
		return "resolving " + strings.Join(addrs, ", ")
	}
	return strings.Join(parts, " ")
}

func joinIPs(ips []net.IP) string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return strings.Join(uniqueSorted(out), ",")
}

func uniqueSorted(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func formatDNSServer(server string) string {
	if server == "" {
		return server
	}
	// Already host:port (including [v6]:port)
	if host, port, err := net.SplitHostPort(server); err == nil {
		if port == "" {
			return net.JoinHostPort(host, "53")
		}
		return net.JoinHostPort(host, port)
	}
	// Bracketed IPv6 without port: [2001:db8::1]
	if strings.HasPrefix(server, "[") && strings.HasSuffix(server, "]") {
		inner := server[1 : len(server)-1]
		return net.JoinHostPort(inner, "53")
	}
	// Bare IPv6
	if ip := net.ParseIP(server); ip != nil {
		return net.JoinHostPort(server, "53")
	}
	return net.JoinHostPort(server, "53")
}
