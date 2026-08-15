// Package lookup resolves hosts via the system resolver, a custom DNS server, or DoH.
package lookup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ycd/dstp/pkg/common"
)

// Default resolves addr with the system default resolver, optionally via DoH.
func Default(ctx context.Context, addr common.Address, timeout time.Duration, doh bool, dohURL string, result *common.Result) error {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var addrs []string
	var err error
	if doh {
		addrs, err = lookupDoH(lookupCtx, dohURL, addr.String(), timeout)
	} else {
		addrs, err = net.DefaultResolver.LookupHost(lookupCtx, addr.String())
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

	r := net.DefaultResolver
	if customDnsServer != "" {
		customDnsServer = formatDNSServer(customDnsServer)
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", customDnsServer)
			},
		}
	}

	addrs, err := r.LookupHost(lookupCtx, addr.String())
	if err != nil {
		result.Store(&result.SystemDNS, common.Fail(err))
		return err
	}

	result.Store(&result.SystemDNS, common.OK(formatAddrs(addrs)))
	return nil
}

// Records looks up A/AAAA/CNAME/MX/NS/TXT with an IPv4/IPv6 split for addresses.
func Records(ctx context.Context, addr common.Address, timeout time.Duration, result *common.Result) error {
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host := addr.String()
	var parts []string

	if ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip4", host); err == nil && len(ips) > 0 {
		parts = append(parts, "A="+joinIPs(ips))
	}
	if ips, err := net.DefaultResolver.LookupIP(lookupCtx, "ip6", host); err == nil && len(ips) > 0 {
		parts = append(parts, "AAAA="+joinIPs(ips))
	}
	if cname, err := net.DefaultResolver.LookupCNAME(lookupCtx, host); err == nil && cname != "" {
		trimmed := strings.TrimSuffix(cname, ".")
		if !strings.EqualFold(trimmed, host) {
			parts = append(parts, "CNAME="+trimmed)
		}
	}
	if mx, err := net.DefaultResolver.LookupMX(lookupCtx, host); err == nil && len(mx) > 0 {
		var hosts []string
		for _, m := range mx {
			h := strings.TrimSuffix(m.Host, ".")
			if h == "" {
				h = "."
			}
			hosts = append(hosts, fmt.Sprintf("%s(pri=%d)", h, m.Pref))
		}
		parts = append(parts, "MX="+strings.Join(hosts, ","))
	}
	if ns, err := net.DefaultResolver.LookupNS(lookupCtx, host); err == nil && len(ns) > 0 {
		var hosts []string
		for _, n := range ns {
			hosts = append(hosts, strings.TrimSuffix(n.Host, "."))
		}
		parts = append(parts, "NS="+strings.Join(hosts, ","))
	}
	if txt, err := net.DefaultResolver.LookupTXT(lookupCtx, host); err == nil && len(txt) > 0 {
		clipped := txt
		if len(clipped) > 3 {
			clipped = append(append([]string{}, txt[:3]...), fmt.Sprintf("…(+%d)", len(txt)-3))
		}
		parts = append(parts, "TXT="+strings.Join(clipped, " | "))
	}

	if len(parts) == 0 {
		err := fmt.Errorf("no DNS records found")
		result.Store(&result.Records, common.Fail(err))
		return err
	}

	result.Store(&result.Records, common.OK(strings.Join(parts, "; ")))
	return nil
}

func formatAddrs(addrs []string) string {
	var v4, v6 []string
	for _, a := range addrs {
		ip := net.ParseIP(a)
		switch {
		case ip == nil:
			v4 = append(v4, a)
		case ip.To4() != nil:
			v4 = append(v4, a)
		default:
			v6 = append(v6, a)
		}
	}
	var parts []string
	if len(v4) > 0 {
		parts = append(parts, "IPv4="+strings.Join(v4, ","))
	}
	if len(v6) > 0 {
		parts = append(parts, "IPv6="+strings.Join(v6, ","))
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
	return strings.Join(out, ",")
}

func formatDNSServer(server string) string {
	if server == "" {
		return server
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}
