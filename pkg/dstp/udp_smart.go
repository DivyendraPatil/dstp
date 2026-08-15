package dstp

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

// udpProbeTarget decides where to send the UDP:53 probe.
// Web/CDN A/AAAA hosts are not nameservers; prefer an NS host when available.
type udpProbeTarget struct {
	Host   string
	Note   string // e.g. "via NS ajay.ns.cloudflare.com"
	Skip   bool
	Reason string // when Skip
}

func resolveUDPProbeTarget(ctx context.Context, address common.Address, port, customDNS string, timeout time.Duration) udpProbeTarget {
	host := strings.TrimSuffix(string(address), ".")
	if port != "53" {
		return udpProbeTarget{Host: host}
	}
	if net.ParseIP(host) != nil {
		// Literal IP may be a resolver; probe it directly.
		return udpProbeTarget{Host: host}
	}

	nsHosts, err := lookupNSWalk(ctx, host, customDNS, timeout)
	if err != nil || len(nsHosts) == 0 {
		// No NS context — keep legacy probe (often inconclusive on CDN edges).
		return udpProbeTarget{Host: host}
	}

	norm := strings.ToLower(host)
	for _, ns := range nsHosts {
		if strings.EqualFold(ns, norm) {
			return udpProbeTarget{Host: host, Note: "host is nameserver"}
		}
	}

	// Retarget to first NS (stable sort already applied).
	return udpProbeTarget{
		Host: nsHosts[0],
		Note: fmt.Sprintf("via NS %s (web/CDN host is not a nameserver)", nsHosts[0]),
	}
}

func lookupNSWalk(ctx context.Context, host, customDNS string, timeout time.Duration) ([]string, error) {
	r := resolverForUDP(customDNS, timeout)
	labels := strings.Split(strings.TrimSuffix(host, "."), ".")
	for i := 0; i < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		if candidate == "" || !strings.Contains(candidate, ".") {
			// Avoid TLD-only lookups like "city" / "com".
			continue
		}
		ns, err := r.LookupNS(ctx, candidate)
		if err != nil || len(ns) == 0 {
			continue
		}
		var hosts []string
		for _, n := range ns {
			h := strings.TrimSuffix(n.Host, ".")
			if h != "" {
				hosts = append(hosts, h)
			}
		}
		if len(hosts) == 0 {
			continue
		}
		// Stable order for deterministic retarget.
		sortStringsCI(hosts)
		return hosts, nil
	}
	return nil, fmt.Errorf("no NS records")
}

func resolverForUDP(customDNS string, timeout time.Duration) *net.Resolver {
	if customDNS == "" {
		return net.DefaultResolver
	}
	server := customDNS
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, network, server)
		},
	}
}

func sortStringsCI(in []string) {
	// insertion sort case-insensitive
	for i := 1; i < len(in); i++ {
		j := i
		for j > 0 && strings.ToLower(in[j]) < strings.ToLower(in[j-1]) {
			in[j], in[j-1] = in[j-1], in[j]
			j--
		}
	}
}

func testUDPSmart(ctx context.Context, address common.Address, port, customDNS string, timeout time.Duration, result *common.Result) error {
	target := resolveUDPProbeTarget(ctx, address, port, customDNS, timeout)
	if target.Skip {
		result.Store(&result.UDP, common.NotApplicable(target.Reason))
		return nil
	}
	err := testUDP(ctx, common.Address(target.Host), port, timeout, result)
	if target.Note == "" || result.UDP.Status == common.StatusError {
		return err
	}
	// Annotate successful/inconclusive outcomes with retarget note.
	result.Mu.Lock()
	defer result.Mu.Unlock()
	part := result.UDP
	if part.Content != "" {
		part.Content = part.Content + "; " + target.Note
	} else if part.Error != nil {
		// keep error
	} else {
		part.Content = target.Note
	}
	result.UDP = part
	return err
}
