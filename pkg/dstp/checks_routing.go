package dstp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
	"github.com/DivyendraPatil/dstp/pkg/routing"
)

func (rn *Runner) testRouting(ctx context.Context, address common.Address, timeout time.Duration, result *common.Result) error {
	ctx, cancel := withCheckTimeout(ctx, timeout)
	defer cancel()

	v4, v6, err := publicIPsByFamily(ctx, address.String())
	if err != nil {
		result.Store(common.KeyRouting, common.Inconclusive(fmt.Sprintf("resolve: %v", err)))
		return nil
	}
	primary := v4
	if !primary.IsValid() {
		primary = v6
	}
	if !primary.IsValid() {
		result.Store(common.KeyRouting, common.Inconclusive("no addresses"))
		return nil
	}
	if !routing.IsPublicRoutable(primary) {
		msg := fmt.Sprintf("%s is %s; ASN/RPKI not queried", primary, routing.ClassifyAddr(primary))
		result.Store(common.KeyRouting, common.Inconclusive(msg))
		return nil
	}

	provider := rn.routingProvider()
	info, err := provider.LookupRouting(ctx, primary)
	if err != nil {
		result.Store(common.KeyRouting, common.Inconclusive(fmt.Sprintf("routing lookup: %v", err)))
		return nil
	}

	report := routing.NetworkReport{
		RoutingInfo: info,
	}

	// Dual-stack: when the other family resolves publicly, look it up too.
	var other netip.Addr
	if primary.Is4() && v6.IsValid() && routing.IsPublicRoutable(v6) {
		other = v6
	} else if primary.Is6() && v4.IsValid() && routing.IsPublicRoutable(v4) {
		other = v4
	}
	if other.IsValid() {
		alt, aerr := provider.LookupRouting(ctx, other)
		if aerr == nil && alt.ASN.ASN != 0 {
			if alt.ASN.ASN != info.ASN.ASN {
				report.Also = &alt
				as4, as6 := info.ASN.ASN, alt.ASN.ASN
				if primary.Is6() {
					as4, as6 = alt.ASN.ASN, info.ASN.ASN
				}
				report.Note = fmt.Sprintf("v4 AS%d vs v6 AS%d", as4, as6)
			} else {
				report.Note = fmt.Sprintf("v4+v6 AS%d", info.ASN.ASN)
			}
		}
	}

	result.StoreNetwork(report)

	content := formatRoutingSummary(info)
	if report.Also != nil {
		content += "; also " + formatRoutingSummary(*report.Also)
	} else if report.Note != "" && strings.HasPrefix(report.Note, "v4+v6") {
		content += "; " + report.Note
	}

	switch info.RPKI.Status {
	case routing.RPKIInvalid:
		result.Store(common.KeyRouting, common.Warn(content))
	case routing.RPKIUnknown:
		result.Store(common.KeyRouting, common.Inconclusive(content))
	default:
		result.Store(common.KeyRouting, common.OK(content))
	}
	return nil
}

func formatRoutingSummary(info routing.RoutingInfo) string {
	var parts []string
	if info.ASN.ASN != 0 {
		parts = append(parts, fmt.Sprintf("AS%d", info.ASN.ASN))
	}
	if info.ASN.Name != "" {
		parts = append(parts, info.ASN.Name)
	}
	if info.ASN.Prefix.IsValid() {
		parts = append(parts, "prefix="+info.ASN.Prefix.String())
	}
	if info.RPKI.Status != "" {
		rpki := "RPKI=" + info.RPKI.Status
		if info.RPKI.Detail != "" {
			rpki += "(" + info.RPKI.Detail + ")"
		}
		parts = append(parts, rpki)
	}
	parts = append(parts, "ip="+info.IP.String())
	return strings.Join(parts, "; ")
}

func (rn *Runner) testRDAPCheck(ctx context.Context, address common.Address, timeout time.Duration, result *common.Result) error {
	ctx, cancel := withCheckTimeout(ctx, timeout)
	defer cancel()

	client := rn.rdapProvider()
	host := address.String()

	var (
		info routing.RDAPInfo
		err  error
	)
	if ip, perr := netip.ParseAddr(host); perr == nil {
		info, err = client.LookupIP(ctx, ip)
	} else {
		info, err = client.LookupDomain(ctx, host)
		if err != nil {
			// Fall back to IP RDAP for the resolved address.
			if ip, rerr := primaryPublicIP(ctx, host); rerr == nil {
				info, err = client.LookupIP(ctx, ip)
			}
		}
	}
	if err != nil {
		result.Store(common.KeyRDAP, common.Inconclusive(fmt.Sprintf("rdap: %v", err)))
		return nil
	}

	var parts []string
	if info.Name != "" {
		parts = append(parts, info.Name)
	}
	if info.Organization != "" && info.Organization != info.Name {
		parts = append(parts, "org="+info.Organization)
	}
	if info.RIR != "" {
		parts = append(parts, "rir="+info.RIR)
	}
	if info.CIDR != "" {
		parts = append(parts, "cidr="+info.CIDR)
	} else if info.StartAddress != "" && info.EndAddress != "" {
		parts = append(parts, "range="+info.StartAddress+"-"+info.EndAddress)
	}
	if info.Country != "" {
		parts = append(parts, "cc="+info.Country)
	}
	if info.AbuseContact != "" {
		parts = append(parts, "abuse="+info.AbuseContact)
	}
	if len(parts) == 0 {
		parts = append(parts, "rdap ok")
	}
	result.Store(common.KeyRDAP, common.OK(strings.Join(parts, "; ")))
	return nil
}

// primaryPublicIP resolves host and returns a preferred public address (v4 then v6).
func primaryPublicIP(ctx context.Context, host string) (netip.Addr, error) {
	v4, v6, err := publicIPsByFamily(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	if v4.IsValid() {
		return v4, nil
	}
	if v6.IsValid() {
		return v6, nil
	}
	return netip.Addr{}, fmt.Errorf("no addresses for %s", host)
}

// publicIPsByFamily returns the first public routable IPv4 and IPv6 (may be invalid).
func publicIPsByFamily(ctx context.Context, host string) (v4, v6 netip.Addr, err error) {
	if ip, perr := netip.ParseAddr(host); perr == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			return ip, netip.Addr{}, nil
		}
		return netip.Addr{}, ip, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	var first netip.Addr
	for _, a := range addrs {
		addr, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if !first.IsValid() {
			first = addr
		}
		if !routing.IsPublicRoutable(addr) {
			continue
		}
		if addr.Is4() && !v4.IsValid() {
			v4 = addr
		}
		if addr.Is6() && !v6.IsValid() {
			v6 = addr
		}
	}
	if v4.IsValid() || v6.IsValid() {
		return v4, v6, nil
	}
	if first.IsValid() {
		if first.Is4() {
			return first, netip.Addr{}, nil
		}
		return netip.Addr{}, first, nil
	}
	return netip.Addr{}, netip.Addr{}, fmt.Errorf("no addresses for %s", host)
}
