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
	"github.com/DivyendraPatil/dstp/pkg/routing/rdap"
	"github.com/DivyendraPatil/dstp/pkg/routing/ripestat"
)

func testRouting(ctx context.Context, address common.Address, timeout time.Duration, result *common.Result) error {
	ctx, cancel := withCheckTimeout(ctx, timeout)
	defer cancel()

	ip, err := primaryPublicIP(ctx, address.String())
	if err != nil {
		result.Store(&result.Routing, common.Inconclusive(fmt.Sprintf("resolve: %v", err)))
		return nil
	}
	if !routing.IsPublicRoutable(ip) {
		msg := fmt.Sprintf("%s is %s; ASN/RPKI not queried", ip, routing.ClassifyAddr(ip))
		result.Store(&result.Routing, common.Inconclusive(msg))
		return nil
	}

	info, err := ripestat.New().LookupRouting(ctx, ip)
	if err != nil {
		// Enrichment failure → inconclusive/unknown, not a hard target error.
		result.Store(&result.Routing, common.Inconclusive(fmt.Sprintf("routing lookup: %v", err)))
		return nil
	}
	result.StoreNetwork(info)

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
	parts = append(parts, "ip="+ip.String())
	content := strings.Join(parts, "; ")

	switch info.RPKI.Status {
	case routing.RPKIInvalid:
		result.Store(&result.Routing, common.Warn(content))
	case routing.RPKIUnknown:
		result.Store(&result.Routing, common.Inconclusive(content))
	default:
		result.Store(&result.Routing, common.OK(content))
	}
	return nil
}

func testRDAPCheck(ctx context.Context, address common.Address, timeout time.Duration, result *common.Result) error {
	ctx, cancel := withCheckTimeout(ctx, timeout)
	defer cancel()

	client := rdap.New()
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
		result.Store(&result.RDAP, common.Inconclusive(fmt.Sprintf("rdap: %v", err)))
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
	result.Store(&result.RDAP, common.OK(strings.Join(parts, "; ")))
	return nil
}

// primaryPublicIP resolves host and returns a preferred public address (v4 then v6).
func primaryPublicIP(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return netip.Addr{}, err
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
		if routing.IsPublicRoutable(addr) && addr.Is4() {
			return addr, nil
		}
	}
	for _, a := range addrs {
		addr, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		if routing.IsPublicRoutable(addr) {
			return addr, nil
		}
	}
	if first.IsValid() {
		return first, nil
	}
	return netip.Addr{}, fmt.Errorf("no addresses for %s", host)
}
