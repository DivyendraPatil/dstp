package routing

import (
	"context"
	"net/netip"
)

// ASNProvider maps a public IP to origin ASN / prefix metadata.
type ASNProvider interface {
	LookupIP(ctx context.Context, ip netip.Addr) (ASNInfo, error)
}

// RPKIProvider validates a prefix + origin ASN pair.
type RPKIProvider interface {
	Validate(ctx context.Context, prefix netip.Prefix, asn uint32) (RPKIResult, error)
}

// RoutingProvider returns combined routing intelligence for an IP.
// Implementations should skip special-use addresses without calling remote APIs.
type RoutingProvider interface {
	LookupIP(ctx context.Context, ip netip.Addr) (RoutingInfo, error)
}

// RDAPProvider looks up IP or domain registration data.
type RDAPProvider interface {
	LookupIP(ctx context.Context, ip netip.Addr) (RDAPInfo, error)
	LookupDomain(ctx context.Context, domain string) (RDAPInfo, error)
}

// PeeringProvider fetches optional PeeringDB enrichment for an ASN.
type PeeringProvider interface {
	LookupASN(ctx context.Context, asn uint32) (PeeringInfo, error)
}

// MapRIPERPKIStatus maps RIPEstat rpki-validation status strings to our
// canonical statuses. Lookup/transport failures should use RPKIUnknown
// separately — never treat them as invalid.
func MapRIPERPKIStatus(ripeStatus string) (status, detail string) {
	switch ripeStatus {
	case "valid":
		return RPKIValid, ""
	case "invalid_asn":
		return RPKIInvalid, "invalid_asn"
	case "invalid_length":
		return RPKIInvalid, "invalid_length"
	case "unknown":
		// RIPE "unknown" means no covering ROA.
		return RPKINotFound, ""
	default:
		if ripeStatus == "" {
			return RPKIUnknown, ""
		}
		return RPKIUnknown, ripeStatus
	}
}
