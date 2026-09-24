package routing

import (
	"net/netip"
	"time"
)

// RPKI status values for structured output.
const (
	RPKIValid    = "valid"
	RPKIInvalid  = "invalid"
	RPKINotFound = "not_found" // no covering ROA
	RPKIUnknown  = "unknown"   // lookup failed / unavailable
)

// ASNInfo is origin ASN metadata for a single IP.
type ASNInfo struct {
	IP           netip.Addr   `json:"ip"`
	ASN          uint32       `json:"asn,omitempty"`
	Name         string       `json:"name,omitempty"`
	Organization string       `json:"organization,omitempty"`
	Prefix       netip.Prefix `json:"prefix,omitempty"`
	RIR          string       `json:"rir,omitempty"`
	Country      string       `json:"country,omitempty"` // registry CC, not geolocation
	Source       string       `json:"source,omitempty"`
}

// ROA describes a matching Route Origin Authorization when available.
type ROA struct {
	ASN       uint32       `json:"asn"`
	Prefix    netip.Prefix `json:"prefix"`
	MaxLength int          `json:"max_length,omitempty"`
}

// RPKIResult is origin validation for a prefix + ASN pair.
type RPKIResult struct {
	Status      string       `json:"status"`           // valid | invalid | not_found | unknown
	Detail      string       `json:"detail,omitempty"` // e.g. invalid_asn, invalid_length
	Prefix      netip.Prefix `json:"prefix,omitempty"`
	OriginASN   uint32       `json:"origin_asn,omitempty"`
	MatchedROA  *ROA         `json:"matched_roa,omitempty"`
	Source      string       `json:"source,omitempty"`
	Description string       `json:"description,omitempty"`
}

// RoutingInfo aggregates ASN/prefix/RPKI for one IP (target diagnosis).
type RoutingInfo struct {
	IP     netip.Addr `json:"ip"`
	ASN    ASNInfo    `json:"asn"`
	RPKI   RPKIResult `json:"rpki"`
	Source string     `json:"source,omitempty"`
}

// RDAPInfo is normalized registration data (IP or domain).
type RDAPInfo struct {
	Kind         string     `json:"kind"` // ip | domain
	Handle       string     `json:"handle,omitempty"`
	Name         string     `json:"name,omitempty"`
	Organization string     `json:"organization,omitempty"`
	Country      string     `json:"country,omitempty"`
	RIR          string     `json:"rir,omitempty"`
	CIDR         string     `json:"cidr,omitempty"`
	StartAddress string     `json:"start_address,omitempty"`
	EndAddress   string     `json:"end_address,omitempty"`
	Registered   *time.Time `json:"registered,omitempty"`
	LastChanged  *time.Time `json:"last_changed,omitempty"`
	AbuseContact string     `json:"abuse_contact,omitempty"`
	Source       string     `json:"source,omitempty"`
}

// PeeringInfo is optional PeeringDB enrichment for an ASN.
type PeeringInfo struct {
	ASN           uint32 `json:"asn"`
	Name          string `json:"name,omitempty"`
	Website       string `json:"website,omitempty"`
	TrafficLevel  string `json:"traffic_level,omitempty"`
	Policy        string `json:"policy,omitempty"`
	IXCount       int    `json:"ix_count,omitempty"`
	FacilityCount int    `json:"facility_count,omitempty"`
	Source        string `json:"source,omitempty"`
}

// HopASN annotates one traceroute hop for observed-path rendering.
type HopASN struct {
	Hop     int        `json:"hop"`
	Address netip.Addr `json:"address,omitempty"`
	ASN     uint32     `json:"asn,omitempty"`
	Name    string     `json:"name,omitempty"`
	Private bool       `json:"private,omitempty"`
	Unknown bool       `json:"unknown,omitempty"`
}

// ObservedASNPath is a collapsed traceroute ASN sequence (not BGP AS_PATH).
type ObservedASNPath struct {
	ASNs   []uint32 `json:"asns"`
	Labels []string `json:"labels,omitempty"` // e.g. "AS7922", "private"
	Source string   `json:"source,omitempty"`
	Note   string   `json:"note,omitempty"` // always clarify observed vs BGP
}
