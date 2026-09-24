// Package routing defines models and provider interfaces for destination
// routing intelligence (ASN, BGP prefix, RPKI, RDAP, PeeringDB).
//
// Default providers (implemented in later packages):
//   - RIPE Stat — target ASN / prefix / RPKI (HTTPS JSON, no API key)
//   - Team Cymru DNS — traceroute hop ASN enrichment
//
// Enrichment failures must map to StatusUnknown (or skipped), never to
// RPKI invalid. Special-use addresses must not be sent to public APIs.
package routing
