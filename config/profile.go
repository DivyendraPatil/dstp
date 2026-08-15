package config

import "strings"

// Named check profiles (high-signal presets). Default is "web".
const (
	ProfileWeb  = "web"
	ProfileMail = "mail"
	ProfileDNS  = "dns"
	ProfileAPI  = "api"
	ProfileFull = "full"
)

// profileSkips lists checks omitted by each profile.
// full has an empty skip set.
var profileSkips = map[string][]string{
	// Sites/CDN edges: skip DNS:53 noise and mail/dnssec depth.
	ProfileWeb: {"udp", "mail", "dnssec"},
	// Inbox / domain auth focus.
	ProfileMail: {"ping", "tcp", "udp", "tls", "http", "https", "http3", "cdn"},
	// Resolver / authority focus (keeps smarter UDP → NS).
	ProfileDNS: {"ping", "tcp", "tls", "http", "https", "http3", "cdn", "mail"},
	// Service endpoint focus.
	ProfileAPI:  {"udp", "mail", "dnssec", "http", "ping"},
	ProfileFull: {},
}

// NormalizeProfile returns a canonical profile name or "" if unknown.
func NormalizeProfile(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "", ProfileWeb:
		return ProfileWeb
	case ProfileMail, ProfileDNS, ProfileAPI, ProfileFull:
		return p
	default:
		return ""
	}
}

// ProfileSkipList returns the skip set for a normalized profile.
func ProfileSkipList(profile string) []string {
	profile = NormalizeProfile(profile)
	if profile == "" {
		profile = ProfileWeb
	}
	out := append([]string(nil), profileSkips[profile]...)
	return out
}

// mergeSkipUnique appends extras onto base without duplicates (order preserved).
func mergeSkipUnique(base, extras []string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(list []string) {
		for _, s := range list {
			s = strings.ToLower(strings.TrimSpace(s))
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	add(base)
	add(extras)
	return out
}
