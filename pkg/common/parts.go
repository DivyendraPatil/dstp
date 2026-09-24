package common

// JSON / check-ID keys for Result parts. Keep in sync with dstp.Registry.
const (
	KeyPing          = "ping"
	KeyDNS           = "dns"
	KeyConfiguredDNS = "configured_dns"
	KeyRecords       = "records"
	KeyMail          = "mail"
	KeyDNSSEC        = "dnssec"
	KeyRouting       = "routing"
	KeyRDAP          = "rdap"
	KeyTCP           = "tcp"
	KeyUDP           = "udp"
	KeyTLS           = "tls"
	KeyHTTP          = "http"
	KeyHTTPS         = "https"
	KeyHTTP3         = "http3"
	KeyCDN           = "cdn"
	KeyTraceroute    = "traceroute"
	KeyWhois         = "whois"
	KeyMTU           = "mtu"
)

// PartSpec describes one ordered Result slot (plaintext label + JSON key).
type PartSpec struct {
	Name string
	Key  string
}

// PartOrder drives plaintext/JSON output order and is the canonical part list.
var PartOrder = []PartSpec{
	{"Ping", KeyPing},
	{"DNS", KeyDNS},
	{"ConfiguredDNS", KeyConfiguredDNS},
	{"Records", KeyRecords},
	{"Mail", KeyMail},
	{"DNSSEC", KeyDNSSEC},
	{"Routing", KeyRouting},
	{"RDAP", KeyRDAP},
	{"TCP", KeyTCP},
	{"UDP", KeyUDP},
	{"TLS", KeyTLS},
	{"HTTP", KeyHTTP},
	{"HTTPS", KeyHTTPS},
	{"HTTP3", KeyHTTP3},
	{"CDN", KeyCDN},
	{"Traceroute", KeyTraceroute},
	{"Whois", KeyWhois},
	{"MTU", KeyMTU},
}

// SkipAliases are alternate --skip names accepted for a PartOrder key.
var SkipAliases = map[string]string{
	"system_dns": KeyConfiguredDNS,
}

// KnownSkipNames returns valid --skip values (canonical keys + aliases).
func KnownSkipNames() map[string]struct{} {
	out := make(map[string]struct{}, len(PartOrder)+len(SkipAliases))
	for _, p := range PartOrder {
		out[p.Key] = struct{}{}
	}
	for a := range SkipAliases {
		out[a] = struct{}{}
	}
	return out
}
