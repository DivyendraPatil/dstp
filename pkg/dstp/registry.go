package dstp

import (
	"strings"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

// CheckID is the canonical identifier for a connectivity check.
type CheckID string

const (
	CheckPing          CheckID = "ping"
	CheckDNS           CheckID = "dns"
	CheckConfiguredDNS CheckID = "configured_dns"
	CheckRecords       CheckID = "records"
	CheckMail          CheckID = "mail"
	CheckDNSSEC        CheckID = "dnssec"
	CheckTCP           CheckID = "tcp"
	CheckUDP           CheckID = "udp"
	CheckTLS           CheckID = "tls"
	CheckHTTP          CheckID = "http"
	CheckHTTPS         CheckID = "https"
	CheckHTTP3         CheckID = "http3"
	CheckCDN           CheckID = "cdn"
	CheckTraceroute    CheckID = "traceroute"
	CheckWhois         CheckID = "whois"
	CheckMTU           CheckID = "mtu"
)

// CheckMeta describes a registered check.
type CheckMeta struct {
	ID      CheckID
	Label   string
	JSONKey string
	Aliases []string
	Extra   bool // only when --extra
}

// Registry is the canonical ordered list of checks.
var Registry = []CheckMeta{
	{ID: CheckPing, Label: "Ping", JSONKey: "ping"},
	{ID: CheckDNS, Label: "DNS", JSONKey: "dns"},
	{ID: CheckConfiguredDNS, Label: "ConfiguredDNS", JSONKey: "configured_dns", Aliases: []string{"system_dns"}},
	{ID: CheckRecords, Label: "Records", JSONKey: "records"},
	{ID: CheckMail, Label: "Mail", JSONKey: "mail"},
	{ID: CheckDNSSEC, Label: "DNSSEC", JSONKey: "dnssec"},
	{ID: CheckTCP, Label: "TCP", JSONKey: "tcp"},
	{ID: CheckUDP, Label: "UDP", JSONKey: "udp"},
	{ID: CheckTLS, Label: "TLS", JSONKey: "tls"},
	{ID: CheckHTTP, Label: "HTTP", JSONKey: "http"},
	{ID: CheckHTTPS, Label: "HTTPS", JSONKey: "https"},
	{ID: CheckHTTP3, Label: "HTTP3", JSONKey: "http3"},
	{ID: CheckCDN, Label: "CDN", JSONKey: "cdn"},
	{ID: CheckTraceroute, Label: "Traceroute", JSONKey: "traceroute", Extra: true},
	{ID: CheckWhois, Label: "Whois", JSONKey: "whois", Extra: true},
	{ID: CheckMTU, Label: "MTU", JSONKey: "mtu", Extra: true},
}

// CheckIDs returns canonical check IDs for CLI completions and validation.
func CheckIDs() []string {
	out := make([]string, 0, len(Registry))
	for _, m := range Registry {
		out = append(out, string(m.ID))
	}
	return out
}

func lookupMeta(id string) (CheckMeta, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, m := range Registry {
		if string(m.ID) == id {
			return m, true
		}
		for _, a := range m.Aliases {
			if a == id {
				return m, true
			}
		}
	}
	return CheckMeta{}, false
}

func setByID(r *common.Result, id CheckID, part common.ResultPart) {
	switch id {
	case CheckPing:
		r.Store(&r.Ping, part)
	case CheckDNS:
		r.Store(&r.DNS, part)
	case CheckConfiguredDNS:
		r.Store(&r.SystemDNS, part)
	case CheckRecords:
		r.Store(&r.Records, part)
	case CheckMail:
		r.Store(&r.Mail, part)
	case CheckDNSSEC:
		r.Store(&r.DNSSEC, part)
	case CheckTCP:
		r.Store(&r.TCP, part)
	case CheckUDP:
		r.Store(&r.UDP, part)
	case CheckTLS:
		r.Store(&r.TLS, part)
	case CheckHTTP:
		r.Store(&r.HTTP, part)
	case CheckHTTPS:
		r.Store(&r.HTTPS, part)
	case CheckHTTP3:
		r.Store(&r.HTTP3, part)
	case CheckCDN:
		r.Store(&r.CDN, part)
	case CheckTraceroute:
		r.Store(&r.Traceroute, part)
	case CheckWhois:
		r.Store(&r.Whois, part)
	case CheckMTU:
		r.Store(&r.MTU, part)
	}
}

func getByID(r *common.Result, id CheckID) common.ResultPart {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	switch id {
	case CheckPing:
		return r.Ping
	case CheckDNS:
		return r.DNS
	case CheckConfiguredDNS:
		return r.SystemDNS
	case CheckRecords:
		return r.Records
	case CheckMail:
		return r.Mail
	case CheckDNSSEC:
		return r.DNSSEC
	case CheckTCP:
		return r.TCP
	case CheckUDP:
		return r.UDP
	case CheckTLS:
		return r.TLS
	case CheckHTTP:
		return r.HTTP
	case CheckHTTPS:
		return r.HTTPS
	case CheckHTTP3:
		return r.HTTP3
	case CheckCDN:
		return r.CDN
	case CheckTraceroute:
		return r.Traceroute
	case CheckWhois:
		return r.Whois
	case CheckMTU:
		return r.MTU
	default:
		return common.ResultPart{}
	}
}
