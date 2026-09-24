package dstp

import (
	"strings"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

// CheckID is the canonical identifier for a connectivity check.
type CheckID string

const (
	CheckPing          CheckID = common.KeyPing
	CheckDNS           CheckID = common.KeyDNS
	CheckConfiguredDNS CheckID = common.KeyConfiguredDNS
	CheckRecords       CheckID = common.KeyRecords
	CheckMail          CheckID = common.KeyMail
	CheckDNSSEC        CheckID = common.KeyDNSSEC
	CheckRouting       CheckID = common.KeyRouting
	CheckRDAP          CheckID = common.KeyRDAP
	CheckTCP           CheckID = common.KeyTCP
	CheckUDP           CheckID = common.KeyUDP
	CheckTLS           CheckID = common.KeyTLS
	CheckHTTP          CheckID = common.KeyHTTP
	CheckHTTPS         CheckID = common.KeyHTTPS
	CheckHTTP3         CheckID = common.KeyHTTP3
	CheckCDN           CheckID = common.KeyCDN
	CheckTraceroute    CheckID = common.KeyTraceroute
	CheckWhois         CheckID = common.KeyWhois
	CheckMTU           CheckID = common.KeyMTU
)

// CheckMeta describes a registered check.
type CheckMeta struct {
	ID      CheckID
	Label   string
	JSONKey string
	Aliases []string
	Extra   bool // only when --extra
}

// Registry is the canonical ordered list of checks (labels/Extra beyond common.PartOrder).
var Registry = []CheckMeta{
	{ID: CheckPing, Label: "Ping", JSONKey: common.KeyPing},
	{ID: CheckDNS, Label: "DNS", JSONKey: common.KeyDNS},
	{ID: CheckConfiguredDNS, Label: "ConfiguredDNS", JSONKey: common.KeyConfiguredDNS, Aliases: []string{"system_dns"}},
	{ID: CheckRecords, Label: "Records", JSONKey: common.KeyRecords},
	{ID: CheckMail, Label: "Mail", JSONKey: common.KeyMail},
	{ID: CheckDNSSEC, Label: "DNSSEC", JSONKey: common.KeyDNSSEC},
	{ID: CheckRouting, Label: "Routing", JSONKey: common.KeyRouting},
	{ID: CheckRDAP, Label: "RDAP", JSONKey: common.KeyRDAP},
	{ID: CheckTCP, Label: "TCP", JSONKey: common.KeyTCP},
	{ID: CheckUDP, Label: "UDP", JSONKey: common.KeyUDP},
	{ID: CheckTLS, Label: "TLS", JSONKey: common.KeyTLS},
	{ID: CheckHTTP, Label: "HTTP", JSONKey: common.KeyHTTP},
	{ID: CheckHTTPS, Label: "HTTPS", JSONKey: common.KeyHTTPS},
	{ID: CheckHTTP3, Label: "HTTP3", JSONKey: common.KeyHTTP3},
	{ID: CheckCDN, Label: "CDN", JSONKey: common.KeyCDN},
	{ID: CheckTraceroute, Label: "Traceroute", JSONKey: common.KeyTraceroute, Extra: true},
	{ID: CheckWhois, Label: "Whois", JSONKey: common.KeyWhois, Extra: true},
	{ID: CheckMTU, Label: "MTU", JSONKey: common.KeyMTU, Extra: true},
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
	r.Store(string(id), part)
}

func getByID(r *common.Result, id CheckID) common.ResultPart {
	return r.Get(string(id))
}
