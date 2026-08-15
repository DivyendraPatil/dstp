package lookup

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

// commonDKIMSelectors are tried when no selector is configured.
var commonDKIMSelectors = []string{
	"google", "selector1", "selector2", "default", "k1", "s1", "s2",
	"dkim", "mail", "smtp", "cm", "zendesk1", "zendesk2",
}

// MailAuth inspects SPF, DMARC, BIMI, and common DKIM selectors.
func MailAuth(ctx context.Context, addr common.Address, customDNS string, timeout time.Duration, result *common.Result) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host := strings.TrimSuffix(addr.String(), ".")
	if net.ParseIP(host) != nil {
		result.Store(&result.Mail, common.NotApplicable("mail auth not applicable for literal IP"))
		return nil
	}

	r := resolverFor(customDNS, timeout)
	var (
		mu    sync.Mutex
		parts []string
		warns int
	)
	add := func(s string, warn bool) {
		mu.Lock()
		defer mu.Unlock()
		parts = append(parts, s)
		if warn {
			warns++
		}
	}

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		txt, err := r.LookupTXT(ctx, host)
		if err != nil {
			add("SPF=missing (TXT lookup failed)", true)
			return
		}
		spf := findSPF(txt)
		if spf == "" {
			add("SPF=missing", true)
			return
		}
		add("SPF="+clipTXT(spf, 90), softFailSPF(spf))
	}()

	go func() {
		defer wg.Done()
		name := "_dmarc." + host
		txt, err := r.LookupTXT(ctx, name)
		if err != nil || len(txt) == 0 {
			add("DMARC=missing", true)
			return
		}
		rec := joinTXT(txt)
		if !strings.Contains(strings.ToLower(rec), "v=dmarc1") {
			add("DMARC=missing", true)
			return
		}
		pol := dmarcPolicy(rec)
		warn := pol == "" || pol == "none"
		msg := "DMARC=" + clipTXT(rec, 90)
		if pol != "" {
			msg = fmt.Sprintf("DMARC=p=%s (%s)", pol, clipTXT(rec, 70))
		}
		add(msg, warn)
	}()

	go func() {
		defer wg.Done()
		name := "default._bimi." + host
		txt, err := r.LookupTXT(ctx, name)
		if err != nil || len(txt) == 0 {
			return
		}
		rec := joinTXT(txt)
		if strings.Contains(strings.ToLower(rec), "v=bimi1") {
			add("BIMI="+clipTXT(rec, 70), false)
		}
		// Absent BIMI is normal — omit to keep output tight.
	}()

	go func() {
		defer wg.Done()
		var found []string
		var fMu sync.Mutex
		var swg sync.WaitGroup
		for _, sel := range commonDKIMSelectors {
			sel := sel
			swg.Add(1)
			go func() {
				defer swg.Done()
				name := sel + "._domainkey." + host
				txt, err := r.LookupTXT(ctx, name)
				if err != nil || len(txt) == 0 {
					return
				}
				rec := joinTXT(txt)
				if !isDKIMRecord(rec) {
					return
				}
				fMu.Lock()
				found = append(found, sel)
				fMu.Unlock()
			}()
		}
		swg.Wait()
		if len(found) == 0 {
			add("DKIM=none", true)
			return
		}
		sortStrings(found)
		add("DKIM=selectors:"+strings.Join(found, ","), false)
	}()

	wg.Wait()
	if len(parts) == 0 {
		err := fmt.Errorf("mail auth: no data")
		result.Store(&result.Mail, common.Fail(err))
		return err
	}
	sortStrings(parts)
	content := strings.Join(parts, "; ")
	if warns > 0 {
		result.Store(&result.Mail, common.Warn(content))
		return nil
	}
	result.Store(&result.Mail, common.OK(content))
	return nil
}

func findSPF(txts []string) string {
	for _, t := range txts {
		s := strings.TrimSpace(t)
		low := strings.ToLower(s)
		if strings.HasPrefix(low, "v=spf1") {
			return s
		}
	}
	return ""
}

func softFailSPF(spf string) bool {
	low := strings.ToLower(spf)
	if strings.Contains(low, " -all") || strings.HasSuffix(low, "-all") {
		return false
	}
	return true
}

// isDKIMRecord requires v=DKIM1 and a non-empty public key (p=...).
func isDKIMRecord(rec string) bool {
	low := strings.ToLower(strings.TrimSpace(rec))
	if !strings.Contains(low, "v=dkim1") {
		return false
	}
	for _, part := range strings.Split(rec, ";") {
		part = strings.TrimSpace(part)
		if len(part) >= 2 && (part[0] == 'p' || part[0] == 'P') && part[1] == '=' {
			key := strings.TrimSpace(part[2:])
			return key != "" && key != "\"\""
		}
	}
	return false
}

func dmarcPolicy(rec string) string {
	for _, part := range strings.Split(rec, ";") {
		part = strings.TrimSpace(part)
		low := strings.ToLower(part)
		if strings.HasPrefix(low, "p=") {
			return strings.TrimSpace(part[2:])
		}
	}
	return ""
}

func joinTXT(txts []string) string {
	return strings.Join(txts, "")
}

func clipTXT(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func sortStrings(in []string) {
	for i := 1; i < len(in); i++ {
		j := i
		for j > 0 && in[j] < in[j-1] {
			in[j], in[j-1] = in[j-1], in[j]
			j--
		}
	}
}
