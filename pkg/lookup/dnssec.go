package lookup

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

// DNS types not exported as named constants in older dnsmessage snapshots.
const (
	typeDS     dnsmessage.Type = 43
	typeDNSKEY dnsmessage.Type = 48
	typeCAA    dnsmessage.Type = 257
)

// DNSSEC reports CAA presence plus DS/DNSKEY and Authentic Data (AD) when available.
func DNSSEC(ctx context.Context, addr common.Address, customDNS string, timeout time.Duration, result *common.Result) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	host := strings.TrimSuffix(addr.String(), ".")
	if net.ParseIP(host) != nil {
		result.Store(&result.DNSSEC, common.NotApplicable("CAA/DNSSEC not applicable for literal IP"))
		return nil
	}

	server := customDNS
	if server == "" {
		server = "1.1.1.1:53" // validating public resolver for AD bit
	} else {
		server = formatDNSServer(server)
	}

	apex := dnsApex(ctx, host, customDNS, timeout)

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
	wg.Add(3)

	go func() {
		defer wg.Done()
		recs, ad, err := queryDNSRecords(ctx, server, host, typeCAA, timeout)
		if err != nil {
			add("CAA=lookup failed", true)
			return
		}
		if len(recs) == 0 {
			add("CAA=none", true)
			return
		}
		msg := "CAA=" + strings.Join(clipList(recs, 4), ",")
		if ad {
			msg += " (AD)"
		}
		add(msg, false)
	}()

	go func() {
		defer wg.Done()
		recs, ad, err := queryDNSRecords(ctx, server, apex, typeDS, timeout)
		if err != nil {
			add("DS=lookup failed", true)
			return
		}
		if len(recs) == 0 {
			add("DS=none (unsigned or not in parent)", true)
			return
		}
		msg := fmt.Sprintf("DS=%d", len(recs))
		if ad {
			msg += " (AD)"
		}
		add(msg+": "+strings.Join(clipList(recs, 2), ","), false)
	}()

	go func() {
		defer wg.Done()
		recs, ad, err := queryDNSRecords(ctx, server, apex, typeDNSKEY, timeout)
		if err != nil {
			add("DNSKEY=lookup failed", true)
			return
		}
		if len(recs) == 0 {
			add("DNSKEY=none", true)
			return
		}
		msg := fmt.Sprintf("DNSKEY=%d", len(recs))
		if ad {
			msg += " (AD)"
		}
		add(msg, false)
	}()

	wg.Wait()
	sortStrings(parts)
	content := strings.Join(parts, "; ")
	if warns > 0 && warns == len(parts) {
		result.Store(&result.DNSSEC, common.Warn(content))
		return nil
	}
	if warns > 0 {
		result.Store(&result.DNSSEC, common.Warn(content))
		return nil
	}
	result.Store(&result.DNSSEC, common.OK(content))
	return nil
}

func dnsApex(ctx context.Context, host, customDNS string, timeout time.Duration) string {
	r := resolverFor(customDNS, timeout)
	labels := strings.Split(host, ".")
	for i := 0; i < len(labels)-1; i++ {
		candidate := strings.Join(labels[i:], ".")
		ns, err := r.LookupNS(ctx, candidate)
		if err == nil && len(ns) > 0 {
			return candidate
		}
	}
	return host
}

func queryDNSRecords(ctx context.Context, server, name string, qtype dnsmessage.Type, timeout time.Duration) (answers []string, ad bool, err error) {
	payload, err := buildDNSQueryDNSSEC(name, qtype)
	if err != nil {
		return nil, false, err
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = conn.Close() }()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(payload); err != nil {
		return nil, false, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	return parseTypedAnswers(buf[:n], qtype)
}

func buildDNSQueryDNSSEC(host string, qtype dnsmessage.Type) ([]byte, error) {
	name, err := dnsmessage.NewName(host + ".")
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			RecursionDesired: true,
			AuthenticData:    true, // request AD when supported
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
		Additionals: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: 4096,    // UDP payload size
				TTL:   1 << 15, // DO bit (DNSSEC OK)
			},
			Body: &dnsmessage.OPTResource{},
		}},
	}
	return msg.Pack()
}

func parseTypedAnswers(body []byte, want dnsmessage.Type) ([]string, bool, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(body)
	if err != nil {
		return nil, false, err
	}
	ad := hdr.AuthenticData
	if hdr.RCode != dnsmessage.RCodeSuccess && hdr.RCode != dnsmessage.RCodeNameError {
		return nil, ad, fmt.Errorf("DNS rcode %v", hdr.RCode)
	}
	for {
		if _, err := p.Question(); err != nil {
			break
		}
	}
	var out []string
	for {
		rh, err := p.AnswerHeader()
		if err != nil {
			break
		}
		if rh.Type != want {
			_ = p.SkipAnswer()
			continue
		}
		switch want {
		case typeCAA:
			ur, err := p.UnknownResource()
			if err != nil {
				return nil, ad, err
			}
			if s, ok := formatCAA(ur.Data); ok {
				out = append(out, s)
			}
		case typeDS:
			ur, err := p.UnknownResource()
			if err != nil {
				return nil, ad, err
			}
			if s, ok := formatDS(ur.Data); ok {
				out = append(out, s)
			}
		case typeDNSKEY:
			ur, err := p.UnknownResource()
			if err != nil {
				return nil, ad, err
			}
			if s, ok := formatDNSKEY(ur.Data); ok {
				out = append(out, s)
			}
		default:
			_ = p.SkipAnswer()
		}
	}
	return out, ad, nil
}

func formatCAA(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	flags := data[0]
	tagLen := int(data[1])
	if 2+tagLen > len(data) {
		return "", false
	}
	tag := string(data[2 : 2+tagLen])
	val := string(data[2+tagLen:])
	return fmt.Sprintf("%d %s %q", flags, tag, val), true
}

func formatDS(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	keyTag := binary.BigEndian.Uint16(data[0:2])
	alg := data[2]
	digestType := data[3]
	return fmt.Sprintf("tag=%d alg=%d digest=%d", keyTag, alg, digestType), true
}

func formatDNSKEY(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	flags := binary.BigEndian.Uint16(data[0:2])
	proto := data[2]
	alg := data[3]
	role := "ZSK"
	if flags&256 != 0 { // SEP
		role = "KSK"
	}
	return fmt.Sprintf("%s alg=%d proto=%d", role, alg, proto), true
}

func clipList(in []string, max int) []string {
	if max <= 0 || len(in) <= max {
		return in
	}
	out := append([]string{}, in[:max]...)
	out = append(out, fmt.Sprintf("…(+%d)", len(in)-max))
	return out
}
