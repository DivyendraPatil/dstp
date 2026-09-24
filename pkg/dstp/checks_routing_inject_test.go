package dstp

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
	"github.com/DivyendraPatil/dstp/pkg/routing"
)

type fakeRouting struct {
	info routing.RoutingInfo
	err  error
}

func (f fakeRouting) LookupRouting(ctx context.Context, ip netip.Addr) (routing.RoutingInfo, error) {
	if f.err != nil {
		return routing.RoutingInfo{IP: ip}, f.err
	}
	out := f.info
	out.IP = ip
	return out, nil
}

func TestRoutingUsesInjectedProvider(t *testing.T) {
	ip := netip.MustParseAddr("1.2.3.4")
	rn := &Runner{
		RoutingProvider: fakeRouting{
			info: routing.RoutingInfo{
				ASN:    routing.ASNInfo{ASN: 64496, Name: "TEST-AS", Prefix: netip.MustParsePrefix("1.2.3.0/24")},
				RPKI:   routing.RPKIResult{Status: routing.RPKIValid},
				Source: "fake",
			},
		},
	}
	result := &common.Result{}
	err := rn.testRouting(context.Background(), common.Address(ip.String()), 2*time.Second, result)
	if err != nil {
		t.Fatal(err)
	}
	part := result.Get(common.KeyRouting)
	if part.Status != common.StatusOK {
		t.Fatalf("%+v", part)
	}
	if !strings.Contains(part.Content, "AS64496") || !strings.Contains(part.Content, "TEST-AS") {
		t.Fatalf("%q", part.Content)
	}
	netObj, ok := result.Network.(routing.NetworkReport)
	if !ok {
		t.Fatalf("network type %T", result.Network)
	}
	if netObj.ASN.ASN != 64496 {
		t.Fatalf("%+v", netObj)
	}
}

func TestHTTPAppHintCloudflare(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		Header:     http.Header{"Cf-Ray": []string{"abc"}, "Server": []string{"cloudflare"}},
	}
	if got := httpAppHint(resp); !strings.Contains(got, "edge challenge") {
		t.Fatalf("%q", got)
	}
	resp2 := &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}}
	if got := httpAppHint(resp2); got != " (application error)" {
		t.Fatalf("%q", got)
	}
}
