package dstp

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
	"github.com/DivyendraPatil/dstp/pkg/routing"
)

func TestPrimaryPublicIPLiteral(t *testing.T) {
	ip, err := primaryPublicIP(context.Background(), "8.8.8.8")
	if err != nil || ip.String() != "8.8.8.8" {
		t.Fatalf("%v %v", ip, err)
	}
}

func TestFormatRoutingSpecialUse(t *testing.T) {
	result := &common.Result{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rn := &Runner{}
	err := rn.testRouting(ctx, common.Address("10.0.0.1"), 2*time.Second, result)
	if err != nil {
		t.Fatal(err)
	}
	part := result.Get(common.KeyRouting)
	if part.Status != common.StatusInconclusive {
		t.Fatalf("%+v", part)
	}
	if !strings.Contains(part.Content, string(routing.AddrPrivate)) {
		t.Fatalf("%q", part.Content)
	}
}

func TestParseAddrUnmap(t *testing.T) {
	addr := netip.MustParseAddr("::ffff:1.2.3.4").Unmap()
	if !addr.Is4() || addr.String() != "1.2.3.4" {
		t.Fatal(addr)
	}
}
