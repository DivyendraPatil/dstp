//go:build integration

package lookup

import (
	"context"
	"testing"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

func TestLookup(t *testing.T) {
	var result common.Result
	err := Host(context.Background(), common.Address("example.com"), "8.8.8.8", 5*time.Second, &result)
	if err != nil {
		t.Skipf("live DNS unavailable: %v", err)
	}
	if result.SystemDNS.Content == "" {
		t.Fatal("empty System DNS content")
	}
}

func TestRecords(t *testing.T) {
	var result common.Result
	err := Records(context.Background(), common.Address("example.com"), "", false, "", "", 5*time.Second, &result)
	if err != nil {
		t.Skipf("live DNS unavailable: %v", err)
	}
	if result.Records.Content == "" && result.Records.Status != common.StatusWarning {
		t.Fatal("expected records content")
	}
}
