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
	err := Host(context.Background(), common.Address("jvns.ca"), "8.8.8.8", 5*time.Second, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.SystemDNS.Error != nil {
		t.Fatal(result.SystemDNS.Error)
	}
	if result.SystemDNS.Content == "" {
		t.Fatal("System DNS resolution failed")
	}
}

func TestRecords(t *testing.T) {
	var result common.Result
	err := Records(context.Background(), common.Address("example.com"), 5*time.Second, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.Records.Content == "" {
		t.Fatal("expected records content")
	}
}
