//go:build integration || fallback

package ping

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

func TestPingFallback(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("ICMP is often restricted in CI")
	}
	out, err := runPingFallback(context.Background(), common.Address("8.8.8.8"), 2, 5*time.Second)
	if err != nil {
		t.Fatal(err.Error())
	}
	if out.Content == "" {
		t.Fatal("empty ping fallback content")
	}
}
