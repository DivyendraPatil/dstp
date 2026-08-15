//go:build integration || fallback

package ping

import (
	"context"
	"testing"
	"time"

	"github.com/ycd/dstp/pkg/common"
)

func TestPingFallback(t *testing.T) {
	out, err := runPingFallback(context.Background(), common.Address("8.8.8.8"), 2, 5*time.Second)
	if err != nil {
		t.Fatal(err.Error())
	}
	if out.Content == "" {
		t.Fatal("empty ping fallback content")
	}
}
