package lookup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

func TestLookupDoH(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-json")
		qtype := r.URL.Query().Get("type")
		resp := dohResponse{Status: 0}
		if qtype == "A" || qtype == "1" {
			resp.Answer = []struct {
				Data string `json:"data"`
				Type int    `json:"type"`
			}{{Data: "1.2.3.4", Type: 1}}
		}
		if qtype == "AAAA" || qtype == "28" {
			resp.Answer = []struct {
				Data string `json:"data"`
				Type int    `json:"type"`
			}{{Data: "2001:db8::1", Type: 28}}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	var result common.Result
	err := Default(context.Background(), common.Address("example.com"), 2*time.Second, true, ts.URL, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.DNS.Status != "ok" {
		t.Fatalf("%+v", result.DNS)
	}
	if got := result.DNS.Content; got == "" {
		t.Fatal("empty doh content")
	}
}

func TestJoinIPs(t *testing.T) {
	if joinIPs(nil) != "" {
		t.Fatal("expected empty")
	}
}
