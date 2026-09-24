package ripestat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestLookupIP(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/data/network-info/data.json", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sourceapp") != "dstp" {
			t.Errorf("sourceapp=%q", r.URL.Query().Get("sourceapp"))
		}
		if r.URL.Query().Get("resource") != "1.1.1.1" {
			t.Errorf("resource=%q", r.URL.Query().Get("resource"))
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":{"asns":["13335"],"prefix":"1.1.1.0/24"}}`))
	})
	mux.HandleFunc("/data/as-overview/data.json", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "13335" {
			t.Errorf("asn resource=%q", r.URL.Query().Get("resource"))
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":{"holder":"CLOUDFLARENET - Cloudflare, Inc.","block":{"desc":"Assigned by ARIN","name":"IANA"}}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := New()
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := c.LookupIP(ctx, netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.ASN != 13335 {
		t.Fatalf("ASN=%d", info.ASN)
	}
	if info.Prefix.String() != "1.1.1.0/24" {
		t.Fatalf("prefix=%s", info.Prefix)
	}
	if !strings.Contains(info.Name, "Cloudflare") {
		t.Fatalf("name=%q", info.Name)
	}
	if info.RIR != "ARIN" {
		t.Fatalf("rir=%q", info.RIR)
	}
	if info.Source != "ripestat" {
		t.Fatalf("source=%q", info.Source)
	}
}

func TestLookupIPSpecialUseSkipped(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(500)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	_, err := c.LookupIP(context.Background(), netip.MustParseAddr("10.0.0.1"))
	if err == nil {
		t.Fatal("expected error")
	}
	if called {
		t.Fatal("must not call remote API for private IP")
	}
}

func TestLookupIPNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		_, _ = w.Write([]byte("nope"))
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	_, err := c.LookupIP(context.Background(), netip.MustParseAddr("8.8.8.8"))
	if err == nil {
		t.Fatal("expected error")
	}
}
