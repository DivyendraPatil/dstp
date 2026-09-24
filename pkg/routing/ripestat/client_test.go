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

func TestValidateRPKI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/data/rpki-validation/data.json", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "13335" || r.URL.Query().Get("prefix") != "1.1.1.0/24" {
			t.Fatalf("q=%v", r.URL.Query())
		}
		_, _ = w.Write([]byte(`{"status":"ok","data":{"resource":"13335","prefix":"1.1.1.0/24","status":"valid","validating_roas":[{"origin":"13335","prefix":"1.1.1.0/24","validity":"valid","max_length":24}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := New()
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	res, err := c.Validate(context.Background(), netip.MustParsePrefix("1.1.1.0/24"), 13335)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "valid" {
		t.Fatalf("status=%q", res.Status)
	}
	if res.MatchedROA == nil || res.MatchedROA.ASN != 13335 || res.MatchedROA.MaxLength != 24 {
		t.Fatalf("roa=%+v", res.MatchedROA)
	}
}

func TestValidateRPKIInvalidASN(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/data/rpki-validation/data.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","data":{"status":"invalid_asn","prefix":"8.8.8.0/24","validating_roas":[{"origin":"15169","prefix":"8.8.8.0/24","validity":"invalid_asn","max_length":24}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := New()
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	res, err := c.Validate(context.Background(), netip.MustParsePrefix("8.8.8.0/24"), 13335)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "invalid" || res.Detail != "invalid_asn" {
		t.Fatalf("%+v", res)
	}
}

func TestValidateRPKINotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/data/rpki-validation/data.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","data":{"status":"unknown","prefix":"203.0.113.0/24","validating_roas":[]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := New()
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	res, err := c.Validate(context.Background(), netip.MustParsePrefix("203.0.113.0/24"), 64500)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "not_found" {
		t.Fatalf("status=%q (RIPE unknown must map to not_found)", res.Status)
	}
}

func TestValidateRPKITransportUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
	}))
	t.Cleanup(srv.Close)

	c := New()
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	res, err := c.Validate(context.Background(), netip.MustParsePrefix("1.1.1.0/24"), 13335)
	if err == nil {
		t.Fatal("expected error")
	}
	if res.Status != "unknown" {
		t.Fatalf("transport failure must be unknown, got %q", res.Status)
	}
}

func TestLookupRouting(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/data/network-info/data.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","data":{"asns":["13335"],"prefix":"1.1.1.0/24"}}`))
	})
	mux.HandleFunc("/data/as-overview/data.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","data":{"holder":"CLOUDFLARENET","block":{"desc":"Assigned by ARIN"}}}`))
	})
	mux.HandleFunc("/data/rpki-validation/data.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","data":{"status":"valid","prefix":"1.1.1.0/24","validating_roas":[{"origin":"13335","prefix":"1.1.1.0/24","validity":"valid","max_length":24}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := New()
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	info, err := c.LookupRouting(context.Background(), netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.ASN.ASN != 13335 || info.RPKI.Status != "valid" {
		t.Fatalf("%+v", info)
	}
}

func TestLookupRoutingRPKIFailureIsUnknown(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/data/network-info/data.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","data":{"asns":["13335"],"prefix":"1.1.1.0/24"}}`))
	})
	mux.HandleFunc("/data/as-overview/data.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","data":{"holder":"CF","block":{}}}`))
	})
	mux.HandleFunc("/data/rpki-validation/data.json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := New()
	c.BaseURL = srv.URL
	c.HTTPClient = srv.Client()

	info, err := c.LookupRouting(context.Background(), netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatalf("RPKI failure must not fail LookupRouting: %v", err)
	}
	if info.ASN.ASN != 13335 {
		t.Fatalf("asn=%d", info.ASN.ASN)
	}
	if info.RPKI.Status != "unknown" {
		t.Fatalf("rpki=%q", info.RPKI.Status)
	}
}
