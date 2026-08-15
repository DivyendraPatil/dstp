package lookup

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

func TestLookupDoHJSON(t *testing.T) {
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
	err := Default(context.Background(), common.Address("example.com"), 2*time.Second, true, ts.URL, "", DoHFormatJSON, &result)
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

func TestLookupDoHRFC8484(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var qwire []byte
		switch r.Method {
		case http.MethodPost:
			var err error
			qwire, err = io.ReadAll(io.LimitReader(r.Body, 1<<16))
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
		case http.MethodGet:
			dns := r.URL.Query().Get("dns")
			if dns == "" {
				http.Error(w, "missing dns", 400)
				return
			}
			raw, err := base64.RawURLEncoding.DecodeString(dns)
			if err != nil {
				raw, err = base64.URLEncoding.DecodeString(dns)
			}
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			qwire = raw
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		var p dnsmessage.Parser
		hdr, err := p.Start(qwire)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		q, err := p.Question()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID:                 hdr.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   hdr.RecursionDesired,
			RecursionAvailable: true,
		})
		_ = builder.StartQuestions()
		_ = builder.Question(q)
		_ = builder.StartAnswers()
		switch q.Type {
		case dnsmessage.TypeA:
			_ = builder.AResource(dnsmessage.ResourceHeader{
				Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60,
			}, dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}})
		case dnsmessage.TypeAAAA:
			var aaaa [16]byte
			copy(aaaa[:], net.ParseIP("2001:db8::1").To16())
			_ = builder.AAAAResource(dnsmessage.ResourceHeader{
				Name: q.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60,
			}, dnsmessage.AAAAResource{AAAA: aaaa})
		}
		msg, err := builder.Finish()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(msg)
	}))
	defer ts.Close()

	var result common.Result
	err := Default(context.Background(), common.Address("example.com"), 2*time.Second, true, ts.URL, "", DoHFormatRFC8484, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.DNS.Status != common.StatusOK {
		t.Fatalf("%+v", result.DNS)
	}
	if !strings.Contains(result.DNS.Content, "1.2.3.4") || !strings.Contains(result.DNS.Content, "2001:db8::1") {
		t.Fatalf("content=%q", result.DNS.Content)
	}
}

func TestJoinIPs(t *testing.T) {
	if joinIPs(nil) != "" {
		t.Fatal("expected empty")
	}
}
