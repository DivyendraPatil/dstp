package common

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestResultOutputJSONIncludesErrors(t *testing.T) {
	r := &Result{}
	r.Store(KeyPing, OK("14ms"))
	r.Store(KeyTLS, Fail(errors.New("connection refused")))

	out := r.Output("json")

	var got map[string]map[string]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json.Unmarshal: %v\noutput: %s", err, out)
	}

	if got["ping"]["status"] != "ok" || got["ping"]["content"] != "14ms" {
		t.Fatalf("ping = %#v", got["ping"])
	}
	if got["tls"]["status"] != "error" || got["tls"]["error"] != "connection refused" {
		t.Fatalf("tls = %#v", got["tls"])
	}
}

func TestResultOutputPlaintextIncludesErrors(t *testing.T) {
	SetNoColor(true)
	r := &Result{}
	r.Store(KeyHTTPS, Fail(errors.New("timeout")))
	r.Store(KeyDNS, OK("IPv4=1.2.3.4"))

	out := r.Output("plaintext")

	if !strings.Contains(out, "timeout") {
		t.Fatalf("plaintext output missing error text:\n%s", out)
	}
	if !strings.Contains(out, "IPv4=1.2.3.4") {
		t.Fatalf("plaintext output missing success content:\n%s", out)
	}
}

func TestResultFailed(t *testing.T) {
	r := &Result{}
	r.Store(KeyPing, OK("1ms"))
	r.Store(KeyTLS, Fail(errors.New("x")))
	if !r.Failed() {
		t.Fatal("expected Failed()")
	}
	r2 := &Result{}
	r2.Store(KeyPing, OK("1ms"))
	r2.Store(KeyTLS, Skipped())
	if r2.Failed() {
		t.Fatal("skipped should not fail")
	}
}

func TestSkippedOmittedFromPlaintext(t *testing.T) {
	SetNoColor(true)
	r := &Result{}
	r.Store(KeyPing, Skipped())
	r.Store(KeyTLS, OK("valid until 2099-01-01"))
	r.Store(KeyUDP, NotApplicable("n/a: cdn"))
	out := r.Output("plaintext")
	if strings.Contains(out, "Ping:") || strings.Contains(out, "UDP:") {
		t.Fatalf("skipped should be omitted:\n%s", out)
	}
	if !strings.Contains(out, "TLS:") {
		t.Fatalf("expected TLS:\n%s", out)
	}
	js := r.Output("json")
	if !strings.Contains(js, `"ping"`) || !strings.Contains(js, "skipped") {
		t.Fatalf("json should keep skipped: %s", js)
	}
}

func TestJSONNetworkBlockAdditive(t *testing.T) {
	r := &Result{}
	r.Store(KeyRouting, OK("AS13335"))
	r.StoreNetwork(map[string]any{"asn": map[string]any{"asn": 13335}, "rpki": map[string]any{"status": "valid"}})
	out := r.Output("json")
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["routing"]; !ok {
		t.Fatalf("missing routing key: %s", out)
	}
	netObj, ok := got["network"].(map[string]any)
	if !ok {
		t.Fatalf("missing network object: %s", out)
	}
	if netObj["asn"] == nil {
		t.Fatalf("%v", netObj)
	}
}

func TestKnownSkipNames(t *testing.T) {
	known := KnownSkipNames()
	if _, ok := known[KeyPing]; !ok {
		t.Fatal("missing ping")
	}
	if _, ok := known["system_dns"]; !ok {
		t.Fatal("missing system_dns alias")
	}
	if len(known) < len(PartOrder) {
		t.Fatalf("known=%d parts=%d", len(known), len(PartOrder))
	}
}
