package common

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestResultOutputJSONIncludesErrors(t *testing.T) {
	r := &Result{
		Ping: OK("14ms"),
		TLS:  Fail(errors.New("connection refused")),
	}

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
	r := &Result{
		HTTPS: Fail(errors.New("timeout")),
		DNS:   OK("IPv4=1.2.3.4"),
	}

	out := r.Output("plaintext")

	if !strings.Contains(out, "timeout") {
		t.Fatalf("plaintext output missing error text:\n%s", out)
	}
	if !strings.Contains(out, "IPv4=1.2.3.4") {
		t.Fatalf("plaintext output missing success content:\n%s", out)
	}
}

func TestResultFailed(t *testing.T) {
	r := &Result{Ping: OK("1ms"), TLS: Fail(errors.New("x"))}
	if !r.Failed() {
		t.Fatal("expected Failed()")
	}
	r2 := &Result{Ping: OK("1ms"), TLS: Skipped()}
	if r2.Failed() {
		t.Fatal("skipped should not fail")
	}
}
