package lookup

import (
	"strings"
	"testing"
)

func TestFormatCAA(t *testing.T) {
	data := []byte{0, 5}
	data = append(data, []byte("issue")...)
	data = append(data, []byte("letsencrypt.org")...)
	got, ok := formatCAA(data)
	if !ok || !strings.Contains(got, "issue") || !strings.Contains(got, "letsencrypt.org") {
		t.Fatalf("%q", got)
	}
}

func TestFormatDS(t *testing.T) {
	data := []byte{0x12, 0x34, 13, 2, 1, 2, 3, 4}
	got, ok := formatDS(data)
	if !ok || !strings.Contains(got, "tag=4660") || !strings.Contains(got, "alg=13") {
		t.Fatalf("%q", got)
	}
}

func TestFindSPFAndDMARC(t *testing.T) {
	if got := findSPF([]string{"hello", "v=spf1 include:_spf.google.com -all"}); got == "" {
		t.Fatal("spf")
	}
	if softFailSPF("v=spf1 -all") {
		t.Fatal("hard fail should not warn")
	}
	if !softFailSPF("v=spf1 ~all") {
		t.Fatal("soft fail should warn")
	}
	if pol := dmarcPolicy("v=DMARC1; p=reject; rua=mailto:a@b.c"); pol != "reject" {
		t.Fatalf("%q", pol)
	}
	if isDKIMRecord(`v=DKIM1; p=`) {
		t.Fatal("empty p= should not count")
	}
	if !isDKIMRecord(`v=DKIM1; k=rsa; p=MIGfMA0GCSq`) {
		t.Fatal("expected valid dkim")
	}
}

func TestClipList(t *testing.T) {
	got := clipList([]string{"a", "b", "c", "d"}, 2)
	if len(got) != 3 || got[2] != "…(+2)" {
		t.Fatalf("%v", got)
	}
}
