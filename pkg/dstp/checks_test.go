package dstp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ycd/dstp/config"
	"github.com/ycd/dstp/pkg/common"
)

func TestRunAllTestsSkipAll(t *testing.T) {
	err := RunAllTests(context.Background(), config.Config{
		Addr:      "example.com",
		Output:    "json",
		Quiet:     true,
		Timeout:   1,
		PingCount: 1,
		Skip:      []string{"ping", "dns", "configured_dns", "records", "tcp", "tls", "https"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTCPLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var result common.Result
	if err := testTCP(context.Background(), "127.0.0.1", port, 2*time.Second, &result); err != nil {
		t.Fatal(err)
	}
	if result.TCP.Status != "ok" {
		t.Fatalf("%+v", result.TCP)
	}
}

func TestHTTPSLocal(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	host, port, err := net.SplitHostPort(ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	var result common.Result
	_ = testHTTPS(context.Background(), common.Address(host), port, 2*time.Second, "GET", false, &result)
	if result.HTTPS.Status == "" {
		t.Fatal("expected https result")
	}
}

func TestTLSLocalCert(t *testing.T) {
	ln, certPEM, keyPEM := localTLSListener(t)
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			cert, err := tls.X509KeyPair(certPEM, keyPEM)
			if err != nil {
				_ = c.Close()
				return
			}
			tlsConn := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
			_ = tlsConn.Handshake()
			_ = tlsConn.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	var result common.Result
	_ = testTLS(context.Background(), common.Address("127.0.0.1"), port, 2*time.Second, &result)
	if result.TLS.Content == "" && result.TLS.Error == nil {
		t.Fatal("expected tls result")
	}
}

func localTLSListener(t *testing.T) (net.Listener, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln, certPEM, keyPEM
}

func TestHTTPSURL(t *testing.T) {
	if got := httpsURL("example.com", ""); got != "https://example.com" {
		t.Fatalf("got %q", got)
	}
	if got := httpsURL("example.com", "8443"); got != "https://example.com:8443" {
		t.Fatalf("got %q", got)
	}
	if got := httpsURL("2001:db8::1", "443"); got != "https://[2001:db8::1]:443" {
		t.Fatalf("got %q", got)
	}
}

func TestTLSVersionHelper(t *testing.T) {
	if tlsVersion(tls.VersionTLS13) != "TLS1.3" {
		t.Fatal(tlsVersion(tls.VersionTLS13))
	}
	if got := tlsVersion(0x9999); got == "" {
		t.Fatal(got)
	}
}

