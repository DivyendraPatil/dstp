package lookup

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

// startHermeticDNS serves a single A record over UDP for tests.
func startHermeticDNS(t *testing.T, ip net.IP) (addr string, cleanup func()) {
	t.Helper()
	v4 := ip.To4()
	if v4 == nil {
		t.Fatal("need IPv4")
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, remote, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var parser dnsmessage.Parser
			hdr, err := parser.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := parser.Question()
			if err != nil {
				continue
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
				ID:            hdr.ID,
				Response:      true,
				Authoritative: true,
			})
			_ = builder.StartQuestions()
			_ = builder.Question(q)
			_ = builder.StartAnswers()
			if q.Type == dnsmessage.TypeA {
				var a [4]byte
				copy(a[:], v4)
				_ = builder.AResource(dnsmessage.ResourceHeader{
					Name:  q.Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				}, dnsmessage.AResource{A: a})
			}
			msg, err := builder.Finish()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(msg, remote)
		}
	}()
	return pc.LocalAddr().String(), func() {
		_ = pc.Close()
		<-done
	}
}

func TestHostHermeticDNS(t *testing.T) {
	srv, cleanup := startHermeticDNS(t, net.IPv4(9, 9, 9, 9))
	defer cleanup()

	var result common.Result
	err := Host(context.Background(), common.Address("example.test"), srv, 2*time.Second, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.SystemDNS.Status != common.StatusOK {
		t.Fatalf("%+v", result.SystemDNS)
	}
	if !strings.Contains(result.SystemDNS.Content, "9.9.9.9") {
		t.Fatalf("content=%q", result.SystemDNS.Content)
	}
}
