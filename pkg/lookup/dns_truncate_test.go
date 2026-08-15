package lookup

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/DivyendraPatil/dstp/pkg/common"
)

// startTruncatingDNS answers UDP with TC=1 and serves the real answer on TCP.
func startTruncatingDNS(t *testing.T, ip net.IP) (addr string, cleanup func(), tcpHits *int32) {
	t.Helper()
	v4 := ip.To4()
	if v4 == nil {
		t.Fatal("need IPv4")
	}
	var hits int32

	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpLn, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}

	serveAnswer := func(id uint16, q dnsmessage.Question, truncated bool) []byte {
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID:            id,
			Response:      true,
			Authoritative: true,
			Truncated:     truncated,
		})
		_ = builder.StartQuestions()
		_ = builder.Question(q)
		if !truncated {
			_ = builder.StartAnswers()
			var a [4]byte
			copy(a[:], v4)
			_ = builder.AResource(dnsmessage.ResourceHeader{
				Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60,
			}, dnsmessage.AResource{A: a})
		}
		msg, _ := builder.Finish()
		return msg
	}

	udpDone := make(chan struct{})
	go func() {
		defer close(udpDone)
		buf := make([]byte, 512)
		for {
			n, remote, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			hdr, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			_, _ = udp.WriteTo(serveAnswer(hdr.ID, q, true), remote)
		}
	}()

	tcpDone := make(chan struct{})
	go func() {
		defer close(tcpDone)
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&hits, 1)
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				lenBuf := make([]byte, 2)
				if _, err := ioReadFull(conn, lenBuf); err != nil {
					return
				}
				l := int(lenBuf[0])<<8 | int(lenBuf[1])
				if l <= 0 || l > 4096 {
					return
				}
				msg := make([]byte, l)
				if _, err := ioReadFull(conn, msg); err != nil {
					return
				}
				var p dnsmessage.Parser
				hdr, err := p.Start(msg)
				if err != nil {
					return
				}
				q, err := p.Question()
				if err != nil {
					return
				}
				ans := serveAnswer(hdr.ID, q, false)
				out := []byte{byte(len(ans) >> 8), byte(len(ans))}
				out = append(out, ans...)
				_, _ = conn.Write(out)
			}(c)
		}
	}()

	return udp.LocalAddr().String(), func() {
		_ = udp.Close()
		_ = tcpLn.Close()
		<-udpDone
		<-tcpDone
	}, &hits
}

func ioReadFull(r net.Conn, buf []byte) (int, error) {
	return io.ReadFull(r, buf)
}

func TestHostTruncatedUDPFallsBackToTCP(t *testing.T) {
	srv, cleanup, hits := startTruncatingDNS(t, net.IPv4(8, 8, 4, 4))
	defer cleanup()

	var result common.Result
	err := Host(context.Background(), common.Address("trunc.test"), srv, 3*time.Second, &result)
	if err != nil {
		t.Fatal(err)
	}
	if result.SystemDNS.Status != common.StatusOK {
		t.Fatalf("%+v", result.SystemDNS)
	}
	if atomic.LoadInt32(hits) < 1 {
		t.Fatal("expected TCP fallback hit")
	}
	if !containsIPStr(result.SystemDNS.Content, "8.8.4.4") {
		t.Fatalf("content=%q", result.SystemDNS.Content)
	}
}

func containsIPStr(s, ip string) bool {
	return len(s) > 0 && (s == ip || stringIndex(s, ip) >= 0)
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
