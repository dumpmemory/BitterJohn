package anytls

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
)

func TestDialerRelaysTCPThroughServer(t *testing.T) {
	echoAddr, closeEcho := startEchoServer(t)
	defer closeEcho()

	srv, err := New(testTLSContext(t), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if err := srv.AddPassages([]server.Passage{{
		Passage: model.Passage{
			In: model.In{Argument: model.Argument{
				Protocol: "anytls",
				Password: "secret-password",
			}},
		},
	}}); err != nil {
		t.Fatal(err)
	}

	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = srv.(*Server).serveListener(lt)
	}()

	dialer, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: lt.Addr().String(),
		Password:     "secret-password",
		IsClient:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.(*Dialer).Close()

	conn, err := dialer.DialContext(context.Background(), "tcp", echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if got, want := string(buf), "pong"; got != want {
		t.Fatalf("echo response = %q, want %q", got, want)
	}
}

func TestDialerRelaysUDPThroughServer(t *testing.T) {
	udpAddr, closeUDP := startUDPEchoServer(t)
	defer closeUDP()

	srv, err := New(testTLSContext(t), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if err := srv.AddPassages([]server.Passage{{
		Passage: model.Passage{
			In: model.In{Argument: model.Argument{
				Protocol: "anytls",
				Password: "secret-password",
			}},
		},
	}}); err != nil {
		t.Fatal(err)
	}

	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = srv.(*Server).serveListener(lt)
	}()

	dialer, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: lt.Addr().String(),
		Password:     "secret-password",
		IsClient:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.(*Dialer).Close()

	conn, err := dialer.DialContext(context.Background(), "udp", udpAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	packetConn := conn.(netproxy.PacketConn)
	if _, err := packetConn.WriteTo([]byte("ping"), udpAddr.String()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, addr, err := packetConn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(buf[:n]) != "pong" {
		t.Fatalf("udp response = %q, want %q", string(buf[:n]), "pong")
	}
	if addr != udpAddr {
		t.Fatalf("udp response addr = %v, want %v", addr, udpAddr)
	}
}

func TestDialCmdMsgPing(t *testing.T) {
	srv, err := New(testTLSContext(t), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if err := srv.AddPassages([]server.Passage{{Manager: true}}); err != nil {
		t.Fatal(err)
	}
	managerPassword := srv.Passages()[0].In.Password

	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = srv.(*Server).serveListener(lt)
	}()

	dialer, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: lt.Addr().String(),
		Password:     managerPassword,
		IsClient:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.(*Dialer).Close()

	conn, err := dialer.(*Dialer).DialCmdMsg(protocol.MetadataCmdPing)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[:4], 4)
	copy(req[4:], "ping")
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, req[:4]); err != nil {
		t.Fatal(err)
	}
	if n := binary.BigEndian.Uint32(req[:4]); n == 0 {
		t.Fatal("empty ping response")
	} else if n > 4096 {
		t.Fatalf("ping response too large: %d", n)
	}
}

func startUDPEchoServer(t *testing.T) (netip.AddrPort, func()) {
	t.Helper()

	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				select {
				case <-quit:
					return
				default:
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			if string(buf[:n]) == "ping" {
				_, _ = conn.WriteToUDPAddrPort([]byte("pong"), addr)
			}
		}
	}()

	return conn.LocalAddr().(*net.UDPAddr).AddrPort(), func() {
		close(quit)
		_ = conn.Close()
		<-done
	}
}

func startEchoServer(t *testing.T) (addr string, closeFn func()) {
	t.Helper()

	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := lt.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 4)
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				if string(buf) == "ping" {
					_, _ = conn.Write([]byte("pong"))
				}
			}(conn)
		}
	}()

	return lt.Addr().String(), func() {
		_ = lt.Close()
		<-done
	}
}
