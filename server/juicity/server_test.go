package juicity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	outprotocol "github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	bjserver "github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
)

func TestCloseStopsServe(t *testing.T) {
	s := newTestServer(t)
	addr := freeUDPAddr(t)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Serve(addr)
	}()

	if !eventually(time.Second, func() bool {
		return s.getListener() != nil
	}) {
		t.Fatal("listener was not assigned to the server")
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case <-errCh:
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

func TestLastAliveAccessIsSafeForConcurrentReadersAndWriters(t *testing.T) {
	s := &Server{}
	ready := make(chan struct{})
	done := make(chan struct{})

	for i := 0; i < 8; i++ {
		go func(offset int) {
			<-ready
			for j := 0; j < 1000; j++ {
				s.setLastAlive(time.Unix(0, int64(offset*1000+j)))
			}
			done <- struct{}{}
		}(i)
		go func() {
			<-ready
			for j := 0; j < 1000; j++ {
				_ = s.getLastAlive()
			}
			done <- struct{}{}
		}()
	}

	close(ready)
	for i := 0; i < 16; i++ {
		<-done
	}
}

func TestOutboundJuicityDialerRelaysTCPThroughServer(t *testing.T) {
	echoAddr, closeEcho := startJuicityTCPEchoServer(t)
	defer closeEcho()

	s, addr, closeServer := startJuicityServerWithPassage(t)
	defer closeServer()

	dialer := newOutboundJuicityDialer(t, addr, testJuicityUser, testJuicityPassword)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", echoAddr)
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
		t.Fatalf("tcp relay response = %q, want %q", got, want)
	}
	if len(s.Passages()) != 1 {
		t.Fatalf("server passages changed during relay: %d", len(s.Passages()))
	}
}

func TestOutboundJuicityDialerRelaysUDPThroughServer(t *testing.T) {
	udpAddr, closeUDP := startJuicityUDPEchoServer(t)
	defer closeUDP()

	_, addr, closeServer := startJuicityServerWithPassage(t)
	defer closeServer()

	dialer := newOutboundJuicityDialer(t, addr, testJuicityUser, testJuicityPassword)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "udp", udpAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	packetConn := conn.(netproxy.PacketConn)
	if _, err := packetConn.WriteTo([]byte("ping"), udpAddr.String()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	n, addrPort, err := packetConn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(buf[:n]) != "pong" {
		t.Fatalf("udp relay response = %q, want %q", string(buf[:n]), "pong")
	}
	if addrPort.String() != udpAddr.String() {
		t.Fatalf("udp response addr = %v, want %v", addrPort, udpAddr)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	cert, key := testCertificate(t)
	s, err := New(&Options{
		Certificate:       cert,
		PrivateKey:        key,
		CongestionControl: "bbr",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return s
}

const (
	testJuicityUser     = "28446de9-2a7e-4fab-827b-6df93e46f945"
	testJuicityPassword = "juicity-password"
)

func startJuicityServerWithPassage(t *testing.T) (*Server, string, func()) {
	t.Helper()
	s := newTestServer(t)
	if err := s.AddPassages([]bjserver.Passage{{
		Passage: model.Passage{In: model.In{Argument: model.Argument{
			Protocol: "juicity",
			Username: testJuicityUser,
			Password: testJuicityPassword,
		}}},
	}}); err != nil {
		t.Fatal(err)
	}
	addr := freeUDPAddr(t)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Serve(addr)
	}()
	if !eventually(time.Second, func() bool {
		return s.getListener() != nil
	}) {
		t.Fatal("listener was not assigned to the server")
	}
	return s, addr, func() {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("juicity server did not stop")
		}
	}
}

func newOutboundJuicityDialer(t *testing.T, proxyAddr, user, password string) netproxy.Dialer {
	t.Helper()
	direct.InitDirectDialers("")
	dialer, err := bjserver.NewDialer("juicity", direct.FullconeDirect, &outprotocol.Header{
		ProxyAddress: proxyAddr,
		User:         user,
		Password:     password,
		Feature1:     "bbr",
		TlsConfig: &tls.Config{
			NextProtos:         []string{"h3"},
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		},
		IsClient: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return dialer
}

func startJuicityTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := lt.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var buf [4]byte
		if _, err := io.ReadFull(conn, buf[:]); err != nil {
			return
		}
		if string(buf[:]) == "ping" {
			_, _ = conn.Write([]byte("pong"))
		}
	}()
	return lt.Addr().String(), func() {
		_ = lt.Close()
		<-done
	}
}

func startJuicityUDPEchoServer(t *testing.T) (net.Addr, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) == "ping" {
			_, _ = conn.WriteTo([]byte("pong"), addr)
		}
	}()
	return conn.LocalAddr(), func() {
		_ = conn.Close()
		<-done
	}
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}

func eventually(timeout time.Duration, f func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if f() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return f()
}

func testCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
