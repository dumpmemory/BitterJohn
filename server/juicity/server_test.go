package juicity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
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
