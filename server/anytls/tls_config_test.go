package anytls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol/direct"
)

func TestNewRequiresExplicitTLSConfig(t *testing.T) {
	_, err := New(context.Background(), direct.SymmetricDirect)
	if !errors.Is(err, ErrTLSConfigRequired) {
		t.Fatalf("New error = %v, want %v", err, ErrTLSConfigRequired)
	}
}

func TestNewRejectsTLSConfigWithoutCertificateProvider(t *testing.T) {
	ctx := WithTLSConfig(context.Background(), &tls.Config{MinVersion: tls.VersionTLS12})
	_, err := New(ctx, direct.SymmetricDirect)
	if !errors.Is(err, ErrTLSConfigRequired) {
		t.Fatalf("New error = %v, want %v", err, ErrTLSConfigRequired)
	}
}

func TestNewAcceptsExplicitTLSConfig(t *testing.T) {
	tlsConfig := testTLSConfig(t)
	ctx := WithTLSConfig(context.Background(), tlsConfig)
	srvIface, err := New(ctx, direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer srvIface.Close()

	srv := srvIface.(*Server)
	if srv.tlsConfig == nil {
		t.Fatal("server tlsConfig is nil")
	}
	if srv.tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("server MinVersion = %v, want TLS 1.2", srv.tlsConfig.MinVersion)
	}
}

func TestAutocertTLSResourcesProvideDynamicCertificates(t *testing.T) {
	resources, err := newAutocertTLSResources("edge.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resources.tlsConfig == nil {
		t.Fatal("tlsConfig is nil")
	}
	if resources.tlsConfig.GetCertificate == nil {
		t.Fatal("GetCertificate is nil")
	}
	if len(resources.tlsConfig.Certificates) != 0 {
		t.Fatalf("static certificates = %d, want 0", len(resources.tlsConfig.Certificates))
	}
	if resources.tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v, want TLS 1.2", resources.tlsConfig.MinVersion)
	}
	if resources.httpServer == nil {
		t.Fatal("ACME HTTP server is nil")
	}
	if resources.httpServer.Addr != ":80" {
		t.Fatalf("ACME HTTP server addr = %q, want %q", resources.httpServer.Addr, ":80")
	}
}

func TestListenReturnsAutocertBindError(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()

	srvIface, err := New(testTLSContext(t), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer srvIface.Close()
	srv := srvIface.(*Server)
	srv.autocertServer = &http.Server{Addr: blocker.Addr().String(), Handler: http.NewServeMux()}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Listen("127.0.0.1:0")
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Listen returned nil, want ACME bind error")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Listen did not return ACME bind error")
	}
}

func TestStartAutocertServerClosesWithServer(t *testing.T) {
	srvIface, err := New(testTLSContext(t), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	srv := srvIface.(*Server)
	srv.autocertServer = &http.Server{Addr: "127.0.0.1:0", Handler: http.NewServeMux()}

	if err := srv.startAutocertServer(); err != nil {
		t.Fatal(err)
	}
	if srv.autocertListener == nil {
		t.Fatal("autocert listener is nil")
	}
	addr := srv.autocertListener.Addr().String()
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("autocert listener still accepts connections after Close")
	}
}

func TestRenewingCertificateGetterDoesNotReRegisterAfterSlowFailure(t *testing.T) {
	expected := errors.New("acme failed")
	var renews atomic.Int64
	getCertificate := renewingCertificateGetter("edge.example.com", func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		time.Sleep(20 * time.Millisecond)
		return nil, expected
	}, time.Millisecond, func() {
		renews.Add(1)
	})

	cert, err := getCertificate(&tls.ClientHelloInfo{})
	if !errors.Is(err, expected) {
		t.Fatalf("GetCertificate error = %v, want %v", err, expected)
	}
	if cert != nil {
		t.Fatal("certificate is not nil after failure")
	}
	if got := renews.Load(); got != 0 {
		t.Fatalf("renew callback calls = %d, want 0", got)
	}
}

func TestRenewingCertificateGetterReRegistersAfterSlowSuccess(t *testing.T) {
	var renews atomic.Int64
	expected := &tls.Certificate{}
	getCertificate := renewingCertificateGetter("edge.example.com", func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		time.Sleep(20 * time.Millisecond)
		return expected, nil
	}, time.Millisecond, func() {
		renews.Add(1)
	})

	cert, err := getCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if cert != expected {
		t.Fatal("unexpected certificate")
	}
	if got := renews.Load(); got != 1 {
		t.Fatalf("renew callback calls = %d, want 1", got)
	}
}
