package server

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/daeuniverse/softwind/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
)

func TestProtocolValidAcceptsAnyTLS(t *testing.T) {
	if !ProtocolValid(ProtocolAnyTLS) {
		t.Fatalf("ProtocolValid(%q) = false, want true", ProtocolAnyTLS)
	}
	if !ProtocolValid(protocol.ProtocolVMessTCP) {
		t.Fatalf("ProtocolValid(%q) = false, want true", protocol.ProtocolVMessTCP)
	}
	if ProtocolValid(protocol.Protocol("definitely-not-supported")) {
		t.Fatal("ProtocolValid accepted an unknown protocol")
	}
}

func TestGetHeaderAnyTLS(t *testing.T) {
	out := model.Out{
		Host: "203.0.113.8",
		Port: "443",
		Argument: model.Argument{
			Protocol: ProtocolAnyTLS,
			Password: "secret-password",
			Method:   "sni=cdn.example.com",
		},
	}

	header, err := GetHeader(out, &config.Lisa{Host: "sweet.example.com"})
	if err != nil {
		t.Fatal(err)
	}

	if got, want := header.ProxyAddress, net.JoinHostPort(out.Host, out.Port); got != want {
		t.Fatalf("ProxyAddress = %q, want %q", got, want)
	}
	if got, want := header.Password, out.Password; got != want {
		t.Fatalf("Password = %q, want %q", got, want)
	}
	if got, want := header.SNI, "cdn.example.com"; got != want {
		t.Fatalf("SNI = %q, want %q", got, want)
	}
	if header.TlsConfig == nil {
		t.Fatal("TlsConfig is nil")
	}
	if got, want := header.TlsConfig.ServerName, "cdn.example.com"; got != want {
		t.Fatalf("TlsConfig.ServerName = %q, want %q", got, want)
	}
	if !header.TlsConfig.InsecureSkipVerify {
		t.Fatal("anytls client config should skip verification unless a stronger verifier is configured")
	}
	if got, want := header.TlsConfig.MinVersion, uint16(tls.VersionTLS12); got != want {
		t.Fatalf("TlsConfig.MinVersion = %v, want %v", got, want)
	}
}
