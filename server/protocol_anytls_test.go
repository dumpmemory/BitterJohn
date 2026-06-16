package server

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
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

func TestGetHeaderAnyTLSConfigVariants(t *testing.T) {
	tests := []struct {
		name       string
		out        model.Out
		wantSNI    string
		wantErr    bool
		wantServer string
	}{
		{
			name: "explicit sni overrides ipv4 derived sni",
			out: model.Out{
				Host: "203.0.113.8",
				Port: "443",
				Argument: model.Argument{
					Protocol: "anytls",
					Password: "secret-password",
					Method:   "sni=cdn.example.com",
				},
			},
			wantSNI:    "cdn.example.com",
			wantServer: "cdn.example.com",
		},
		{
			name: "domain host is used as fallback sni",
			out: model.Out{
				Host: "edge.example.net",
				Port: "8443",
				Argument: model.Argument{
					Protocol: "anytls",
					Password: "secret-password",
				},
			},
			wantSNI:    "edge.example.net",
			wantServer: "edge.example.net",
		},
		{
			name: "ipv4 host derives lisa subdomain sni",
			out: model.Out{
				Host: "203.0.113.8",
				Port: "9443",
				Argument: model.Argument{
					Protocol: "anytls",
					Password: "secret-password",
				},
			},
			wantSNI:    "203-0-113-8.sweet.example.com",
			wantServer: "203-0-113-8.sweet.example.com",
		},
		{
			name: "explicit sni allows ipv6 proxy host",
			out: model.Out{
				Host: "2001:db8::1",
				Port: "9443",
				Argument: model.Argument{
					Protocol: "anytls",
					Password: "secret-password",
					Method:   "sni=edge.example.com",
				},
			},
			wantSNI:    "edge.example.com",
			wantServer: "edge.example.com",
		},
		{
			name: "ipv6 host without explicit sni is rejected",
			out: model.Out{
				Host: "2001:db8::1",
				Port: "9443",
				Argument: model.Argument{
					Protocol: "anytls",
					Password: "secret-password",
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header, err := GetHeader(tt.out, &config.Lisa{Host: "sweet.example.com"})
			if tt.wantErr {
				if err == nil {
					t.Fatal("GetHeader succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}

			if got, want := header.ProxyAddress, net.JoinHostPort(tt.out.Host, tt.out.Port); got != want {
				t.Fatalf("ProxyAddress = %q, want %q", got, want)
			}
			if got, want := header.Password, tt.out.Password; got != want {
				t.Fatalf("Password = %q, want %q", got, want)
			}
			if got := header.SNI; got != tt.wantSNI {
				t.Fatalf("SNI = %q, want %q", got, tt.wantSNI)
			}
			if header.TlsConfig == nil {
				t.Fatal("TlsConfig is nil")
			}
			if got := header.TlsConfig.ServerName; got != tt.wantServer {
				t.Fatalf("TlsConfig.ServerName = %q, want %q", got, tt.wantServer)
			}
			if !header.TlsConfig.InsecureSkipVerify {
				t.Fatal("anytls client config should skip verification unless a stronger verifier is configured")
			}
			if got, want := header.TlsConfig.MinVersion, uint16(tls.VersionTLS12); got != want {
				t.Fatalf("TlsConfig.MinVersion = %v, want %v", got, want)
			}
		})
	}
}
