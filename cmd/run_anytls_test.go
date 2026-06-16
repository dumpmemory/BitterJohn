package cmd

import (
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
)

func TestProtocolRuntimeAcceptsAnyTLS(t *testing.T) {
	ctx, dialer, err := protocolRuntime(server.ProtocolAnyTLS)
	if err != nil {
		t.Fatal(err)
	}
	if ctx == nil {
		t.Fatal("ctx is nil")
	}
	if dialer == nil {
		t.Fatal("dialer is nil")
	}
}

func TestProtocolRequiresDNSReadyIncludesAnyTLS(t *testing.T) {
	tests := []struct {
		name  string
		proto protocol.Protocol
		want  bool
	}{
		{name: "anytls", proto: server.ProtocolAnyTLS, want: true},
		{name: "grpc tls", proto: protocol.ProtocolVMessTlsGrpc, want: true},
		{name: "vmess tcp", proto: protocol.ProtocolVMessTCP, want: false},
		{name: "juicity", proto: protocol.ProtocolJuicity, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := protocolRequiresDNSReady(tt.proto); got != tt.want {
				t.Fatalf("protocolRequiresDNSReady(%q) = %v, want %v", tt.proto, got, tt.want)
			}
		})
	}
}
