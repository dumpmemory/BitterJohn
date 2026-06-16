package cmd

import (
	"testing"

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
