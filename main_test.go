package main

import (
	"testing"

	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
)

func TestMainImportsAnyTLSServer(t *testing.T) {
	if _, ok := server.Mapper[string(server.ProtocolAnyTLS)]; !ok {
		t.Fatalf("server mapper does not contain %q", server.ProtocolAnyTLS)
	}
}
