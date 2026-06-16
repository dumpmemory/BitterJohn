package cmd

import (
	"testing"

	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
)

func TestInstallProtocolOptionsIncludeAnyTLS(t *testing.T) {
	for _, option := range installProtocolOptions() {
		if option == string(server.ProtocolAnyTLS) {
			return
		}
	}
	t.Fatalf("install protocol options do not contain %q", server.ProtocolAnyTLS)
}
