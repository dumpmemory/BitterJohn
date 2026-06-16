package anytls

import (
	"crypto/sha256"
	"errors"
	"net"
	"testing"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
)

func TestServerPassageConfigLifecycle(t *testing.T) {
	srvIface, err := New(testTLSContext(t), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer srvIface.Close()
	srv := srvIface.(*Server)

	alpha := anyTLSPassage("alpha-password")
	bravo := anyTLSPassage("bravo-password")
	charlie := anyTLSPassage("charlie-password")
	if err := srv.AddPassages([]server.Passage{alpha, bravo, server.Passage{Manager: true}}); err != nil {
		t.Fatal(err)
	}
	managerPassword := requireManagerPassword(t, srv)

	requireAuthPassword(t, srv, alpha.In.Password)
	requireAuthPassword(t, srv, bravo.In.Password)
	requireAuthPassword(t, srv, managerPassword)

	if err := srv.RemovePassages([]server.Passage{alpha}, false); err != nil {
		t.Fatal(err)
	}
	requireAuthFailure(t, srv, alpha.In.Password)
	requireAuthPassword(t, srv, bravo.In.Password)
	requireAuthPassword(t, srv, managerPassword)

	if err := srv.SyncPassages([]server.Passage{charlie}); err != nil {
		t.Fatal(err)
	}
	requireAuthFailure(t, srv, alpha.In.Password)
	requireAuthFailure(t, srv, bravo.In.Password)
	requireAuthPassword(t, srv, charlie.In.Password)
	requireAuthPassword(t, srv, managerPassword)
}

func TestAuthenticatedPassageSurvivesHotSync(t *testing.T) {
	srvIface, err := New(testTLSContext(t), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer srvIface.Close()
	srv := srvIface.(*Server)

	alpha := anyTLSPassage("alpha-password")
	bravo := anyTLSPassage("bravo-password")
	if err := srv.AddPassages([]server.Passage{alpha, bravo}); err != nil {
		t.Fatal(err)
	}

	passage, err := authPassword(t, srv, alpha.In.Password)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.RemovePassages([]server.Passage{alpha}, false); err != nil {
		t.Fatal(err)
	}

	if got, want := passage.In.Password, alpha.In.Password; got != want {
		t.Fatalf("authenticated passage password changed after sync: got %q, want %q", got, want)
	}
}

func anyTLSPassage(password string) server.Passage {
	return server.Passage{
		Passage: model.Passage{
			In: model.In{Argument: model.Argument{
				Protocol: "anytls",
				Password: password,
			}},
		},
	}
}

func requireManagerPassword(t *testing.T, srv *Server) string {
	t.Helper()

	for _, passage := range srv.Passages() {
		if passage.Manager {
			if passage.In.Password == "" {
				t.Fatal("manager password is empty")
			}
			return passage.In.Password
		}
	}
	t.Fatal("manager passage not found")
	return ""
}

func requireAuthPassword(t *testing.T, srv *Server, password string) {
	t.Helper()

	passage, err := authPassword(t, srv, password)
	if err != nil {
		t.Fatalf("auth %q failed: %v", password, err)
	}
	if passage.In.Password != password {
		t.Fatalf("authenticated password = %q, want %q", passage.In.Password, password)
	}
}

func requireAuthFailure(t *testing.T, srv *Server, password string) {
	t.Helper()

	if _, err := authPassword(t, srv, password); !errors.Is(err, protocol.ErrFailAuth) {
		t.Fatalf("auth %q error = %v, want %v", password, err, protocol.ErrFailAuth)
	}
}

func authPassword(t *testing.T, srv *Server, password string) (*Passage, error) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	writeErr := make(chan error, 1)
	go func() {
		defer clientConn.Close()
		writeErr <- writeClientAuth(clientConn, sha256.Sum256([]byte(password)))
	}()

	passage, err := srv.auth(serverConn)
	_ = serverConn.Close()
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	return passage, err
}
