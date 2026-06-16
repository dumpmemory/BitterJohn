package vmess

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	proto "github.com/daeuniverse/outbound/pkg/gun_proto"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/daeuniverse/outbound/protocol/vmess"
	grpc2 "github.com/daeuniverse/outbound/transport/grpc"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"google.golang.org/grpc"
)

func TestServer(t *testing.T) {
	doubleCuckoo := vmess.NewReplayFilter(120)
	svr, err := New(context.WithValue(context.Background(), "doubleCuckoo", doubleCuckoo), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	if err = svr.AddPassages([]server.Passage{{
		Manager: false,
		Passage: model.Passage{
			In: model.In{
				From: "",
				Argument: model.Argument{
					Protocol: "vmess",
					Password: "28446de9-2a7e-4fab-827b-6df93e46f945",
				},
			},
			Out: nil,
		},
	}}); err != nil {
		t.Fatal(err)
	}
	s := svr.(*Server)
	s.protocol = protocol.ProtocolVMessTCP
	errCh := make(chan error, 1)
	go func() {
		errCh <- svr.Listen("127.0.0.1:0")
	}()
	waitForListener(t, s)
	if err := svr.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Listen did not return after Close")
	}
}

func TestCloseClosesClosedChannel(t *testing.T) {
	doubleCuckoo := vmess.NewReplayFilter(120)
	svr, err := New(context.WithValue(context.Background(), "doubleCuckoo", doubleCuckoo), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	s := svr.(*Server)
	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.listener = lt
	if err := svr.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not close closed channel")
	}
}

func TestAuthenticatedPassageSurvivesHotSync(t *testing.T) {
	doubleCuckoo := vmess.NewReplayFilter(120)
	svr, err := New(context.WithValue(context.Background(), "doubleCuckoo", doubleCuckoo), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	s := svr.(*Server)

	alpha := vmessTestPassage("alpha", "28446de9-2a7e-4fab-827b-6df93e46f945")
	bravo := vmessTestPassage("bravo", "38446de9-2a7e-4fab-827b-6df93e46f945")
	if err := s.AddPassages([]server.Passage{alpha, bravo}); err != nil {
		t.Fatal(err)
	}

	ctx := s.GetUserContextOrInsert("127.0.0.1")
	passage, _ := ctx.Auth(func(passage *Passage) ([]byte, bool) {
		return nil, passage.In.From == alpha.In.From
	})
	if passage == nil {
		t.Fatal("alpha passage was not found")
	}

	if err := s.RemovePassages([]server.Passage{alpha}, false); err != nil {
		t.Fatal(err)
	}
	if got, want := passage.In.From, alpha.In.From; got != want {
		t.Fatalf("authenticated passage changed after sync: got %q, want %q", got, want)
	}
}

func TestGrpcServer(t *testing.T) {
	log.SetLogLevel("trace")
	doubleCuckoo := vmess.NewReplayFilter(120)
	svr, err := New(context.WithValue(context.Background(), "doubleCuckoo", doubleCuckoo), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	if err = svr.AddPassages([]server.Passage{{
		Manager: false,
		Passage: model.Passage{
			In: model.In{
				From: "",
				Argument: model.Argument{
					Protocol: "vmess",
					Password: "28446de9-2a7e-4fab-827b-6df93e46f945",
				},
			},
			Out: nil,
		},
	}}); err != nil {
		t.Fatal(err)
	}

	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := svr.(*Server)
	s.grpc = grpc2.Server{
		Server:     grpc.NewServer(),
		LocalAddr:  lt.Addr(),
		HandleConn: s.handleConn,
	}
	proto.RegisterGunServiceServerX(s.grpc.Server, s.grpc, "GunService")

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.grpc.Serve(lt)
	}()
	s.grpc.Stop()
	select {
	case err = <-errCh:
		if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("grpc Serve did not return after Stop")
	}
}

func vmessTestPassage(from, password string) server.Passage {
	return server.Passage{
		Passage: model.Passage{
			In: model.In{
				From: from,
				Argument: model.Argument{
					Protocol: "vmess",
					Password: password,
				},
			},
		},
	}
}

func waitForListener(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("listener was not created")
		case <-ticker.C:
			s.mutex.Lock()
			listener := s.listener
			s.mutex.Unlock()
			if listener != nil {
				return
			}
		}
	}
}
