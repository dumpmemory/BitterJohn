package vmess

import (
	"context"
	"github.com/mzz2017/softwind/protocol/vmess"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	"golang.org/x/net/proxy"
	"testing"
)

func TestServer(t *testing.T) {
	doubleCuckoo := vmess.NewReplayFilter(120)
	svr, err := New(context.WithValue(context.Background(), "doubleCuckoo", doubleCuckoo), proxy.Direct)
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
	if err := svr.Listen("localhost:18080"); err != nil {
		t.Fatal(err)
	}
}
