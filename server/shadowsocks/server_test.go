package shadowsocks

import (
	"context"
	"hash/fnv"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/softwind/protocol/direct"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/infra/lru"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/SweetLisa/model"
	disk_bloom "github.com/mzz2017/disk-bloom"
)

func getState(s *Server, key string) (list []string) {
	val, _ := s.userContextPool.Infra().GetOrInsert(key, func() (val interface{}) {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		return NewUserContext(s.passages)
	})
	nodes := val.(*UserContext).Infra().GetListCopy()
	for _, node := range nodes {
		switch passage := node.Val.(type) {
		case Passage:
			list = append(list, passage.In.From)
		case *Passage:
			list = append(list, passage.In.From)
		default:
			panic("unexpected passage type")
		}
	}
	val.(*UserContext).Infra().DestroyListCopy(nodes)
	return list
}

func TestServer_AddPassages(t *testing.T) {
	s := Server{
		userContextPool: (*UserContextPool)(lru.New(lru.FixedTimeout, int64(1*time.Hour))),
	}
	if err := s.AddPassages([]server.Passage{{Manager: true}}); err != nil {
		t.Fatal(err)
	}
	if len(s.passages) != 1 {
		t.Fatal()
	} else if !s.passages[0].Manager {
		t.Fatal()
	}
	passages := [][]server.Passage{
		{
			{
				Manager: false,
				Passage: model.Passage{
					In: model.In{
						From:     "1",
						Argument: model.Argument{Method: "aes-128-gcm"},
					},
				}}, {
				Manager: false,
				Passage: model.Passage{
					In: model.In{
						From:     "2",
						Argument: model.Argument{Method: "aes-256-gcm"},
					},
				},
			},
		},
		{
			{
				Manager: false,
				Passage: model.Passage{
					In: model.In{
						From:     "1",
						Argument: model.Argument{Method: "aes-128-gcm"},
					},
				},
			},
		},
		{
			{
				Manager: false,
				Passage: model.Passage{
					In: model.In{
						From:     "1",
						Argument: model.Argument{Method: "aes-128-gcm"},
					},
				},
			},
			{
				Manager: false,
				Passage: model.Passage{
					In: model.In{
						From:     "2",
						Argument: model.Argument{Method: "aes-256-gcm"},
					},
				},
			},
		},
	}
	states := [][]string{
		{"", "1", "2"},
		{"", "1"},
		{"", "1", "2"},
	}
	for i := range passages {
		if err := s.SyncPassages(passages[i]); err != nil {
			t.Fatal(err)
		}
		st := getState(&s, "test")
		if len(states[i]) != len(st) {
			t.Fatal("test", strconv.Itoa(i)+":", st, "should be", states[i])
		}
		sort.Strings(st)
		sort.Strings(states[i])
		for j := range st {
			if states[i][j] != st[j] {
				t.Fatal("test", strconv.Itoa(i)+":", st, "should be", states[i])
			}
		}
	}
}

func TestServer(t *testing.T) {
	bloom, err := disk_bloom.NewGroup("/tmp/bloom_*", disk_bloom.FsyncModeNo, 1e3, 1e-6, func(b []byte) (uint64, uint64) {
		hx := fnv.New64()
		hx.Write(b)
		x := hx.Sum64()
		hy := fnv.New64a()
		hy.Write(b)
		y := hy.Sum64()
		return x, y
	})
	if err != nil {
		t.Fatal(err)
	}
	svr, err := New(context.WithValue(context.Background(), "bloom", bloom), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	if err = svr.AddPassages([]server.Passage{{
		Manager: false,
		Passage: model.Passage{
			In: model.In{
				From: "",
				Argument: model.Argument{
					Protocol: "shadowsocks",
					Password: "oKLW52IDIZKQ3QXHS434N",
					Method:   "aes-128-gcm",
				},
			},
			Out: nil,
		},
	}}); err != nil {
		t.Fatal(err)
	}
	s := svr.(*Server)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenTCP("127.0.0.1:0")
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
		t.Fatal("ListenTCP did not return after Close")
	}
}

func TestServer_ListenUDPReturnsIfAlreadyClosed(t *testing.T) {
	s := &Server{closed: make(chan struct{})}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenUDP("127.0.0.1:0")
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ListenUDP did not return after Close")
	}
}

func TestServer_CloseStopsListenUDP(t *testing.T) {
	s := &Server{closed: make(chan struct{})}
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.ListenUDP("127.0.0.1:0")
	}()

	waitForUDPConn(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ListenUDP did not return after Close")
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

func waitForUDPConn(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			t.Fatal("udp listener was not created")
		case <-ticker.C:
			s.mutex.Lock()
			udpConn := s.udpConn
			s.mutex.Unlock()
			if udpConn != nil {
				return
			}
		}
	}
}
