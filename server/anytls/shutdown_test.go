package anytls

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/softwind/protocol"
	"github.com/daeuniverse/softwind/protocol/direct"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
)

func TestCloseBeforeServeListenerStopsListener(t *testing.T) {
	srvIface, err := New(context.Background(), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	srv := srvIface.(*Server)
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}

	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.serveListener(lt)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		_ = lt.Close()
		t.Fatal("serveListener did not return after Close had already run")
	}
}

func TestManagerPingLastAliveIsSafeWithRegistrar(t *testing.T) {
	srvIface, err := New(context.Background(), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer srvIface.Close()
	srv := srvIface.(*Server)
	srv.setLastAlive(time.Now())
	go srv.registerBackground()

	passage := &Passage{Passage: server.Passage{Manager: true}}
	deadline := time.Now().Add(2300 * time.Millisecond)
	var pings atomic.Int64
	errCh := make(chan error, 4)

	for range 4 {
		go func() {
			for time.Now().Before(deadline) {
				if err := exchangeManagerPing(srv, passage); err != nil {
					errCh <- err
					return
				}
				pings.Add(1)
			}
			errCh <- nil
		}()
	}

	for range 4 {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}
	if pings.Load() == 0 {
		t.Fatal("manager ping loop did not run")
	}
}

func exchangeManagerPing(srv *Server, passage *Passage) error {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	errCh := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		errCh <- srv.handleMsg(serverConn, passage)
	}()

	req := make([]byte, 1+4+4)
	req[0] = byte(protocol.MetadataCmdPing)
	binary.BigEndian.PutUint32(req[1:5], 4)
	copy(req[5:], "ping")
	if _, err := clientConn.Write(req); err != nil {
		return err
	}

	var lenBuf [4]byte
	if _, err := io.ReadFull(clientConn, lenBuf[:]); err != nil {
		return err
	}
	if n := binary.BigEndian.Uint32(lenBuf[:]); n > 0 {
		if _, err := io.CopyN(io.Discard, clientConn, int64(n)); err != nil {
			return err
		}
	}
	return <-errCh
}
