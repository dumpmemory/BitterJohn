package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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

func TestCloseStopsAcceptedConnectionDuringTLSHandshake(t *testing.T) {
	srvIface, err := New(context.Background(), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	srv := srvIface.(*Server)
	addr, errCh := serveAnyTLSForShutdownTest(t, srv)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(20 * time.Millisecond)

	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	requireConnClosedByServer(t, conn)
	requireServeStopped(t, errCh)
}

func TestCloseStopsAcceptedConnectionDuringAuthRead(t *testing.T) {
	srvIface, err := New(context.Background(), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	srv := srvIface.(*Server)
	addr, errCh := serveAnyTLSForShutdownTest(t, srv)

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	conn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	requireConnClosedByServer(t, conn)
	requireServeStopped(t, errCh)
}

func TestCloseStopsAuthenticatedIdleSession(t *testing.T) {
	srvIface, err := New(context.Background(), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer srvIface.Close()
	srv := srvIface.(*Server)
	const password = "idle-session-password"
	if err := srv.AddPassages([]server.Passage{anyTLSPassage(password)}); err != nil {
		t.Fatal(err)
	}
	addr, errCh := serveAnyTLSForShutdownTest(t, srv)

	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()
	conn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := writeClientAuth(conn, sha256.Sum256([]byte(password))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)

	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	requireConnClosedByServer(t, conn)
	requireServeStopped(t, errCh)
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

func serveAnyTLSForShutdownTest(t *testing.T, srv *Server) (string, <-chan error) {
	t.Helper()
	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.serveListener(lt)
	}()
	return lt.Addr().String(), errCh
}

func requireConnClosedByServer(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	_, err := conn.Read(buf[:])
	if err == nil {
		t.Fatal("connection remained readable after server Close")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("connection was not closed by server Close")
	}
}

func requireServeStopped(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveListener did not stop after Close")
	}
}
