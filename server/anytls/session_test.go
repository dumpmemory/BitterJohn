package anytls

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
)

func TestClientSettingsAdvertiseSupportedProtocolVersion(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		errCh <- newClientSession(clientConn).runClient()
	}()

	if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	f, err := readFrame(serverConn)
	if err != nil {
		t.Fatal(err)
	}
	if f.cmd != cmdSettings {
		t.Fatalf("first client frame command = %d, want cmdSettings", f.cmd)
	}
	if got, want := parseSettings(f.data)["v"], "2"; got != want {
		t.Fatalf("advertised protocol version = %q, want %q", got, want)
	}

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func TestDialWaitsForV2Synack(t *testing.T) {
	password := "synack-password"
	addr, releaseSynack, closeServer := startSynackServer(t, password)
	defer closeServer()

	dialer, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: addr,
		Password:     password,
		TlsConfig:    &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.(*Dialer).Close()

	dialDone := make(chan error, 1)
	go func() {
		conn, err := dialer.DialContext(context.Background(), "tcp", "127.0.0.1:1")
		if err == nil {
			_ = conn.Close()
		}
		dialDone <- err
	}()

	select {
	case err := <-dialDone:
		t.Fatalf("Dial returned before SYNACK: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseSynack)
	select {
	case err := <-dialDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Dial did not return after SYNACK")
	}
}

func TestDialFallsBackToV1WithoutServerSettings(t *testing.T) {
	password := "v1-fallback-password"
	addr, closeServer := startV1Server(t, password)
	defer closeServer()

	dialer, err := NewDialer(direct.SymmetricDirect, protocol.Header{
		ProxyAddress: addr,
		Password:     password,
		TlsConfig:    &tls.Config{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer dialer.(*Dialer).Close()

	start := time.Now()
	conn, err := dialer.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Dial waited too long for v2 negotiation against a v1 server: %v", elapsed)
	}
}

func TestLateServerSettingsCanUpgradeAfterNegotiationTimeout(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	session := newClientSession(clientConn)
	errCh := make(chan error, 1)
	go func() {
		errCh <- session.runClient()
	}()

	if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if f, err := readFrame(serverConn); err != nil {
		t.Fatal(err)
	} else if f.cmd != cmdSettings {
		t.Fatalf("first client frame command = %d, want cmdSettings", f.cmd)
	}
	if err := serverConn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	if got := session.waitServerSettings(10 * time.Millisecond); got != 1 {
		t.Fatalf("peer version after negotiation timeout = %d, want v1 fallback", got)
	}
	if err := writeFrame(serverConn, frame{cmd: cmdServerSettings, data: []byte("v=2")}); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(time.Second)
	for {
		if got := session.waitServerSettings(time.Millisecond); got == 2 {
			break
		}
		time.Sleep(time.Millisecond)
		select {
		case <-deadline:
			t.Fatal("late server settings did not upgrade peer version to v2")
		default:
		}
	}

	_ = session.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
}

func startSynackServer(t *testing.T, password string) (addr string, releaseSynack chan struct{}, closeFn func()) {
	t.Helper()
	tlsConfig := testTLSConfig(t)
	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	releaseSynack = make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		rawConn, err := lt.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()
		conn := tls.Server(rawConn, tlsConfig)
		if err := conn.Handshake(); err != nil {
			return
		}
		if _, err := authFromConn(t, conn, password); err != nil {
			return
		}
		settings, err := readFrame(conn)
		if err != nil || settings.cmd != cmdSettings {
			return
		}
		if err := writeFrame(conn, frame{cmd: cmdServerSettings, data: []byte("v=2")}); err != nil {
			return
		}
		syn, err := readFrame(conn)
		if err != nil || syn.cmd != cmdSYN {
			return
		}
		psh, err := readFrame(conn)
		if err != nil || psh.cmd != cmdPSH {
			return
		}
		<-releaseSynack
		_ = writeFrame(conn, frame{cmd: cmdSYNACK, streamID: syn.streamID})
		<-time.After(20 * time.Millisecond)
	}()
	return lt.Addr().String(), releaseSynack, func() {
		_ = lt.Close()
		<-done
	}
}

func startV1Server(t *testing.T, password string) (addr string, closeFn func()) {
	t.Helper()
	tlsConfig := testTLSConfig(t)
	lt, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		rawConn, err := lt.Accept()
		if err != nil {
			return
		}
		defer rawConn.Close()
		conn := tls.Server(rawConn, tlsConfig)
		if err := conn.Handshake(); err != nil {
			return
		}
		if _, err := authFromConn(t, conn, password); err != nil {
			return
		}
		if _, err := readFrame(conn); err != nil {
			return
		}
		if _, err := readFrame(conn); err != nil {
			return
		}
		if _, err := readFrame(conn); err != nil {
			return
		}
		<-time.After(20 * time.Millisecond)
	}()
	return lt.Addr().String(), func() {
		_ = lt.Close()
		<-done
	}
}

func authFromConn(t *testing.T, conn net.Conn, password string) (*Passage, error) {
	t.Helper()
	srvIface, err := New(testTLSContext(t), direct.SymmetricDirect)
	if err != nil {
		t.Fatal(err)
	}
	defer srvIface.Close()
	srv := srvIface.(*Server)
	if err := srv.AddPassages([]server.Passage{anyTLSPassage(password)}); err != nil {
		t.Fatal(err)
	}
	return srv.auth(conn)
}
