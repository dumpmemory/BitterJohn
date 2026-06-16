package anytls

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/softwind/netproxy"
)

func TestUDPPacketConnReadFromResolvesDomainTarget(t *testing.T) {
	stream := newStream(1, &Session{closed: make(chan struct{})})
	defer stream.closeRemote()
	conn := newUDPPacketConn(stream, socksAddr{Host: "localhost", Port: 53})

	var payload bytes.Buffer
	if err := writeUOTPayload(&payload, []byte("pong")); err != nil {
		t.Fatal(err)
	}
	if err := stream.receive(payload.Bytes()); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 4)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(buf) != "pong" {
		t.Fatalf("ReadFrom payload = %q, want %q", string(buf[:n]), "pong")
	}
	if !addr.IsValid() {
		t.Fatal("ReadFrom returned an invalid zero address for a domain target")
	}
}

func TestHandleUOTAppliesDialTimeout(t *testing.T) {
	dialer := &contextDialerSpy{}
	srv := &Server{dialer: dialer}
	stream := newStream(1, &Session{closed: make(chan struct{})})
	defer stream.closeRemote()

	var req bytes.Buffer
	if err := writeUOTRequest(&req, uotRequest{
		IsConnect:   true,
		Destination: socksAddr{Host: "127.0.0.1", Port: 53},
	}); err != nil {
		t.Fatal(err)
	}
	if err := stream.receive(req.Bytes()); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.handleUOT(stream, &Passage{})
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("handleUOT error = %v, want context deadline exceeded", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handleUOT did not return after DialTimeout")
	}
}

type contextDialerSpy struct{}

func (d *contextDialerSpy) Dial(network string, addr string) (netproxy.Conn, error) {
	return nil, errors.New("plain Dial called")
}

func (d *contextDialerSpy) DialContext(ctx context.Context, network string, addr string) (netproxy.Conn, error) {
	if _, ok := ctx.Deadline(); !ok {
		return nil, errors.New("DialContext called without deadline")
	}
	return nil, context.DeadlineExceeded
}
