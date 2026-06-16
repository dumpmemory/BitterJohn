package anytls

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

func TestStreamSetReadDeadlineWakesBlockedRead(t *testing.T) {
	stream := newStream(1, &Session{closed: make(chan struct{})})
	defer stream.closeRemote()

	errCh := make(chan error, 1)
	go func() {
		var buf [1]byte
		_, err := stream.Read(buf[:])
		errCh <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := stream.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read() error = %v, want deadline exceeded", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("SetReadDeadline did not wake blocked Read")
	}
}

func TestStreamSetWriteDeadlineWakesBlockedWrite(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	stream := newStream(1, &Session{
		conn:   local,
		closed: make(chan struct{}),
	})
	defer stream.closeRemote()

	errCh := make(chan error, 1)
	go func() {
		_, err := stream.Write([]byte("blocked"))
		errCh <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := stream.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write() error = %v, want deadline exceeded", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("SetWriteDeadline did not wake blocked Write")
	}
}
