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

func TestStreamWriteDeadlineDoesNotPoisonOtherStreams(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	session := &Session{
		conn:    local,
		streams: make(map[uint32]*Stream),
		closed:  make(chan struct{}),
	}
	blockedStream := newStream(1, session)
	otherStream := newStream(2, session)
	defer blockedStream.closeRemote()
	defer otherStream.closeRemote()

	errCh := make(chan error, 1)
	go func() {
		_, err := blockedStream.Write([]byte("blocked"))
		errCh <- err
	}()

	time.Sleep(10 * time.Millisecond)
	if err := blockedStream.SetWriteDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("blocked stream Write() error = %v, want deadline exceeded", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("SetWriteDeadline did not wake blocked stream Write")
	}

	readCh := make(chan frame, 1)
	readErrCh := make(chan error, 1)
	go func() {
		f, err := readFrame(remote)
		if err != nil {
			readErrCh <- err
			return
		}
		readCh <- f
	}()

	if _, err := otherStream.Write([]byte("ok")); err != nil {
		t.Fatalf("other stream Write() error = %v, want nil", err)
	}
	select {
	case err := <-readErrCh:
		t.Fatal(err)
	case f := <-readCh:
		if f.cmd != cmdPSH || f.streamID != otherStream.id || string(f.data) != "ok" {
			t.Fatalf("written frame = cmd:%d stream:%d data:%q, want cmdPSH stream:%d data:%q", f.cmd, f.streamID, f.data, otherStream.id, "ok")
		}
	case <-time.After(time.Second):
		t.Fatal("remote peer did not receive other stream write")
	}
}
