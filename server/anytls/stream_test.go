package anytls

import (
	"errors"
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
