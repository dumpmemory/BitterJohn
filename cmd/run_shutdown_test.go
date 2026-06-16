package cmd

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestRunShutdownRecordsFirstErrorAndIgnoresRepeatedSignals(t *testing.T) {
	shutdown := newRunShutdown(nil)
	firstErr := errors.New("first")

	shutdown.signal(firstErr)
	shutdown.signal(errors.New("second"))

	if err := shutdown.wait(); !errors.Is(err, firstErr) {
		t.Fatalf("wait() error = %v, want %v", err, firstErr)
	}
}

func TestRunShutdownCanBeSignaledConcurrently(t *testing.T) {
	shutdown := newRunShutdown(nil)

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			shutdown.signal(nil)
		}()
	}

	waited := make(chan struct{})
	go func() {
		defer close(waited)
		wg.Wait()
		_ = shutdown.wait()
	}()

	select {
	case <-waited:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for concurrent shutdown signals")
	}
}

func TestRunShutdownClosesServerBeforeWaitReturns(t *testing.T) {
	closed := make(chan struct{})
	shutdown := newRunShutdown(func() error {
		close(closed)
		return nil
	})

	shutdown.signal(nil)
	if err := shutdown.wait(); err != nil {
		t.Fatalf("wait() error = %v, want nil", err)
	}
	select {
	case <-closed:
	default:
		t.Fatal("server close hook was not called before wait returned")
	}
}
