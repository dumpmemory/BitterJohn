package lrulist

import (
	"runtime"
	"testing"
	"time"
)

func TestCloseWaitsForUpdaterGoroutine(t *testing.T) {
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)

	list := New(time.Hour, InsertFront)

	if err := list.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case <-list.updateDone:
	default:
		t.Fatal("Close returned before updater goroutine stopped")
	}
}

func TestCloseStopsUpdaterGoroutine(t *testing.T) {
	list := New(time.Hour, InsertFront)

	if err := list.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case <-list.updateDone:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close did not stop updater goroutine")
	}
}

func TestCloseCanBeCalledMoreThanOnce(t *testing.T) {
	list := New(time.Hour, InsertFront)

	if err := list.Close(); err != nil {
		t.Fatalf("first Close returned error: %v", err)
	}
	if err := list.Close(); err != nil {
		t.Fatalf("second Close returned error: %v", err)
	}
}

func TestCloseWithNewWithListDoesNotBlockAndIsIdempotent(t *testing.T) {
	list := NewWithList(time.Hour, InsertFront, []interface{}{"a", "b"})

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := list.Close(); err != nil {
			t.Errorf("first Close returned error: %v", err)
		}
		if err := list.Close(); err != nil {
			t.Errorf("second Close returned error: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Close blocked for NewWithList")
	}
}
