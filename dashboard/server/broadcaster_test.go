//nolint:testpackage // Need access to internal implementation details
package server

import (
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestBroadcasterSendNoClients(t *testing.T) {
	t.Parallel()

	bc := newBroadcaster()

	// Must not panic or block when nobody is subscribed.
	bc.Send([]byte("nobody listening"))
}

func TestBroadcasterSlowClientDrop(t *testing.T) {
	t.Parallel()

	bc := newBroadcaster()
	slow := bc.Add()
	fast := bc.Add()

	// Fill the slow client's buffer completely while the fast client keeps draining.
	for range cap(slow) {
		bc.Send([]byte("fill"))
		<-fast
	}

	if len(slow) != cap(slow) {
		t.Fatalf("slow client buffer = %d, want full (%d)", len(slow), cap(slow))
	}

	// Buffer full: this send is dropped for the slow client but still reaches the fast one.
	bc.Send([]byte("overflow"))

	select {
	case msg := <-fast:
		if string(msg) != "overflow" {
			t.Fatalf("fast client got %q, want overflow", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("fast client did not receive message after slow client filled up")
	}

	if len(slow) != cap(slow) {
		t.Fatalf("slow client buffer grew past capacity: %d", len(slow))
	}

	// The dropped message must not appear when draining the slow client.
	for i := range cap(slow) {
		msg := <-slow
		if string(msg) != "fill" {
			t.Fatalf("slow client message %d = %q, want fill", i, msg)
		}
	}

	bc.Remove(slow)
	bc.Remove(fast)
}

func TestBroadcasterRemoveClosesOnlyTarget(t *testing.T) {
	t.Parallel()

	bc := newBroadcaster()
	removed := bc.Add()
	kept := bc.Add()

	bc.Remove(removed)

	_, ok := <-removed
	if ok {
		t.Fatal("removed channel should be closed")
	}

	bc.Send([]byte("still here"))

	select {
	case msg := <-kept:
		if string(msg) != "still here" {
			t.Fatalf("kept client got %q, want still here", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("kept client did not receive message after other client removed")
	}

	bc.Remove(kept)
}

func TestBroadcasterConcurrentAddSendRemove(t *testing.T) {
	t.Parallel()

	bc := newBroadcaster()

	var wg sync.WaitGroup

	for i := range 8 {
		wg.Go(func() {
			ch := bc.Add()

			bc.Send([]byte("msg-" + strconv.Itoa(i)))
			bc.Remove(ch)
		})
	}

	wg.Wait()

	// All clients removed: a final send must not panic on closed channels.
	bc.Send([]byte("after"))
}
