package server

import "sync"

// changeNotifier wakes every current waiter without retaining per-connection
// state. A waiter subscribes before reading the store so it cannot miss a
// change committed between the read and the wait.
type changeNotifier struct {
	mu sync.Mutex
	ch chan struct{}
}

func newChangeNotifier() *changeNotifier {
	return &changeNotifier{ch: make(chan struct{})}
}

func (n *changeNotifier) subscribe() <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.ch
}

func (n *changeNotifier) notify() {
	n.mu.Lock()
	close(n.ch)
	n.ch = make(chan struct{})
	n.mu.Unlock()
}
