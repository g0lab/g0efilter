//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/recovery"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	n, err := b.buf.Write(p)
	if err != nil {
		return n, fmt.Errorf("write log buffer: %w", err)
	}

	return n, nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func testLogger() (*slog.Logger, *syncBuffer) {
	buf := &syncBuffer{}

	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})), buf
}

func connPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	ln, err := listenTCP(t, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	defer func() { _ = ln.Close() }()

	type accepted struct {
		conn net.Conn
		err  error
	}

	ch := make(chan accepted, 1)

	go func() {
		conn, acceptErr := ln.Accept()
		ch <- accepted{conn: conn, err: acceptErr}
	}()

	client, err := dialTCP(t, ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	result := <-ch
	if result.err != nil {
		t.Fatalf("accept: %v", result.err)
	}

	t.Cleanup(func() {
		_ = client.Close()
		_ = result.conn.Close()
	})

	return client, result.conn
}

func TestDispatchConnContainsHandlerPanic(t *testing.T) {
	t.Parallel()

	lg, buf := testLogger()

	_, server := connPair(t)

	done := make(chan struct{})
	handler := func(_ net.Conn, _ *hostMatcher, _ Options) error {
		defer close(done)

		panic("malformed input")
	}

	dispatchConn(t.Context(), nil, server, handler, newMatcher(nil), Options{Logger: lg}, "https")

	<-done

	waitFor(t, func() bool { return strings.Contains(buf.String(), recovery.PanicMessage) })

	if !strings.Contains(buf.String(), `"component":"https"`) {
		t.Errorf("panic was not attributed to the listener: %q", buf.String())
	}
}

func TestDispatchConnClosesConnectionOnPanic(t *testing.T) {
	t.Parallel()

	lg, _ := testLogger()

	client, server := connPair(t)

	handler := func(_ net.Conn, _ *hostMatcher, _ Options) error {
		panic("before the handler registers its own close")
	}

	dispatchConn(t.Context(), nil, server, handler, newMatcher(nil), Options{Logger: lg}, "https")

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))

	_, err := client.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("connection was left open after the handler panicked")
	}
}

func TestDispatchConnReleasesSemaphoreOnPanic(t *testing.T) {
	t.Parallel()

	lg, _ := testLogger()

	sem := make(chan struct{}, 1)

	for range 3 {
		_, server := connPair(t)

		done := make(chan struct{})
		handler := func(_ net.Conn, _ *hostMatcher, _ Options) error {
			defer close(done)

			panic("boom")
		}

		dispatchConn(t.Context(), sem, server, handler, newMatcher(nil), Options{Logger: lg}, "https")
		<-done
	}

	waitFor(t, func() bool { return len(sem) == 0 })
}

func TestDispatchConnAbandonsQueuedConnectionOnCancel(t *testing.T) {
	t.Parallel()

	lg, _ := testLogger()

	ctx, cancel := context.WithCancel(t.Context())

	sem := make(chan struct{}, 1)
	sem <- struct{}{} // no free slot: the dispatch must queue

	client, server := connPair(t)

	var handled atomic.Bool

	//nolint:unparam // must satisfy the handler signature
	handler := func(_ net.Conn, _ *hostMatcher, _ Options) error {
		handled.Store(true)

		return nil
	}

	returned := make(chan struct{})

	go func() {
		defer close(returned)

		dispatchConn(ctx, sem, server, handler, newMatcher(nil), Options{Logger: lg}, "https")
	}()

	select {
	case <-returned:
		t.Fatal("dispatchConn returned while the semaphore was full")
	case <-time.After(100 * time.Millisecond):
	}

	cancel()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("dispatchConn ignored cancellation and stayed queued")
	}

	if handled.Load() {
		t.Error("a connection queued at cancellation must not be handled")
	}

	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))

	_, err := client.Read(make([]byte, 1))
	if err == nil {
		t.Error("an abandoned connection must be closed, not leaked")
	}
}

func TestNextAcceptBackoff(t *testing.T) {
	t.Parallel()

	tests := []struct {
		current time.Duration
		want    time.Duration
	}{
		{0, acceptBackoffMin},
		{acceptBackoffMin, 2 * acceptBackoffMin},
		{acceptBackoffMax / 2, acceptBackoffMax},
		{acceptBackoffMax, acceptBackoffMax},
		{2 * acceptBackoffMax, acceptBackoffMax},
	}

	for _, tt := range tests {
		if got := nextAcceptBackoff(tt.current); got != tt.want {
			t.Errorf("nextAcceptBackoff(%v) = %v, want %v", tt.current, got, tt.want)
		}
	}
}

var errFDExhausted = errors.New("too many open files")

type failingListener struct {
	attempts atomic.Int64
	addr     net.Addr
}

func (l *failingListener) Accept() (net.Conn, error) {
	l.attempts.Add(1)

	return nil, errFDExhausted
}

func (l *failingListener) Close() error   { return nil }
func (l *failingListener) Addr() net.Addr { return l.addr }

func TestAcceptLoopBacksOffOnPersistentFailure(t *testing.T) {
	t.Parallel()

	lg, _ := testLogger()

	ln := &failingListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}}

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	handler := func(_ net.Conn, _ *hostMatcher, _ Options) error { return nil }

	acceptLoop(ctx, ln, lg, nil, handler, newMatcher(nil), Options{Logger: lg}, "https")

	attempts := ln.attempts.Load()

	const maxAttempts = 20

	if attempts > maxAttempts {
		t.Errorf("accept was retried %d times in 200ms, want at most %d", attempts, maxAttempts)
	}

	if attempts < 2 {
		t.Errorf("accept was retried %d times, want it to keep trying", attempts)
	}
}

type scriptedListener struct {
	mu        sync.Mutex
	calls     []time.Time
	succeedOn int
	conns     []net.Conn
	addr      net.Addr
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls = append(l.calls, time.Now())
	n := len(l.calls)
	l.mu.Unlock()

	if n != l.succeedOn {
		return nil, errFDExhausted
	}

	client, server := net.Pipe()

	l.mu.Lock()
	l.conns = append(l.conns, client, server)
	l.mu.Unlock()

	return server, nil
}

func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return l.addr }

func (l *scriptedListener) gapAfter(n int) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.calls[n].Sub(l.calls[n-1])
}

func (l *scriptedListener) attempts() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return len(l.calls)
}

func TestAcceptLoopResetsBackoffAfterSuccess(t *testing.T) {
	t.Parallel()

	lg, _ := testLogger()

	const (
		succeedOn = 7
		total     = 9
	)

	ln := &scriptedListener{
		succeedOn: succeedOn,
		addr:      &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		for ln.attempts() < total {
			time.Sleep(time.Millisecond)
		}

		cancel()
	}()

	handler := func(conn net.Conn, _ *hostMatcher, _ Options) error {
		return conn.Close()
	}

	acceptLoop(ctx, ln, lg, nil, handler, newMatcher(nil), Options{Logger: lg}, "https")

	t.Cleanup(func() {
		for _, c := range ln.conns {
			_ = c.Close()
		}
	})

	if ln.attempts() < total {
		t.Fatalf("only %d accept attempts, want %d", ln.attempts(), total)
	}

	grown := ln.gapAfter(succeedOn - 1)
	if grown < 4*acceptBackoffMin {
		t.Fatalf("backoff did not grow across failures: gap was %v", grown)
	}

	reset := ln.gapAfter(succeedOn + 1)
	if reset > 20*acceptBackoffMin {
		t.Errorf("retry %v after a successful accept, want it reset to about %v", reset, acceptBackoffMin)
	}
}

func TestServeTCPSurvivesAPanickingHandler(t *testing.T) {
	t.Parallel()

	lg, buf := testLogger()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var handled atomic.Int64

	handler := func(conn net.Conn, _ *hostMatcher, _ Options) error {
		defer func() { _ = conn.Close() }()

		if handled.Add(1) == 1 {
			panic("first connection is hostile")
		}

		return nil
	}

	addr := reservedAddr(t)

	opts := Options{Logger: lg, MaxConns: 4}

	serveErr := make(chan error, 1)

	go func() {
		serveErr <- serveTCP(ctx, addr, lg, handler, newMatcher(nil), opts, "https")
	}()

	waitFor(t, func() bool { return strings.Contains(buf.String(), "https.filter_listen") })

	for range 2 {
		conn, dialErr := dialTCP(t, addr)
		if dialErr != nil {
			t.Fatalf("dial: %v", dialErr)
		}

		_ = conn.Close()

		time.Sleep(20 * time.Millisecond)
	}

	waitFor(t, func() bool { return handled.Load() >= 2 })

	if !strings.Contains(buf.String(), recovery.PanicMessage) {
		t.Error("the panic was not reported")
	}

	cancel()

	select {
	case <-serveErr:
	case <-time.After(5 * time.Second):
		t.Fatal("serveTCP did not return after cancellation")
	}
}

func TestBidirectionalCopyContainsPanicInItsGoroutine(t *testing.T) {
	t.Parallel()

	lg, buf := testLogger()

	client, server := connPair(t)

	_ = server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))

	done := make(chan struct{})

	go func() {
		defer close(done)

		bidirectionalCopy(server, panicOnReadConn{Conn: client}, bytes.NewBuffer(nil), Options{Logger: lg})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("bidirectionalCopy never returned")
	}

	if !strings.Contains(buf.String(), recovery.PanicMessage) {
		t.Errorf("panic in the copy goroutine was not contained: %q", buf.String())
	}
}

type panicOnReadConn struct {
	net.Conn
}

func (panicOnReadConn) Read([]byte) (int, error) {
	panic("dependency panic mid-copy")
}

func listenTCP(t *testing.T, addr string) (net.Listener, error) {
	t.Helper()

	lc := &net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), testTCPNetwork, addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}

	return ln, nil
}

func dialTCP(t *testing.T, addr string) (net.Conn, error) {
	t.Helper()

	d := &net.Dialer{}

	conn, err := d.DialContext(t.Context(), testTCPNetwork, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	return conn, nil
}

func reservedAddr(t *testing.T) string {
	t.Helper()

	ln, err := listenTCP(t, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	addr := ln.Addr().String()

	err = ln.Close()
	if err != nil {
		t.Fatalf("close: %v", err)
	}

	return addr
}

func tcpPortHeld(t *testing.T, addr string) bool {
	t.Helper()

	ln, err := listenTCP(t, addr)
	if err != nil {
		return true
	}

	_ = ln.Close()

	return false
}

func udpPortHeld(addr string) bool {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return true
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return true
	}

	_ = conn.Close()

	return false
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatal("condition was not met within the deadline")
}

func TestServeTCPReleasesThePortBeforeReturning(t *testing.T) {
	t.Parallel()

	lg, _ := testLogger()

	addr := reservedAddr(t)
	handler := func(conn net.Conn, _ *hostMatcher, _ Options) error {
		return conn.Close()
	}

	for round := range 20 {
		ctx, cancel := context.WithCancel(t.Context())

		returned := make(chan error, 1)

		go func() {
			returned <- serveTCP(ctx, addr, lg, handler, newMatcher(nil), Options{Logger: lg}, "https")
		}()

		waitFor(t, func() bool { return tcpPortHeld(t, addr) })

		cancel()

		select {
		case err := <-returned:
			if err != nil {
				t.Fatalf("round %d: serveTCP = %v, want nil on cancellation", round, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: serveTCP did not return after cancellation", round)
		}

		if tcpPortHeld(t, addr) {
			t.Fatalf("round %d: the port was still held when serveTCP returned", round)
		}
	}
}

type closedListener struct {
	attempts atomic.Int64
	addr     net.Addr
}

func (l *closedListener) Accept() (net.Conn, error) {
	l.attempts.Add(1)

	return nil, net.ErrClosed
}

func (l *closedListener) Close() error   { return nil }
func (l *closedListener) Addr() net.Addr { return l.addr }

func TestAcceptLoopReturnsOnAClosedListener(t *testing.T) {
	t.Parallel()

	lg, _ := testLogger()

	ln := &closedListener{addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}}

	handler := func(_ net.Conn, _ *hostMatcher, _ Options) error { return nil }

	returned := make(chan struct{})

	go func() {
		defer close(returned)

		acceptLoop(t.Context(), ln, lg, nil, handler, newMatcher(nil), Options{Logger: lg}, "https")
	}()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("acceptLoop spun on a dead listener instead of handing back to the supervisor")
	}

	if got := ln.attempts.Load(); got != 1 {
		t.Errorf("accept was retried %d times on a closed listener, want 1", got)
	}
}
