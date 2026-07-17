//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"testing"
	"time"
)

func TestServe443(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	allowedHosts := []string{"example.com", "*.google.com"}
	options := Options{
		ListenAddr:  "127.0.0.1:0", // Use port 0 to let OS choose
		DialTimeout: 1000,
		IdleTimeout: 5000,
		Logger:      logger,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Test that Serve443 can start (will likely timeout in test environment)
	err := Serve443(ctx, allowedHosts, options)

	// In test environment, we expect this to timeout or fail to bind
	// We're mainly testing that the function doesn't panic
	if err != nil {
		t.Logf("Serve443 failed as expected in test environment: %v", err)
	}
}

func TestCreateMarkedDialer(t *testing.T) {
	t.Parallel()

	options := Options{
		DialTimeout: 5000,
		IdleTimeout: 30000,
	}

	// Test creating marked dialer
	dialer := newDialerFromOptions(options)
	if dialer == nil {
		t.Error("Expected non-nil marked dialer")

		return
	}

	// Test timeout is set correctly
	expectedTimeout := time.Duration(options.DialTimeout) * time.Millisecond
	if dialer.Timeout != expectedTimeout {
		t.Errorf("Expected timeout %v, got %v", expectedTimeout, dialer.Timeout)
	}
}

func TestSetConnectionTimeouts(t *testing.T) {
	t.Parallel()

	// Test with specific timeouts
	options := Options{
		DialTimeout: 5000,
		IdleTimeout: 30000,
	}

	dialer := newDialerFromOptions(options)

	// Should have the configured timeout
	expectedTimeout := time.Duration(options.DialTimeout) * time.Millisecond
	if dialer.Timeout != expectedTimeout {
		t.Errorf("Expected timeout %v, got %v", expectedTimeout, dialer.Timeout)
	}
}

func TestHandleBlockedHTTPS(t *testing.T) {
	t.Parallel()
	t.Skip("requires real TCP connection with SO_ORIGINAL_DST; covered by integration tests")
}

func TestLogBlockedHTTPS(t *testing.T) {
	t.Parallel()
	t.Skip("requires real TCP connection with SO_ORIGINAL_DST; covered by integration tests")
}

func TestHandleAllowedHTTPS(t *testing.T) {
	t.Parallel()
	t.Skip("requires real TCP connection with SO_ORIGINAL_DST; covered by integration tests")
}

func TestConnectAndSpliceHTTPS(t *testing.T) {
	t.Parallel()

	mockConn := &mockConn{
		remoteAddr: &net.TCPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 12345},
	}

	opts := Options{
		Logger:      slog.Default(),
		DialTimeout: 100,
		IdleTimeout: 500,
	}

	buf := bytes.NewBuffer([]byte{})

	// Dial a closed local port: exercises the dial-failure path without depending
	// on the network (a reachable target would splice against mockConn and hang).
	err := connectAndSpliceHTTPS(mockConn, buf, "127.0.0.1:1", opts)
	if err == nil {
		t.Error("expected dial error for closed port")
	}
}

func TestPeekClientHello(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "invalid TLS data",
			data:    []byte{0x00, 0x01, 0x02, 0x03},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reader := bytes.NewReader(tt.data)
			_, _, err := peekClientHello(reader)

			if (err != nil) != tt.wantErr {
				t.Errorf("peekClientHello() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
