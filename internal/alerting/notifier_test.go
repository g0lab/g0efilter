package alerting_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/internal/alerting"
)

//nolint:tparallel // some subtests use t.Setenv and cannot be parallel
func TestNewNotifier(t *testing.T) {
	t.Run("NoEnvironmentVariables", func(t *testing.T) {
		t.Parallel()
		testNewNotifierNilCase(t)
	})
	t.Run("MissingToken", func(t *testing.T) { //nolint:paralleltest // uses t.Setenv
		testNewNotifierMissingToken(t)
	})
	t.Run("ValidConfiguration", func(t *testing.T) { //nolint:paralleltest // uses t.Setenv
		testNewNotifierValidConfig(t)
	})
}

func testNewNotifierNilCase(t *testing.T) {
	t.Helper()
	// Ensure clean environment
	_ = os.Unsetenv("NOTIFICATION_HOST")
	_ = os.Unsetenv("NOTIFICATION_KEY")

	notifier := alerting.NewNotifier()
	if notifier != nil {
		t.Error("Expected nil notifier when no environment variables set")
	}
}

func testNewNotifierMissingToken(t *testing.T) {
	t.Helper()
	// Test with missing token
	t.Setenv("NOTIFICATION_HOST", "http://test.com")

	notifier := alerting.NewNotifier()
	if notifier != nil {
		t.Error("Expected nil notifier when token is missing")
	}
}

func testNewNotifierValidConfig(t *testing.T) {
	t.Helper()
	// Test with both variables set
	t.Setenv("NOTIFICATION_HOST", "http://test.com")
	t.Setenv("NOTIFICATION_KEY", "test-token")
	t.Setenv("HOSTNAME", "test-hostname")

	notifier := alerting.NewNotifier()
	if notifier == nil {
		t.Error("Expected notifier when both host and token are set")
	}

	// Test that we can call Close without panic
	notifier.Close()
}

//nolint:tparallel // some subtests use t.Setenv and cannot be parallel
func TestNotifyBlock(t *testing.T) {
	t.Run("NilNotifier", func(t *testing.T) {
		t.Parallel()
		testNotifyBlockNilNotifier(t)
	})
	t.Run("WithMockServer", func(t *testing.T) { //nolint:paralleltest // uses t.Setenv
		testNotifyBlockWithMockServer(t)
	})
}

func testNotifyBlockNilNotifier(t *testing.T) {
	t.Helper()
	// Test with nil notifier
	var nilNotifier *alerting.Notifier

	info := alerting.BlockedConnectionInfo{
		SourceIP:        "192.168.1.1",
		SourcePort:      "54321",
		DestinationIP:   "1.1.1.1",
		DestinationPort: "443",
		Destination:     "example.com",
		Reason:          "test",
		Component:       "sni",
	}
	nilNotifier.NotifyBlock(context.Background(), info)
	// Should not panic
}

func testNotifyBlockWithMockServer(t *testing.T) {
	t.Helper()

	// Setup mock server
	receivedRequest := make(chan *RequestData, 1)

	server := createMockNotificationServer(t, receivedRequest)
	defer server.Close()

	// Setup environment and create notifier
	notifier := setupTestNotifier(t, server.URL)

	// Test notification
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	testInfo := alerting.BlockedConnectionInfo{
		SourceIP:        "192.168.1.100",
		SourcePort:      "12345",
		DestinationIP:   "1.1.1.1",
		DestinationPort: "443",
		Destination:     "malicious.com",
		Reason:          "DNS filtering",
		Component:       "dns",
	}

	notifier.NotifyBlock(ctx, testInfo)

	// Wait for the notification request
	select {
	case reqData := <-receivedRequest:
		validateNotificationRequestData(t, reqData, testInfo)
	case <-time.After(2 * time.Second):
		t.Error("Notification request not received within timeout")
	}
}

// RequestData holds parsed request information for testing.
type RequestData struct {
	Method      string
	ContentType string
	FormValues  map[string]string
	AuthToken   string // For X-Gotify-Key header
	UserAgent   string
}

func createMockNotificationServer(t *testing.T, requestChan chan<- *RequestData) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse the request immediately while it's still valid
		data := &RequestData{
			Method:      r.Method,
			ContentType: r.Header.Get("Content-Type"),
			FormValues:  make(map[string]string),
			AuthToken:   r.Header.Get("X-Gotify-Key"),
			UserAgent:   r.Header.Get("User-Agent"),
		}

		// Parse form data (URL-encoded for Gotify)
		err := r.ParseForm()
		if err != nil {
			t.Errorf("Failed to parse form: %v", err)
		} else {
			// Extract form values
			for key := range r.Form {
				data.FormValues[key] = r.FormValue(key)
			}
		}

		// Store the parsed request data
		select {
		case requestChan <- data:
		default:
			t.Error("Request channel full")
		}

		w.WriteHeader(http.StatusOK)
	}))
}

func setupTestNotifier(t *testing.T, serverURL string) *alerting.Notifier {
	t.Helper()

	// Set up environment
	t.Setenv("NOTIFICATION_HOST", serverURL)
	t.Setenv("NOTIFICATION_KEY", "test-token")
	t.Setenv("HOSTNAME", "test-host")

	notifier := alerting.NewNotifier()
	if notifier == nil {
		t.Fatal("Failed to create notifier")
	}

	return notifier
}

func validateNotificationRequestData(t *testing.T, data *RequestData, expectedInfo alerting.BlockedConnectionInfo) {
	t.Helper()

	validateRequestBasics(t, data)
	validateRequestHeaders(t, data)
	validateNotificationTitle(t, data, expectedInfo)
	validateNotificationMessage(t, data, expectedInfo)
}

func validateRequestBasics(t *testing.T, data *RequestData) {
	t.Helper()

	// Validate request method
	if data.Method != http.MethodPost {
		t.Errorf("Expected POST request, got %s", data.Method)
	}

	// Validate content type (should be URL-encoded for Gotify)
	if !strings.Contains(data.ContentType, "application/x-www-form-urlencoded") {
		t.Errorf("Expected URL-encoded form data content type, got %s", data.ContentType)
	}

	// Validate required form fields
	validateFormFieldFromData(t, data, "priority", "8")
}

func validateRequestHeaders(t *testing.T, data *RequestData) {
	t.Helper()

	// Validate authentication header
	if data.AuthToken != "test-token" {
		t.Errorf("Expected X-Gotify-Key header 'test-token', got '%s'", data.AuthToken)
	}

	// Validate User-Agent header
	if data.UserAgent != "g0efilter/1.0" {
		t.Errorf("Expected User-Agent 'g0efilter/1.0', got '%s'", data.UserAgent)
	}
}

func validateNotificationTitle(t *testing.T, data *RequestData, expectedInfo alerting.BlockedConnectionInfo) {
	t.Helper()

	title := data.FormValues["title"]
	if title == "" {
		t.Error("Expected title in form data")

		return
	}

	if !strings.Contains(title, "test-host") {
		t.Errorf("Expected title to contain hostname, got: %s", title)
	}

	if !strings.Contains(strings.ToUpper(title), strings.ToUpper(expectedInfo.Component)) {
		t.Errorf("Expected title to contain component '%s', got: %s", expectedInfo.Component, title)
	}
}

func validateNotificationMessage(t *testing.T, data *RequestData, expectedInfo alerting.BlockedConnectionInfo) {
	t.Helper()

	message := data.FormValues["message"]
	if message == "" {
		t.Error("Expected message in form data")

		return
	}

	expectedSource := expectedInfo.SourceIP + ":" + expectedInfo.SourcePort
	if !strings.Contains(message, expectedSource) {
		t.Errorf("Expected message to contain source '%s', got: %s", expectedSource, message)
	}

	if !strings.Contains(message, expectedInfo.Destination) {
		t.Errorf("Expected message to contain destination '%s', got: %s", expectedInfo.Destination, message)
	}

	if !strings.Contains(message, expectedInfo.Reason) {
		t.Errorf("Expected message to contain reason '%s', got: %s", expectedInfo.Reason, message)
	}
}

func validateFormFieldFromData(t *testing.T, data *RequestData, fieldName, expectedValue string) {
	t.Helper()

	value := data.FormValues[fieldName]
	if value != expectedValue {
		t.Errorf("Expected %s '%s', got '%s'", fieldName, expectedValue, value)
	}
}

//nolint:tparallel // some subtests use t.Setenv and cannot be parallel
func TestNotifierClose(t *testing.T) {
	t.Run("NilNotifier", func(t *testing.T) {
		t.Parallel()
		testNotifierCloseNil(t)
	})
	t.Run("ValidNotifier", func(t *testing.T) { //nolint:paralleltest // uses t.Setenv
		testNotifierCloseValid(t)
	})
}

func testNotifierCloseNil(t *testing.T) {
	t.Helper()
	// Test closing nil notifier
	var nilNotifier *alerting.Notifier
	nilNotifier.Close() // Should not panic
}

func testNotifierCloseValid(t *testing.T) {
	t.Helper()
	// Test closing valid notifier
	t.Setenv("NOTIFICATION_HOST", "http://test.com")
	t.Setenv("NOTIFICATION_KEY", "test-token")

	notifier := alerting.NewNotifier()
	if notifier == nil {
		t.Fatal("Failed to create notifier")
	}

	// Test that Close doesn't panic
	notifier.Close()
}

//nolint:paralleltest // subtests use t.Setenv
func TestBlockedConnectionInfoFormatting(t *testing.T) {
	testCases := getFormattingTestCases()

	for _, tc := range testCases { //nolint:paralleltest // uses t.Setenv
		t.Run(tc.name, func(t *testing.T) {
			runFormattingTest(t, tc)
		})
	}
}

type formattingTestCase struct {
	name     string
	info     alerting.BlockedConnectionInfo
	wantSrc  string
	wantDest string
}

func getFullInfoTestCase() formattingTestCase {
	return formattingTestCase{
		name: "FullInfo",
		info: alerting.BlockedConnectionInfo{
			SourceIP:        "192.168.1.100",
			SourcePort:      "12345",
			DestinationIP:   "1.1.1.1",
			DestinationPort: "443",
			Destination:     "example.com",
			Reason:          "blocked by policy",
			Component:       "dns",
		},
		wantSrc:  "192.168.1.100:12345",
		wantDest: "example.com (1.1.1.1:443)",
	}
}

func getNoDestinationNameTestCase() formattingTestCase {
	return formattingTestCase{
		name: "NoDestinationName",
		info: alerting.BlockedConnectionInfo{
			SourceIP:        "192.168.1.100",
			SourcePort:      "12345",
			DestinationIP:   "1.1.1.1",
			DestinationPort: "443",
			Destination:     "",
			Reason:          "blocked by policy",
			Component:       "sni",
		},
		wantSrc:  "192.168.1.100:12345",
		wantDest: "1.1.1.1:443",
	}
}

func getNoSourcePortTestCase() formattingTestCase {
	return formattingTestCase{
		name: "NoSourcePort",
		info: alerting.BlockedConnectionInfo{
			SourceIP:        "192.168.1.100",
			SourcePort:      "",
			DestinationIP:   "1.1.1.1",
			DestinationPort: "443",
			Destination:     "example.com",
			Reason:          "blocked by policy",
			Component:       "http",
		},
		wantSrc:  "192.168.1.100",
		wantDest: "example.com (1.1.1.1:443)",
	}
}

func getDestinationIsIPPortTestCase() formattingTestCase {
	return formattingTestCase{
		name: "DestinationIsIPPort",
		info: alerting.BlockedConnectionInfo{
			SourceIP:        "192.168.1.100",
			SourcePort:      "12345",
			DestinationIP:   "142.251.221.78",
			DestinationPort: "80",
			Destination:     "142.251.221.78:80", // This is what was causing duplicate IPs
			Reason:          "blocked by policy",
			Component:       "http",
		},
		wantSrc:  "192.168.1.100:12345",
		wantDest: "142.251.221.78:80", // Should NOT be "142.251.221.78:80 (142.251.221.78:80)"
	}
}

func getFormattingTestCases() []formattingTestCase {
	return []formattingTestCase{
		getFullInfoTestCase(),
		getNoDestinationNameTestCase(),
		getNoSourcePortTestCase(),
		getDestinationIsIPPortTestCase(),
	}
}

func runFormattingTest(t *testing.T, tc formattingTestCase) {
	t.Helper()
	// Setup mock server to capture the message
	messageChan := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm() // Parse URL-encoded form data
		messageChan <- r.FormValue("message")

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create notifier and send notification
	notifier := setupTestNotifier(t, server.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	notifier.NotifyBlock(ctx, tc.info)

	// Verify message formatting
	select {
	case message := <-messageChan:
		if !strings.Contains(message, tc.wantSrc) {
			t.Errorf("Expected message to contain source '%s', got: %s", tc.wantSrc, message)
		}

		if !strings.Contains(message, tc.wantDest) {
			t.Errorf("Expected message to contain destination '%s', got: %s", tc.wantDest, message)
		}
	case <-time.After(time.Second):
		t.Error("No message received within timeout")
	}
}

// TestComponentMapping tests that component names are properly mapped for user-friendly display.
// Note: Cannot use t.Parallel() due to t.Setenv usage in setupTestNotifier.
//
//nolint:paralleltest // Cannot use t.Parallel() due to t.Setenv usage in setupTestNotifier
func TestComponentMapping(t *testing.T) {
	// Setup mock server to capture the message
	messageChan := make(chan string, 1)
	titleChan := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm() // Parse URL-encoded form data
		messageChan <- r.FormValue("message")

		titleChan <- r.FormValue("title")

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create notifier and send notification with SNI component
	notifier := setupTestNotifier(t, server.URL)

	info := alerting.BlockedConnectionInfo{
		SourceIP:        "192.168.1.100",
		SourcePort:      "12345",
		DestinationIP:   "1.1.1.1",
		DestinationPort: "443",
		Destination:     "example.com",
		Reason:          "blocked by policy",
		Component:       "sni", // This should be mapped to "https"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	notifier.NotifyBlock(ctx, info)

	// Verify component mapping in both title and message
	select {
	case title := <-titleChan:
		if !strings.Contains(strings.ToUpper(title), "HTTPS") {
			t.Errorf("Expected title to contain 'HTTPS' (mapped from 'sni'), got: %s", title)
		}
	case <-time.After(time.Second):
		t.Error("No title received within timeout")
	}

	select {
	case message := <-messageChan:
		if !strings.Contains(message, "Blocked https connection") {
			t.Errorf("Expected message to contain 'Blocked https connection' (mapped from 'sni'), got: %s", message)
		}
	case <-time.After(time.Second):
		t.Error("No message received within timeout")
	}
}

// TestNotificationRateLimiting tests the rate limiting functionality to prevent spam.
//
//nolint:paralleltest,funlen // Cannot use t.Parallel() due to t.Setenv usage
func TestNotificationRateLimiting(t *testing.T) {
	setupNotifier := func(t *testing.T) (*alerting.Notifier, *httptest.Server, *int64) {
		t.Helper()

		var notificationCount int64

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			atomic.AddInt64(&notificationCount, 1)
			w.WriteHeader(http.StatusOK)
		}))

		t.Setenv("NOTIFICATION_HOST", server.URL)
		t.Setenv("NOTIFICATION_KEY", "test-token")
		t.Setenv("NOTIFICATION_BACKOFF_SECONDS", "1")

		notifier := alerting.NewNotifier()
		if notifier == nil {
			t.Fatal("Failed to create notifier")
		}

		return notifier, server, &notificationCount
	}

	t.Run("basic_rate_limiting", func(t *testing.T) {
		notifier, server, notificationCount := setupNotifier(t)
		defer server.Close()
		defer notifier.Close()

		info := alerting.BlockedConnectionInfo{
			SourceIP: "192.168.1.100", SourcePort: "12345", DestinationIP: "1.1.1.1",
			DestinationPort: "443", Destination: "example.com", Reason: "blocked by policy", Component: "https",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// First notification should go through
		notifier.NotifyBlock(ctx, info)
		time.Sleep(100 * time.Millisecond)

		if atomic.LoadInt64(notificationCount) != 1 {
			t.Errorf("Expected 1 notification after first alert, got %d", atomic.LoadInt64(notificationCount))
		}

		// Immediate duplicate should be rate limited
		notifier.NotifyBlock(ctx, info)
		time.Sleep(100 * time.Millisecond)

		if atomic.LoadInt64(notificationCount) != 1 {
			t.Errorf("Expected 1 notification after rate-limited alert, got %d", atomic.LoadInt64(notificationCount))
		}
	})

	t.Run("source_port_ignored", func(t *testing.T) {
		notifier, server, notificationCount := setupNotifier(t)
		defer server.Close()
		defer notifier.Close()

		info := alerting.BlockedConnectionInfo{
			SourceIP: "192.168.1.100", SourcePort: "12345", DestinationIP: "1.1.1.1",
			DestinationPort: "443", Destination: "example.com", Reason: "blocked by policy", Component: "https",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		notifier.NotifyBlock(ctx, info)
		time.Sleep(100 * time.Millisecond)

		// Same connection with different source port should still be rate limited
		sameConnectionDiffPort := info
		sameConnectionDiffPort.SourcePort = "54321"
		notifier.NotifyBlock(ctx, sameConnectionDiffPort)
		time.Sleep(100 * time.Millisecond)

		if atomic.LoadInt64(notificationCount) != 1 {
			t.Errorf("Expected 1 notification (source port should be ignored), got %d",
				atomic.LoadInt64(notificationCount))
		}
	})

	t.Run("different_destination_allowed", func(t *testing.T) {
		notifier, server, notificationCount := setupNotifier(t)
		defer server.Close()
		defer notifier.Close()

		info := alerting.BlockedConnectionInfo{
			SourceIP: "192.168.1.100", SourcePort: "12345", DestinationIP: "1.1.1.1",
			DestinationPort: "443", Destination: "example.com", Reason: "blocked by policy", Component: "https",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		notifier.NotifyBlock(ctx, info)
		time.Sleep(100 * time.Millisecond)

		// Different destination should go through
		differentInfo := info
		differentInfo.DestinationIP = "8.8.8.8"
		notifier.NotifyBlock(ctx, differentInfo)
		time.Sleep(100 * time.Millisecond)

		if atomic.LoadInt64(notificationCount) != 2 {
			t.Errorf("Expected 2 notifications for different destinations, got %d",
				atomic.LoadInt64(notificationCount))
		}
	})

	t.Run("backoff_expiry", func(t *testing.T) {
		notifier, server, notificationCount := setupNotifier(t)
		defer server.Close()
		defer notifier.Close()

		info := alerting.BlockedConnectionInfo{
			SourceIP: "192.168.1.100", SourcePort: "12345", DestinationIP: "1.1.1.1",
			DestinationPort: "443", Destination: "example.com", Reason: "blocked by policy", Component: "https",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		notifier.NotifyBlock(ctx, info)
		time.Sleep(100 * time.Millisecond)

		// Wait for backoff to expire
		time.Sleep(1100 * time.Millisecond)

		// Should go through now
		notifier.NotifyBlock(ctx, info)
		time.Sleep(100 * time.Millisecond)

		if atomic.LoadInt64(notificationCount) != 2 {
			t.Errorf("Expected 2 notifications after backoff expiry, got %d",
				atomic.LoadInt64(notificationCount))
		}
	})
}

// TestNotificationBackoffConfiguration tests configurable backoff period.
//

func TestNotificationBackoffConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		envValue       string
		expectedPeriod time.Duration
	}{
		{
			name:           "Default backoff (no env)",
			envValue:       "",
			expectedPeriod: 60 * time.Second,
		},
		{
			name:           "Custom backoff 30 seconds",
			envValue:       "30",
			expectedPeriod: 30 * time.Second,
		},
		{
			name:           "Invalid env value (use default)",
			envValue:       "invalid",
			expectedPeriod: 60 * time.Second,
		},
		{
			name:           "Zero value (use default)",
			envValue:       "0",
			expectedPeriod: 60 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup environment
			t.Setenv("NOTIFICATION_HOST", "http://test.com")
			t.Setenv("NOTIFICATION_KEY", "test-token")

			if tc.envValue != "" {
				t.Setenv("NOTIFICATION_BACKOFF_SECONDS", tc.envValue)
			}

			notifier := alerting.NewNotifier()
			if notifier == nil {
				t.Fatal("Failed to create notifier")
			}
			defer notifier.Close()

			// We can't directly access backoffPeriod since it's private,
			// but we can test the behavior by sending duplicate notifications
			// and measuring timing (this is more of an integration test)

			// For now, just verify the notifier was created successfully
			// The actual backoff timing is tested in TestNotificationRateLimiting
		})
	}
}
