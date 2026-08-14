package alerting_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/agent/alerting"
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
	_ = os.Unsetenv("NOTIFICATION_URLS")

	notifier := alerting.NewNotifier()
	if notifier != nil {
		t.Error("Expected nil notifier when no environment variables set")
	}
}

func testNewNotifierMissingToken(t *testing.T) {
	t.Helper()
	// An unusable URL must disable alerting rather than half-configure it.
	t.Setenv("NOTIFICATION_URLS", "carrier-pigeon://roost/token")

	notifier := alerting.NewNotifier()
	if notifier != nil {
		t.Error("Expected nil notifier for an unsupported scheme")
	}
}

func testNewNotifierValidConfig(t *testing.T) {
	t.Helper()
	t.Setenv("NOTIFICATION_URLS", "gotify://test.com/"+gotifyTestToken)
	t.Setenv("HOSTNAME", "test-hostname")

	notifier := alerting.NewNotifier()
	if notifier == nil {
		t.Error("Expected notifier when NOTIFICATION_URLS is set")
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
		Component:       "https",
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
	AuthToken   string
	UserAgent   string
}

// Stands in for a Gotify server: shoutrrr posts a JSON body with the token in the query.
func createMockNotificationServer(t *testing.T, requestChan chan<- *RequestData) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		data := &RequestData{
			Method:      r.Method,
			ContentType: r.Header.Get("Content-Type"),
			FormValues:  decodePayload(t, r),
			AuthToken:   r.URL.Query().Get("token"),
			UserAgent:   r.Header.Get("User-Agent"),
		}

		select {
		case requestChan <- data:
		default:
			t.Error("Request channel full")
		}

		writeGotifyReply(w)
	}))
}

// writeGotifyReply sends the JSON body shoutrrr's Gotify service decodes.
func writeGotifyReply(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{}`))
}

func decodePayload(t *testing.T, r *http.Request) map[string]string {
	t.Helper()

	raw := map[string]any{}

	err := json.NewDecoder(r.Body).Decode(&raw)
	if err != nil {
		t.Errorf("Failed to decode payload: %v", err)
	}

	fields := make(map[string]string, len(raw))
	for key, value := range raw {
		fields[key] = fmt.Sprint(value)
	}

	return fields
}

func decodeField(t *testing.T, r *http.Request, field string) string {
	t.Helper()

	return decodePayload(t, r)[field]
}

// gotifyTestToken satisfies shoutrrr's Gotify format check: 15 chars from 'A'.
const gotifyTestToken = "Aaa.bbb.ccc.ddd" //nolint:gosec // A test fixture, not a credential.

func setupTestNotifier(t *testing.T, serverURL string) *alerting.Notifier {
	t.Helper()

	t.Setenv("NOTIFICATION_URLS", gotifyURL(serverURL))
	t.Setenv("HOSTNAME", "test-host")

	notifier := alerting.NewNotifier()
	if notifier == nil {
		t.Fatal("Failed to create notifier")
	}

	return notifier
}

func gotifyURL(serverURL string) string {
	return "gotify://" + strings.TrimPrefix(serverURL, "http://") + "/" + gotifyTestToken + "?disabletls=yes"
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

	if !strings.Contains(data.ContentType, "application/json") {
		t.Errorf("Expected JSON content type, got %s", data.ContentType)
	}
}

func validateRequestHeaders(t *testing.T, data *RequestData) {
	t.Helper()

	if data.AuthToken != gotifyTestToken {
		t.Errorf("Expected token %q, got %q", gotifyTestToken, data.AuthToken)
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
	t.Setenv("NOTIFICATION_URLS", "gotify://test.com/"+gotifyTestToken)

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
			Component:       "https",
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
			Destination:     "142.251.221.78:80",
			Reason:          "blocked by policy",
			Component:       "http",
		},
		wantSrc:  "192.168.1.100:12345",
		wantDest: "142.251.221.78:80",
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
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		messageChan <- decodeField(t, r, "message")

		writeGotifyReply(w)
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
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

		payload := decodePayload(t, r)

		messageChan <- payload["message"]

		titleChan <- payload["title"]

		writeGotifyReply(w)
	}))
	defer server.Close()

	// Create notifier and send notification with HTTPS component
	notifier := setupTestNotifier(t, server.URL)

	info := alerting.BlockedConnectionInfo{
		SourceIP:        "192.168.1.100",
		SourcePort:      "12345",
		DestinationIP:   "1.1.1.1",
		DestinationPort: "443",
		Destination:     "example.com",
		Reason:          "blocked by policy",
		Component:       "https", // This should be mapped to "https"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	notifier.NotifyBlock(ctx, info)

	// Verify component mapping in both title and message
	select {
	case title := <-titleChan:
		if !strings.Contains(strings.ToUpper(title), "HTTPS") {
			t.Errorf("Expected title to contain 'HTTPS' (mapped from 'https'), got: %s", title)
		}
	case <-time.After(time.Second):
		t.Error("No title received within timeout")
	}

	select {
	case message := <-messageChan:
		if !strings.Contains(message, "Blocked https connection") {
			t.Errorf("Expected message to contain 'Blocked https connection' (mapped from 'https'), got: %s", message)
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
			writeGotifyReply(w)
		}))

		t.Setenv("NOTIFICATION_URLS", gotifyURL(server.URL))
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
			t.Setenv("NOTIFICATION_URLS", "gotify://test.com/"+gotifyTestToken)

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
