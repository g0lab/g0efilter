package logging_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/g0lab/g0efilter/internal/logging"
)

func TestAlertingIntegration(t *testing.T) {
	// Test that BLOCKED events trigger notifications when alerting is configured

	// Set up mock notification server
	notificationReceived := make(chan bool, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validateNotificationRequest(t, r)
		w.WriteHeader(http.StatusOK)

		notificationReceived <- true
	}))
	defer server.Close()

	// Configure environment for alerting
	t.Setenv("NOTIFICATION_HOST", server.URL)
	t.Setenv("NOTIFICATION_KEY", "test-token-123")
	t.Setenv("HOSTNAME", "test-g0efilter")

	// Create logger with alerting enabled
	logger := logging.NewWithFormat("DEBUG", "json", io.Discard, false, "test-version")

	// Test BLOCKED event
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logger.InfoContext(ctx, "dns.blocked",
		"component", "dns",
		"action", "BLOCKED",
		"qname", "malicious.com",
		"qtype", "A",
		"source_ip", "192.168.1.100",
		"source_port", 12345,
		"destination_ip", "8.8.8.8",
		"destination_port", 53,
		"reason", "DNS filtering",
		"flow_id", "test-flow-123",
	)

	// Wait for notification
	select {
	case <-notificationReceived:
		// Success
	case <-time.After(2 * time.Second):
		t.Error("Notification was not received within timeout")
	}
}

func validateNotificationRequest(t *testing.T, r *http.Request) {
	t.Helper()

	if r.Method != http.MethodPost {
		t.Errorf("Expected POST request, got %s", r.Method)

		return
	}

	err := r.ParseForm()
	if err != nil {
		t.Errorf("Failed to parse form: %v", err)

		return
	}

	// Validate content type
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/x-www-form-urlencoded") {
		t.Errorf("Expected URL-encoded form, got %s", contentType)

		return
	}

	// Validate authentication header
	authToken := r.Header.Get("X-Gotify-Key")
	if authToken != "test-token-123" {
		t.Errorf("Expected X-Gotify-Key 'test-token-123', got '%s'", authToken)

		return
	}

	validateFormFields(t, r)
	validateMessageContent(t, r)
}

func validateFormFields(t *testing.T, r *http.Request) {
	t.Helper()

	// Token is now in X-Gotify-Key header, not form data

	if r.FormValue("title") == "" {
		t.Error("Expected title in form data")
	}

	if r.FormValue("message") == "" {
		t.Error("Expected message in form data")
	}

	if r.FormValue("priority") != "8" {
		t.Error("Expected priority 8 in form data")
	}
}

func validateMessageContent(t *testing.T, r *http.Request) {
	t.Helper()

	message := r.FormValue("message")
	title := r.FormValue("title")

	expectedContents := []struct {
		field   string
		value   string
		inMsg   bool
		inTitle bool
	}{
		{"source IP:port", "192.168.1.100:12345", true, false},
		{"destination hostname", "malicious.com", true, false},
		{"destination IP:port", "8.8.8.8:53", true, false},
		{"reason", "DNS filtering", true, false},
		{"component", "DNS", false, true},
		{"hostname", "test-g0efilter", false, true},
	}

	for _, expected := range expectedContents {
		if expected.inMsg && !strings.Contains(message, expected.value) {
			t.Errorf("Expected %s '%s' in message, got: %s", expected.field, expected.value, message)
		}

		if expected.inTitle && !strings.Contains(title, expected.value) {
			t.Errorf("Expected %s '%s' in title, got: %s", expected.field, expected.value, title)
		}
	}
}

func TestAlertingDisabled(t *testing.T) {
	// Test that no notifications are sent when alerting is not configured
	t.Parallel()

	// Create logger without alerting configuration
	logger := logging.NewWithFormat("DEBUG", "json", io.Discard, false, "test-version")

	// Test BLOCKED event - should not panic or cause errors
	logger.Info("dns.blocked",
		"component", "dns",
		"action", "BLOCKED",
		"qname", "malicious.com",
		"source_ip", "192.168.1.100",
		"reason", "DNS filtering",
	)

	// Test passes if no panic occurs
}

func TestAlertingOnlyBlockedEvents(t *testing.T) {
	// Test that only BLOCKED events trigger notifications
	var notificationCount int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&notificationCount, 1)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Configure alerting
	t.Setenv("NOTIFICATION_HOST", server.URL)
	t.Setenv("NOTIFICATION_KEY", "test-token")

	logger := logging.NewWithFormat("DEBUG", "json", io.Discard, false, "test-version")

	// Test various actions - only BLOCKED should trigger notification
	testCases := []struct {
		action   string
		expected bool
	}{
		{"BLOCKED", true},
		{"ALLOWED", false},
		{"REDIRECTED", false},
		{"ERROR", false},
		{"blocked", true}, // case insensitive
	}

	for i, tc := range testCases {
		atomic.StoreInt64(&notificationCount, 0)

		// Use different IPs for each test case to avoid rate limiting
		sourceIP := fmt.Sprintf("192.168.1.%d", i+1)
		destIP := fmt.Sprintf("10.0.0.%d", i+1)

		logger.Info("test.event",
			"action", tc.action,
			"source_ip", sourceIP,
			"destination_ip", destIP,
		)

		// Give some time for potential notification
		time.Sleep(50 * time.Millisecond)

		count := atomic.LoadInt64(&notificationCount)
		if tc.expected && count == 0 {
			t.Errorf("Expected notification for action %s but none received", tc.action)
		}

		if !tc.expected && count > 0 {
			t.Errorf("Unexpected notification for action %s", tc.action)
		}
	}
}
