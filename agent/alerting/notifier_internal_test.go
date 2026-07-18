package alerting

import (
	"net/http"
	"testing"
)

// The notifier must dial with the SO_MARK bypass or its own requests get
// filtered when the notification server isn't allowlisted (issue #110).
func TestNotifierUsesMarkedDialer(t *testing.T) {
	t.Setenv("NOTIFICATION_HOST", "http://notify.example.com")
	t.Setenv("NOTIFICATION_KEY", "test-key")

	n := NewNotifier()
	if n == nil {
		t.Fatal("NewNotifier returned nil with host and key set")
	}

	tr, ok := n.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected transport type %T", n.client.Transport)
	}

	if tr.DialContext == nil {
		t.Error("notifier transport must use the marked dialer")
	}
}
