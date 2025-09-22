//nolint:testpackage // Need access to internal implementation details
package dashboard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIndexHandler(t *testing.T) {
	t.Parallel()

	testCases := getIndexHandlerTestCases()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			handler := IndexHandler(tc.timeout)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			validateIndexHandlerResponse(t, rr)
		})
	}
}

func getIndexHandlerTestCases() []struct {
	name    string
	timeout time.Duration
} {
	return []struct {
		name    string
		timeout time.Duration
	}{
		{"zero timeout", 0},
		{"short timeout", 5 * time.Second},
		{"long timeout", 30 * time.Second},
	}
}

func validateIndexHandlerResponse(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	bodyStr := string(body)
	validateHTMLStructure(t, bodyStr)
	validateHTMLContent(t, bodyStr)
	validateContentType(t, rr)
}

func validateHTMLStructure(t *testing.T, bodyStr string) {
	t.Helper()

	// Check that it's valid HTML
	if !strings.HasPrefix(bodyStr, "<!doctype html>") {
		t.Error("Response should start with HTML doctype")
	}

	// Check for essential HTML elements
	requiredElements := []string{
		"<html>", "<head>", "<title>g0efilter dashboard</title>",
		"<body>", "<header>", "<main>", "</html>",
	}

	for _, element := range requiredElements {
		if !strings.Contains(bodyStr, element) {
			t.Errorf("HTML should contain %q", element)
		}
	}
}

func validateHTMLContent(t *testing.T, bodyStr string) {
	t.Helper()

	// Check for JavaScript and CSS
	if !strings.Contains(bodyStr, "<style>") {
		t.Error("HTML should contain CSS styles")
	}

	if !strings.Contains(bodyStr, "<script>") {
		t.Error("HTML should contain JavaScript")
	}
}

func validateContentType(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()

	contentType := rr.Header().Get("Content-Type")
	if contentType != "text/html; charset=utf-8" {
		t.Errorf("Expected Content-Type 'text/html; charset=utf-8', got %q", contentType)
	}
}

func TestIndexHandlerWithDifferentMethods(t *testing.T) {
	t.Parallel()

	handler := IndexHandler(10 * time.Second)

	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(method, "/", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			// Should return 200 for all methods (it's just serving static HTML)
			if rr.Code != http.StatusOK {
				t.Errorf("Expected status %d for %s method, got %d", http.StatusOK, method, rr.Code)
			}

			// HEAD method should not return body
			if method == "HEAD" {
				body, _ := io.ReadAll(rr.Body)
				if len(body) != 0 {
					// Note: httptest.ResponseRecorder still returns body for HEAD requests
					// This is a limitation of the test framework, not the handler
					t.Logf("HEAD method returned body (httptest limitation): %d bytes", len(body))
				}
			}
		})
	}
}
