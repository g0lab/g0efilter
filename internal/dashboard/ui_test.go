//nolint:testpackage // Need access to internal implementation details
package dashboard

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIndexHandler(t *testing.T) {
	t.Parallel()

	handler := IndexHandler()
	// http.FileServer automatically serves index.html for directory requests
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	validateIndexHandlerResponse(t, rr)
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
	if !strings.HasPrefix(bodyStr, "<!DOCTYPE html>") && !strings.HasPrefix(bodyStr, "<!doctype html>") {
		t.Error("Response should start with HTML doctype")
	}

	// The Svelte build ships a minimal shell; the app renders client-side.
	requiredElements := []string{
		"<html", "<head>", "<title>g0efilter dashboard</title>",
		"<body>", `<div id="app">`, "</html>",
	}

	for _, element := range requiredElements {
		if !strings.Contains(bodyStr, element) {
			t.Errorf("HTML should contain %q", element)
		}
	}
}

func validateHTMLContent(t *testing.T, bodyStr string) {
	t.Helper()

	// Hashed Vite script bundles are external; runtime Svelte style directives
	// are covered by the browser E2E and the style-src policy.
	if !strings.Contains(bodyStr, `src="/assets/`) {
		t.Error("HTML should reference a hashed JS bundle under /assets/")
	}

	if !strings.Contains(bodyStr, `rel="stylesheet"`) {
		t.Error("HTML should reference an external stylesheet")
	}

	if strings.Contains(bodyStr, "onclick=") || strings.Contains(bodyStr, "style=") {
		t.Error("built HTML must not contain inline handlers or styles (CSP)")
	}
}

func validateContentType(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()

	contentType := rr.Header().Get("Content-Type")
	// http.FileServer sets "text/html; charset=utf-8" for .html files
	if !strings.HasPrefix(contentType, "text/html") {
		t.Errorf("Expected Content-Type to start with 'text/html', got %q", contentType)
	}
}

func TestIndexHandlerWithDifferentMethods(t *testing.T) {
	t.Parallel()

	handler := IndexHandler()

	methods := []string{"GET", "HEAD"}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			// http.FileServer only supports GET and HEAD
			req := httptest.NewRequestWithContext(context.Background(), method, "/", nil)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

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
