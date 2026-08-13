//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"testing"
)

//nolint:exhaustruct
func TestAudited(t *testing.T) {
	t.Parallel()

	if !audited(false, Options{AuditMode: true}) {
		t.Error("not-permitted + audit mode must audit")
	}

	if audited(true, Options{AuditMode: true}) {
		t.Error("permitted traffic is never audited")
	}

	if audited(false, Options{}) {
		t.Error("audit must be off by default")
	}
}

//nolint:exhaustruct
func TestHostPermittedUnchangedByAuditMode(t *testing.T) {
	t.Parallel()

	// AuditMode must not alter the policy decision itself - only what handlers
	// do with a negative decision. A weaker hostPermitted would corrupt the
	// AUDIT/ALLOWED distinction in logs.
	opts := Options{AuditMode: true}

	if hostPermitted("blocked.example.com", []string{"github.com"}, opts) {
		t.Error("audit mode must not make hostPermitted return true")
	}
}
