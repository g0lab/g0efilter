//nolint:testpackage // Need access to internal implementation details
package filter

import (
	"testing"

	"github.com/g0lab/g0efilter/agent/procinfo"
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

//nolint:exhaustruct
func TestProcFieldsDegradeToUnknown(t *testing.T) {
	t.Parallel()

	if procFields(Options{}, "1.2.3.4", 1234, "tcp") != nil {
		t.Error("no provider means no fields")
	}

	fields := procFields(Options{ProcInfo: stubProc{ok: false}}, "1.2.3.4", 1234, "tcp")
	if len(fields) != 2 || fields[1] != "unknown" {
		t.Errorf("miss must degrade to process_name=unknown, got %v", fields)
	}

	fields = procFields(Options{ProcInfo: stubProc{ok: true}}, "1.2.3.4", 1234, "tcp")
	if len(fields) != 8 || fields[1] != 4242 {
		t.Errorf("hit must carry pid/name/cmdline/executable, got %v", fields)
	}
}

type stubProc struct{ ok bool }

func (s stubProc) Lookup(_ string, _ int, _ string) (procinfo.Info, bool) {
	if !s.ok {
		return procinfo.Info{}, false //nolint:exhaustruct
	}

	return procinfo.Info{PID: 4242, Name: "curl", Cmdline: "curl -sS", Executable: "/usr/bin/curl"}, true
}
