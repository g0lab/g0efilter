//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/agent/caps"
)

// netAdminEffective reports what the test environment can actually do, so the
// assertions below hold whether or not the suite runs with CAP_NET_ADMIN.
func netAdminEffective(t *testing.T) bool {
	t.Helper()

	state, err := caps.Inspect()
	if err != nil {
		t.Fatalf("inspect capabilities: %v", err)
	}

	return state.Effective
}

func TestHandleCapsIgnoresOtherCommands(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"g0efilter"},
		{"g0efilter", "healthcheck"},
		{"g0efilter", "--version"},
		{"g0efilter", "capsule"},
	} {
		var out, errOut bytes.Buffer

		handled, code := handleCaps(args, &out, &errOut)
		if handled {
			t.Errorf("args %v were handled as the caps subcommand", args)
		}

		if code != 0 {
			t.Errorf("args %v returned exit code %d, want 0", args, code)
		}

		if out.Len() != 0 || errOut.Len() != 0 {
			t.Errorf("args %v produced output: %q %q", args, out.String(), errOut.String())
		}
	}
}

func TestHandleCapsAlwaysReportsTheCapabilityState(t *testing.T) {
	t.Parallel()

	var out, errOut bytes.Buffer

	handled, _ := handleCaps([]string{"g0efilter", "caps"}, &out, &errOut)
	if !handled {
		t.Fatal("the caps subcommand was not handled")
	}

	// The summary is printed before any verdict so a failing preflight still shows
	// which capability sets were actually granted.
	for _, want := range []string{"euid=", "effective=", "permitted=", "ambient="} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("capability summary missing %q: %q", want, out.String())
		}
	}
}

func TestHandleCapsFailsWithActionableHints(t *testing.T) {
	t.Parallel()

	if netAdminEffective(t) {
		t.Skip("this environment has CAP_NET_ADMIN; the failure path cannot be reached")
	}

	var out, errOut bytes.Buffer

	_, code := handleCaps([]string{"g0efilter", "caps"}, &out, &errOut)
	if code != 1 {
		t.Errorf("exit code %d without NET_ADMIN, want 1", code)
	}

	// The hints are the whole point of the subcommand: without them a failure looks
	// like a bug rather than a securityContext or an image to fix.
	for _, want := range []string{"capabilities.add", "getcap"} {
		if !strings.Contains(errOut.String(), want) {
			t.Errorf("failure output omits %q: %q", want, errOut.String())
		}
	}
}

func TestVerifyCapabilitiesMatchesTheEnvironment(t *testing.T) {
	t.Parallel()

	lg := slog.New(slog.DiscardHandler)

	err := verifyCapabilities(lg)

	if netAdminEffective(t) && err != nil {
		t.Errorf("startup rejected a usable environment: %v", err)
	}

	if !netAdminEffective(t) && err == nil {
		t.Error("startup accepted an environment without effective CAP_NET_ADMIN")
	}
}
