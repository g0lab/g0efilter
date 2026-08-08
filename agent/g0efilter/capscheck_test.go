//nolint:testpackage // Need access to internal implementation details
package g0efilter

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/agent/caps"
)

var (
	errTestCapsInspect = errors.New("read status")
	errTestCapsProbe   = errors.New("netlink denied")
	errTestPreflight   = errors.New("capability rejected")
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

//nolint:funlen // the table keeps every security-relevant verdict in one place
func TestHandleCapsOutcomes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		inspect    func() (caps.State, error)
		probeErr   error
		wantProbe  bool
		wantCode   int
		wantOut    string
		wantErrOut string
	}{
		{
			name: "inspect error",
			inspect: func() (caps.State, error) {
				return caps.State{}, errTestCapsInspect
			},
			wantCode:   1,
			wantErrOut: "cannot read capabilities: read status",
		},
		{
			name: "capability unavailable",
			inspect: func() (caps.State, error) {
				return caps.State{EUID: 1000}, nil
			},
			wantCode:   1,
			wantOut:    "effective=false",
			wantErrOut: "capabilities.add",
		},
		{
			name: "nft probe fails",
			inspect: func() (caps.State, error) {
				return caps.State{EUID: 1000, Effective: true, Permitted: true}, nil
			},
			probeErr:   errTestCapsProbe,
			wantProbe:  true,
			wantCode:   1,
			wantOut:    "effective=true",
			wantErrOut: "nftables unreachable: netlink denied",
		},
		{
			name: "usable",
			inspect: func() (caps.State, error) {
				return caps.State{EUID: 1000, Effective: true, Permitted: true}, nil
			},
			wantProbe: true,
			wantCode:  0,
			wantOut:   "can program nftables",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out, errOut bytes.Buffer

			probeCalled := false
			probe := func(context.Context) error {
				probeCalled = true

				return tc.probeErr
			}

			handled, code := handleCapsWith(
				[]string{"g0efilter", "caps"}, &out, &errOut, tc.inspect, probe,
			)
			if !handled || code != tc.wantCode {
				t.Errorf("handled/code = %t/%d, want true/%d", handled, code, tc.wantCode)
			}

			if !strings.Contains(out.String(), tc.wantOut) {
				t.Errorf("stdout %q omits %q", out.String(), tc.wantOut)
			}

			if !strings.Contains(errOut.String(), tc.wantErrOut) {
				t.Errorf("stderr %q omits %q", errOut.String(), tc.wantErrOut)
			}

			if probeCalled != tc.wantProbe {
				t.Errorf("probe called = %t, want %t", probeCalled, tc.wantProbe)
			}
		})
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

func TestPreflightFailsClosed(t *testing.T) {
	t.Parallel()

	valid := config{mode: "https", httpPort: "65080", httpsPort: "65443", dnsPort: "65053"}
	verifyFailure := func(*slog.Logger) error { return errTestPreflight }

	err := preflightWith(valid, discardLogger(), verifyFailure)
	if !errors.Is(err, errTestPreflight) {
		t.Errorf("preflight capability error = %v, want %v", err, errTestPreflight)
	}

	invalid := valid
	invalid.httpPort = invalid.httpsPort

	err = preflightWith(invalid, discardLogger(), func(*slog.Logger) error { return nil })
	if err == nil {
		t.Error("preflight accepted conflicting proxy ports")
	}

	err = preflightWith(valid, discardLogger(), func(*slog.Logger) error { return nil })
	if err != nil {
		t.Errorf("preflight rejected a usable configuration: %v", err)
	}
}
