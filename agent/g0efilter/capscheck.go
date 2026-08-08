package g0efilter

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/g0lab/g0efilter/agent/caps"
	"github.com/g0lab/g0efilter/agent/nftables"
)

const capsProbeTimeout = 5 * time.Second

const capsHint = "grant NET_ADMIN to this container " +
	"(Kubernetes: securityContext.capabilities.add, Docker: --cap-add=NET_ADMIN)"

// xattrHint covers the other failure mode: the capability is granted but the
// binary lost its file capabilities somewhere between build and run.
const xattrHint = "if NET_ADMIN is granted, the binary lost its file capabilities " +
	"(check `getcap /app/g0efilter`); rebuild or re-pull the image"

// HandleCaps runs the `caps` subcommand: it reports whether this container can
// program nftables, without starting the filter. Returns handled=true and the
// process exit code.
func HandleCaps(args []string) (bool, int) {
	return handleCaps(args, os.Stdout, os.Stderr)
}

func handleCaps(args []string, out, errOut io.Writer) (bool, int) {
	return handleCapsWith(args, out, errOut, caps.Inspect, nftables.Probe)
}

func handleCapsWith(
	args []string,
	out, errOut io.Writer,
	inspect func() (caps.State, error),
	probe func(context.Context) error,
) (bool, int) {
	if len(args) < 2 || args[1] != "caps" {
		return false, 0
	}

	state, err := inspect()
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "g0efilter: cannot read capabilities: %v\n", err)

		return true, 1
	}

	_, _ = fmt.Fprintf(out, "euid=%d net_admin: effective=%t permitted=%t ambient=%t\n",
		state.EUID, state.Effective, state.Permitted, state.Ambient)

	if !state.Effective {
		_, _ = fmt.Fprintf(errOut, "g0efilter: %v\n", caps.ErrUnavailable)
		_, _ = fmt.Fprintf(errOut, "g0efilter: %s\n", capsHint)
		_, _ = fmt.Fprintf(errOut, "g0efilter: %s\n", xattrHint)

		return true, 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), capsProbeTimeout)
	defer cancel()

	err = probe(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "g0efilter: nftables unreachable: %v\n", err)
		_, _ = fmt.Fprintf(errOut, "g0efilter: the nft binary lost its file capabilities "+
			"(check `getcap $(command -v nft)`)\n")

		return true, 1
	}

	_, _ = fmt.Fprintln(out, "g0efilter: this container can program nftables")

	return true, 0
}

// verifyCapabilities aborts startup when nftables cannot be programmed: running on
// without it would leave the workload silently unfiltered.
func verifyCapabilities(lg *slog.Logger) error {
	state, err := caps.Verify()
	if err != nil {
		lg.Error("startup.capabilities_unusable", "err", err, "hint", capsHint, "xattr_hint", xattrHint)

		return fmt.Errorf("verify capabilities: %w", err)
	}

	lg.Info("startup.capabilities",
		"euid", state.EUID,
		"net_admin_effective", state.Effective,
		"net_admin_ambient", state.Ambient,
	)

	return nil
}

// preflight rejects a configuration that cannot filter before any traffic flows.
func preflight(cfg config, lg *slog.Logger) error {
	return preflightWith(cfg, lg, verifyCapabilities)
}

func preflightWith(cfg config, lg *slog.Logger, verify func(*slog.Logger) error) error {
	err := verify(lg)
	if err != nil {
		return err
	}

	err = validatePorts(cfg, lg)
	if err != nil {
		lg.Error("config.port_validation_failed", "err", err)

		return err
	}

	return nil
}
