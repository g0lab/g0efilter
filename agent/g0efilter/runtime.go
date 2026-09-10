package g0efilter

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/g0lab/g0efilter/agent/policy"
	"github.com/g0lab/g0efilter/shared/actions"
)

const enforcementAudit = "audit"

var errRuntimeConfig = errors.New("invalid runtime configuration")

// datapath is the set of settings the policy document's runtime block replaces as a unit.
type datapath struct {
	mode         string
	dnsUpstreams []string
	auditMode    bool
	dnsHardening bool
	dnsRateQPS   int
	dnsRateBurst int
}

// datapathOf snapshots the environment's settings, so a later policy that drops the
// runtime block reverts to them instead of keeping the last overlay in force.
func datapathOf(cfg config) datapath {
	return datapath{
		mode:         cfg.mode,
		dnsUpstreams: cloneUpstreams(cfg.dnsUpstreams),
		auditMode:    cfg.auditMode,
		dnsHardening: cfg.dnsHardening,
		dnsRateQPS:   cfg.dnsRateQPS,
		dnsRateBurst: cfg.dnsRateBurst,
	}
}

func withDatapath(cfg config, next datapath) config {
	cfg.mode = next.mode
	cfg.dnsUpstreams = cloneUpstreams(next.dnsUpstreams)
	cfg.auditMode = next.auditMode
	cfg.dnsHardening = next.dnsHardening
	cfg.dnsRateQPS = next.dnsRateQPS
	cfg.dnsRateBurst = next.dnsRateBurst

	return cfg
}

// cloneUpstreams keeps the nil/empty distinction: a non-nil empty slice selects resolver discovery.
func cloneUpstreams(upstreams []string) []string {
	if upstreams == nil {
		return nil
	}

	out := make([]string, len(upstreams))
	copy(out, upstreams)

	return out
}

// withRuntime overlays the runtime block, replacing the environment as a unit rather than field by field.
func withRuntime(cfg config, pol *policy.Policy) (config, error) {
	settings := pol.Runtime
	if settings == nil {
		// The block is declarative, so dropping it reverts to the environment rather
		// than leaving the settings a previous policy overlaid still in force.
		return withDatapath(cfg, cfg.bootstrap), nil
	}

	mode, err := runtimeMode(settings.Mode)
	if err != nil {
		return cfg, err
	}

	err = validateEnforcement(settings.Enforcement)
	if err != nil {
		return cfg, err
	}

	err = validateRates(settings.DNSRateQPS, settings.DNSRateBurst)
	if err != nil {
		return cfg, err
	}

	err = validateUpstreams(settings.DNSUpstreams)
	if err != nil {
		return cfg, err
	}

	return withDatapath(cfg, datapath{
		mode:         mode,
		dnsUpstreams: append([]string{}, settings.DNSUpstreams...),
		auditMode:    settings.Enforcement == enforcementAudit,
		dnsHardening: settings.DNSHardening == nil || *settings.DNSHardening,
		dnsRateQPS:   settings.DNSRateQPS,
		dnsRateBurst: settings.DNSRateBurst,
	}), nil
}

func runtimeMode(mode string) (string, error) {
	if mode == "" {
		return actions.ModeHTTPS, nil
	}

	if mode != actions.ModeHTTPS && mode != actions.ModeDNS && mode != actions.ModeDNSStrict {
		return "", fmt.Errorf("%w: mode %q", errRuntimeConfig, mode)
	}

	return mode, nil
}

func validateEnforcement(enforcement string) error {
	if enforcement != "" && enforcement != "block" && enforcement != enforcementAudit {
		return fmt.Errorf("%w: enforcement %q", errRuntimeConfig, enforcement)
	}

	return nil
}

func validateRates(qps, burst int) error {
	if qps < 0 || burst < 0 {
		return fmt.Errorf("%w: DNS rate limits must not be negative", errRuntimeConfig)
	}

	return nil
}

func validateUpstreams(upstreams []string) error {
	for _, upstream := range upstreams {
		host, port, err := net.SplitHostPort(upstream)
		if err != nil || host == "" {
			return fmt.Errorf("%w: DNS upstream %q must be host:port", errRuntimeConfig, upstream)
		}

		number, convErr := strconv.Atoi(port)
		if convErr != nil || number < 1 || number > 65535 {
			return fmt.Errorf("%w: DNS upstream %q must be host:port", errRuntimeConfig, upstream)
		}
	}

	return nil
}
