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

// withRuntime overlays the runtime block, replacing the environment as a unit rather than field by field.
func withRuntime(cfg config, pol *policy.Policy) (config, error) {
	settings := pol.Runtime
	if settings == nil {
		return cfg, nil
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

	cfg.mode = mode
	cfg.auditMode = settings.Enforcement == enforcementAudit
	cfg.dnsUpstreams = append([]string{}, settings.DNSUpstreams...)
	cfg.dnsHardening = settings.DNSHardening == nil || *settings.DNSHardening
	cfg.dnsRateQPS = settings.DNSRateQPS
	cfg.dnsRateBurst = settings.DNSRateBurst

	return cfg, nil
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
