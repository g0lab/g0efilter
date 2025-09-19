// Package policy parses and validates the allowlist policy file used by g0efilter.
package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"unicode"

	"github.com/goccy/go-yaml"
	"golang.org/x/net/idna"
)

var (
	errInvalidIP     = errors.New("invalid IP address")
	errInvalidDomain = errors.New("invalid domain pattern")
)

const maxDomainLength = 253

//nolint:cyclop
func validateIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("%w: empty", errInvalidIP)
	}

	// reject host:port (e.g. 1.2.3.4:80)
	if i := strings.LastIndexByte(ip, ':'); i != -1 && strings.Count(ip, ":") == 1 && strings.Contains(ip, ".") {
		return fmt.Errorf("%w (contains port): %s", errInvalidIP, ip)
	}

	// CIDR
	if strings.Contains(ip, "/") {
		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("%w range: %s", errInvalidIP, ip)
		}

		if ipnet.IP.To4() == nil {
			return fmt.Errorf("%w: IPv6 not allowed: %s", errInvalidIP, ip)
		}

		return nil
	}

	// Plain IPv4
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		if parsed != nil {
			return fmt.Errorf("%w: IPv6 not allowed: %s", errInvalidIP, ip)
		}

		return fmt.Errorf("%w: %s", errInvalidIP, ip)
	}

	return nil
}

// Domain patterns: "*", "example.com", "*.example.com".
func validateDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("%w: empty", errInvalidDomain)
	}

	if domain == "*" {
		return nil
	}

	orig := domain

	// Wildcard handling
	if strings.HasPrefix(domain, "*.") {
		domain = strings.TrimPrefix(domain, "*.")
		if domain == "" {
			return fmt.Errorf("%w: %s", errInvalidDomain, orig)
		}
	}

	// Single trailing dot is fine
	domain = strings.TrimSuffix(domain, ".")

	// No other '*' anywhere
	if strings.Contains(domain, "*") {
		return fmt.Errorf("%w: %s", errInvalidDomain, orig)
	}

	// Convert to ASCII and perform basic structural checks
	ascii, err := domainToASCII(domain, orig)
	if err != nil {
		return err
	}

	// Validate labels and TLD rules
	err = validateDomainLabels(ascii, orig)
	if err != nil {
		return err
	}

	return nil
}

// domainToASCII converts input to ASCII using IDNA and performs basic
// structural checks (length, dot placement, IP-literal rejection).
func domainToASCII(domain, orig string) (string, error) {
	ascii, err := idna.Lookup.ToASCII(domain)
	if err != nil || ascii == "" {
		return "", fmt.Errorf("%w: %s", errInvalidDomain, orig)
	}

	// Reject IP literals sneaking in as "domains"
	if ip := net.ParseIP(ascii); ip != nil {
		return "", fmt.Errorf("%w (IP literal): %s", errInvalidDomain, orig)
	}

	// Structure + length
	if len(ascii) > maxDomainLength {
		return "", fmt.Errorf("%w (too long): %s", errInvalidDomain, orig)
	}

	if strings.HasPrefix(ascii, ".") || strings.HasSuffix(ascii, ".") || strings.Contains(ascii, "..") {
		return "", fmt.Errorf("%w: %s", errInvalidDomain, orig)
	}

	if !strings.Contains(ascii, ".") {
		return "", fmt.Errorf("%w (need at least one dot): %s", errInvalidDomain, orig)
	}

	return ascii, nil
}

// validateDomainLabels checks each label for length, allowed characters,
// hyphen placement and ensures the final TLD is not all digits.
func validateDomainLabels(ascii, orig string) error {
	labels := strings.Split(ascii, ".")
	for idx, label := range labels {
		if l := len(label); l < 1 || l > 63 {
			return fmt.Errorf("%w (label length): %s", errInvalidDomain, orig)
		}

		// Validate characters in label
		err := validateLabelChars(label, orig)
		if err != nil {
			return err
		}

		lower := strings.ToLower(label)
		if lower[0] == '-' || lower[len(lower)-1] == '-' {
			return fmt.Errorf("%w (hyphen position): %s", errInvalidDomain, orig)
		}

		// Final TLD must not be all digits
		if idx == len(labels)-1 {
			if isAllDigits(lower) {
				return fmt.Errorf("%w (numeric TLD): %s", errInvalidDomain, orig)
			}
		}
	}

	return nil
}

// validateLabelChars ensures label characters are a-z, 0-9 or hyphen
// (uppercase tolerated via unicode.IsUpper).
func validateLabelChars(label, orig string) error {
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}

		if unicode.IsUpper(r) {
			continue
		}

		return fmt.Errorf("%w (label chars): %s", errInvalidDomain, orig)
	}

	return nil
}

// isAllDigits returns true if s contains only ASCII digits.
func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

// AllowList defines the structure for allowed IPs and domains in the policy.
type AllowList struct {
	IPs     []string `yaml:"ips"`
	Domains []string `yaml:"domains"`
}

// Config wraps the AllowList for YAML parsing.
type Config struct {
	AllowList AllowList `yaml:"allowlist"`
}

// loadConfig reads and parses the YAML policy file at path 'file'.
// It returns a parsed Config or an error; callers should handle logging.
func loadConfig(file string) (Config, error) {
	var cfg Config

	data, err := os.ReadFile(file) // #nosec G304
	if err != nil {
		return cfg, fmt.Errorf("error reading file: %w", err)
	}

	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("error parsing YAML: %w", err)
	}

	return cfg, nil
}

// ReadPolicy reads the YAML policy file at path 'file', validates entries,
// and returns cleaned lists of allowed IPs and domains.
func ReadPolicy(file string) ([]string, []string, error) {
	lg := slog.Default()
	if lg != nil {
		lg.Info("policy.read_start", "component", "policy", "file", strings.TrimSpace(file))
	}

	cfg, err := loadConfig(file)
	if err != nil {
		// The caller (main) is responsible for logging the top-level error.
		// We no longer log it here to avoid redundancy.
		return nil, nil, err
	}

	cleanIPs, err := validateIPs(lg, file, cfg.AllowList.IPs)
	if err != nil {
		// validateIPs already logged the specific validation error,
		// so we just return the error up the stack.
		return nil, nil, err
	}

	cleanDomains, err := validateDomains(lg, file, cfg.AllowList.Domains)
	if err != nil {
		// validateDomains also logs the specific error at the source.
		return nil, nil, err
	}

	if lg != nil {
		lg.Info("policy.read_ok",
			"component", "policy",
			"file", file,
			"ip_count", len(cleanIPs),
			"domain_count", len(cleanDomains),
		)
	}

	return cleanIPs, cleanDomains, nil
}

// validateIPs iterates through a slice of IPs, validates them, and returns a clean slice.
func validateIPs(lg *slog.Logger, file string, ips []string) ([]string, error) {
	cleanIPs := make([]string, 0, len(ips))

	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		err := validateIP(ip)
		if err != nil {
			if lg != nil {
				errStr := err.Error()
				lg.Error("policy.validation_error",
					"component", "policy",
					"file", file,
					"field", "ip",
					"value", ip,
					"err", errStr,
				)
			}

			return nil, fmt.Errorf("IP validation failed: %w", err)
		}

		cleanIPs = append(cleanIPs, ip)
	}

	return cleanIPs, nil
}

// validateDomains iterates through a slice of domains, validates them, and returns a clean slice.
func validateDomains(lg *slog.Logger, file string, domains []string) ([]string, error) {
	cleanDomains := make([]string, 0, len(domains))

	for _, dom := range domains {
		dom = strings.TrimSpace(dom)
		if dom == "" {
			continue
		}

		err := validateDomain(dom)
		if err != nil {
			if lg != nil {
				errStr := err.Error()
				lg.Error("policy.validation_error",
					"component", "policy",
					"file", file,
					"field", "domain",
					"value", dom,
					"err", errStr,
				)
			}

			return nil, fmt.Errorf("domain validation failed: %w", err)
		}

		cleanDomains = append(cleanDomains, dom)
	}

	return cleanDomains, nil
}
