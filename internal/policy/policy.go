// Package policy parses and validates the allowlist policy file.
package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/goccy/go-yaml"
	"golang.org/x/net/idna"
)

var (
	errInvalidIP               = errors.New("invalid IP address")
	errInvalidDomain           = errors.New("invalid domain pattern")
	errInvalidFilePath         = errors.New("invalid file path")
	errPathTraversalNotAllowed = errors.New("path traversal not allowed")
	errNotRegularFile          = errors.New("not a regular file")
)

const maxDomainLength = 253

// validateIP validates an IP address or CIDR range, rejecting IPv6 and addresses with ports.
//
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

// validateDomain validates a domain pattern, accepting wildcards and ensuring valid DNS format.
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
	if after, ok := strings.CutPrefix(domain, "*."); ok {
		domain = after
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

// domainToASCII converts a domain to ASCII using IDNA and validates basic structure.
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

// validateDomainLabels validates each label in a domain for length, character set, and hyphen placement.
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

// validateLabelChars ensures a domain label contains only valid characters (a-z, 0-9, hyphen).
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

// isAllDigits returns true if the string contains only numeric digits.
func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

// AllowList defines allowed IPs and domains.
type AllowList struct {
	IPs     []string `yaml:"ips"`
	Domains []string `yaml:"domains"`
}

// Config wraps the AllowList for YAML parsing.
type Config struct {
	AllowList AllowList `yaml:"allowlist"`
}

// loadConfig reads and parses a YAML policy file with path validation.
func loadConfig(file string) (Config, error) {
	var cfg Config

	// Validate file path to prevent directory traversal
	cleanPath := filepath.Clean(file)
	if cleanPath != file {
		return cfg, fmt.Errorf("%w: %s", errInvalidFilePath, file)
	}

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return cfg, fmt.Errorf("%w: %s", errPathTraversalNotAllowed, file)
	}

	// Ensure file is readable regular file
	fileInfo, err := os.Stat(cleanPath)
	if err != nil {
		return cfg, fmt.Errorf("error accessing file: %w", err)
	}

	if !fileInfo.Mode().IsRegular() {
		return cfg, fmt.Errorf("%w: %s", errNotRegularFile, cleanPath)
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return cfg, fmt.Errorf("error reading file: %w", err)
	}

	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("error parsing YAML: %w", err)
	}

	return cfg, nil
}

// ReadPolicy loads and validates the allowlist policy file, returning normalized IPs and domains.
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

// validateIPs validates and filters a list of IP addresses, logging and rejecting invalid entries.
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

// validateDomains validates and filters a list of domain patterns, logging and rejecting invalid entries.
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
