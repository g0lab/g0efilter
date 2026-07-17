// Package policy parses and validates the allowlist policy file.
package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"go.yaml.in/yaml/v4"
	"golang.org/x/net/idna"
)

var (
	errInvalidIP               = errors.New("invalid IP address")
	errInvalidDomain           = errors.New("invalid domain pattern")
	errInvalidRegex            = errors.New("invalid regex domain pattern")
	errInvalidWildcard         = errors.New("invalid wildcard domain pattern")
	errInvalidDefaultAction    = errors.New("invalid default_action (want allow or deny)")
	errPathTraversalNotAllowed = errors.New("path traversal not allowed")
	errNotRegularFile          = errors.New("not a regular file")
	errUnknownAllowlistField   = errors.New("unknown allowlist field")
)

const (
	maxDomainLength = 253
	maxRegexLength  = 1024
)

// Valid default_action values.
const (
	DefaultActionDeny  = "deny"
	DefaultActionAllow = "allow"
)

// IsRegexPattern reports whether a domain entry is a slash-delimited regex, e.g. /^a\.b\.com$/.
func IsRegexPattern(s string) bool {
	return len(s) > 2 && strings.HasPrefix(s, "/") && strings.HasSuffix(s, "/")
}

// CompileDomainPattern compiles a /regex/ domain entry. The expression is anchored
// to the full host and matched case-insensitively. Go's RE2 engine guarantees
// linear-time matching, so untrusted patterns cannot cause catastrophic backtracking.
func CompileDomainPattern(pattern string) (*regexp.Regexp, error) {
	if !IsRegexPattern(pattern) {
		return nil, fmt.Errorf("%w: %s", errInvalidRegex, pattern)
	}

	inner := pattern[1 : len(pattern)-1]
	if len(inner) > maxRegexLength {
		return nil, fmt.Errorf("%w (too long): %s", errInvalidRegex, pattern)
	}

	re, err := regexp.Compile(`\A(?i:` + inner + `)\z`)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errInvalidRegex, pattern, err)
	}

	return re, nil
}

// CompileWildcardPattern compiles a domain pattern containing '*' into an anchored,
// case-insensitive regexp. Each '*' matches one or more characters including dots,
// so sub.*.sub.domain.com covers any label depth between the literal parts -
// consistent with a leading *.domain.com matching any subdomain level.
func CompileWildcardPattern(pattern string) (*regexp.Regexp, error) {
	err := validateWildcardStructure(pattern)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(pattern, "*")
	for i, chunk := range parts {
		if !isValidWildcardChunk(chunk) {
			return nil, fmt.Errorf("%w (invalid characters): %s", errInvalidWildcard, pattern)
		}

		parts[i] = regexp.QuoteMeta(strings.ToLower(chunk))
	}

	re, err := regexp.Compile(`\A(?i:` + strings.Join(parts, `.+`) + `)\z`)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", errInvalidWildcard, pattern, err)
	}

	return re, nil
}

func validateWildcardStructure(pattern string) error {
	if !strings.Contains(pattern, "*") || pattern == "*" {
		return fmt.Errorf("%w: %s", errInvalidWildcard, pattern)
	}

	if len(pattern) > maxDomainLength {
		return fmt.Errorf("%w (too long): %s", errInvalidWildcard, pattern)
	}

	if strings.Contains(pattern, "**") {
		return fmt.Errorf("%w (consecutive wildcards): %s", errInvalidWildcard, pattern)
	}

	if strings.Contains(pattern, "..") || strings.HasPrefix(pattern, ".") || strings.HasSuffix(pattern, ".") {
		return fmt.Errorf("%w (dot placement): %s", errInvalidWildcard, pattern)
	}

	if !strings.Contains(pattern, ".") {
		return fmt.Errorf("%w (need at least one dot): %s", errInvalidWildcard, pattern)
	}

	return nil
}

// isValidWildcardChunk allows only hostname characters in the literal parts of a wildcard pattern.
func isValidWildcardChunk(chunk string) bool {
	for _, r := range chunk {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}

		return false
	}

	return true
}

// validateIP validates an IP address or CIDR range, accepting both IPv4 and IPv6.
// Rejects addresses with ports (e.g. 1.2.3.4:80 or [::1]:80) and scoped IPv6 (e.g. fe80::1%eth0).
//

func validateIP(ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("%w: empty", errInvalidIP)
	}

	// Reject bracketed IPv6 with port (e.g. [::1]:80)
	if strings.HasPrefix(ip, "[") {
		return fmt.Errorf("%w (contains port): %s", errInvalidIP, ip)
	}

	// Reject scoped/zone IPv6 (e.g. fe80::1%eth0) - not useful for egress filtering
	if strings.Contains(ip, "%") {
		return fmt.Errorf("%w (scoped address): %s", errInvalidIP, ip)
	}

	// Reject IPv4 host:port (e.g. 1.2.3.4:80) - exactly one colon and contains a dot
	if i := strings.LastIndexByte(ip, ':'); i != -1 && strings.Count(ip, ":") == 1 && strings.Contains(ip, ".") {
		return fmt.Errorf("%w (contains port): %s", errInvalidIP, ip)
	}

	if strings.Contains(ip, "/") {
		_, _, err := net.ParseCIDR(ip)
		if err != nil {
			return fmt.Errorf("%w range: %s", errInvalidIP, ip)
		}

		return nil
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("%w: %s", errInvalidIP, ip)
	}

	return nil
}

// validateDomain validates a domain pattern, accepting wildcards, /regex/ entries,
// and ensuring valid DNS format for literal names.
func validateDomain(domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("%w: empty", errInvalidDomain)
	}

	if domain == "*" {
		return nil
	}

	if IsRegexPattern(domain) {
		_, err := CompileDomainPattern(domain)

		return err
	}

	orig := domain

	// Leading "*." with no other wildcards keeps the strict per-label validation below
	if after, ok := strings.CutPrefix(domain, "*."); ok && !strings.Contains(after, "*") {
		domain = after
		if domain == "" {
			return fmt.Errorf("%w: %s", errInvalidDomain, orig)
		}
	} else if strings.Contains(domain, "*") {
		// Mid-name wildcards (e.g. sub.*.sub.domain.com) validate by compiling
		_, err := CompileWildcardPattern(strings.TrimSuffix(domain, "."))

		return err
	}

	// Single trailing dot is fine
	domain = strings.TrimSuffix(domain, ".")

	ascii, err := domainToASCII(domain, orig)
	if err != nil {
		return err
	}

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

func validateDomainLabels(ascii, orig string) error {
	labels := strings.Split(ascii, ".")
	for idx, label := range labels {
		if l := len(label); l < 1 || l > 63 {
			return fmt.Errorf("%w (label length): %s", errInvalidDomain, orig)
		}

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

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}

	return true
}

// AllowList defines a list of IPs and domains (used for both allowlist and denylist).
type AllowList struct {
	IPs     []string `yaml:"ips"`
	Domains []string `yaml:"domains"`
}

// Config is the YAML shape of the policy file.
type Config struct {
	DefaultAction string    `yaml:"default_action,omitempty"` //nolint:tagliatelle // policy file uses snake_case
	AllowList     AllowList `yaml:"allowlist"`
	DenyList      AllowList `yaml:"denylist,omitempty"`
}

// Policy is the validated, normalized policy.
// DefaultAction is "" when the policy file does not set it (caller applies its default).
type Policy struct {
	DefaultAction string
	AllowIPs      []string
	AllowDomains  []string
	DenyIPs       []string
	DenyDomains   []string
}

// loadConfig reads and parses a YAML policy file with path validation.
func loadConfig(file string) (Config, error) {
	var cfg Config

	// Validate file path to prevent directory traversal
	cleanPath := filepath.Clean(file)

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

// ReadPolicy loads and validates the policy, returning only the allowlist IPs and domains.
// Kept for callers that predate denylist/default_action support.
func ReadPolicy(file string) ([]string, []string, error) {
	pol, err := Read(file)
	if err != nil {
		return nil, nil, err
	}

	return pol.AllowIPs, pol.AllowDomains, nil
}

// Read loads and validates the full policy, first checking environment variables
// (ALLOWLIST_IPS, ALLOWLIST_DOMAINS, DENYLIST_IPS, DENYLIST_DOMAINS), then falling
// back to the policy file if none are set.
func Read(file string) (*Policy, error) {
	lg := slog.Default()

	envAllowIPs := strings.TrimSpace(os.Getenv("ALLOWLIST_IPS"))
	envAllowDomains := strings.TrimSpace(os.Getenv("ALLOWLIST_DOMAINS"))
	envDenyIPs := strings.TrimSpace(os.Getenv("DENYLIST_IPS"))
	envDenyDomains := strings.TrimSpace(os.Getenv("DENYLIST_DOMAINS"))

	if envAllowIPs != "" || envAllowDomains != "" || envDenyIPs != "" || envDenyDomains != "" {
		lg.Debug("policy.read_start", "component", "policy", "source", "environment")

		return loadFromEnv(lg, envAllowIPs, envAllowDomains, envDenyIPs, envDenyDomains)
	}

	lg.Debug("policy.read_start", "component", "policy", "source", "file", "file", strings.TrimSpace(file))

	cfg, err := loadConfig(file)
	if err != nil {
		return nil, err
	}

	defaultAction, err := validateDefaultAction(cfg.DefaultAction)
	if err != nil {
		return nil, err
	}

	pol := &Policy{DefaultAction: defaultAction} //nolint:exhaustruct

	pol.AllowIPs, pol.AllowDomains, err = validateLists(lg, file, cfg.AllowList)
	if err != nil {
		return nil, err
	}

	pol.DenyIPs, pol.DenyDomains, err = validateLists(lg, file, cfg.DenyList)
	if err != nil {
		return nil, err
	}

	lg.Debug("policy.read_ok",
		"component", "policy",
		"source", "file",
		"file", file,
		"default_action", defaultAction,
		"ip_count", len(pol.AllowIPs),
		"domain_count", len(pol.AllowDomains),
		"deny_ip_count", len(pol.DenyIPs),
		"deny_domain_count", len(pol.DenyDomains),
	)

	return pol, nil
}

func validateDefaultAction(action string) (string, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	switch action {
	case "", DefaultActionDeny, DefaultActionAllow:
		return action, nil
	default:
		return "", fmt.Errorf("%w: %s", errInvalidDefaultAction, action)
	}
}

// validateLists validates one allowlist/denylist section, returning nil slices when empty.
func validateLists(lg *slog.Logger, source string, list AllowList) ([]string, []string, error) {
	cleanIPs, err := validateIPs(lg, source, list.IPs)
	if err != nil {
		return nil, nil, err
	}

	cleanDomains, err := validateDomains(lg, source, list.Domains)
	if err != nil {
		return nil, nil, err
	}

	if len(cleanIPs) == 0 {
		cleanIPs = nil
	}

	if len(cleanDomains) == 0 {
		cleanDomains = nil
	}

	return cleanIPs, cleanDomains, nil
}

func loadFromEnv(lg *slog.Logger, allowIPs, allowDomains, denyIPs, denyDomains string) (*Policy, error) {
	pol := &Policy{} //nolint:exhaustruct

	var err error

	pol.AllowIPs, pol.AllowDomains, err = validateLists(lg, "env:ALLOWLIST", AllowList{
		IPs:     parseCommaSeparated(allowIPs),
		Domains: parseCommaSeparated(allowDomains),
	})
	if err != nil {
		return nil, err
	}

	pol.DenyIPs, pol.DenyDomains, err = validateLists(lg, "env:DENYLIST", AllowList{
		IPs:     parseCommaSeparated(denyIPs),
		Domains: parseCommaSeparated(denyDomains),
	})
	if err != nil {
		return nil, err
	}

	lg.Debug("policy.read_ok",
		"component", "policy",
		"source", "environment",
		"ip_count", len(pol.AllowIPs),
		"domain_count", len(pol.AllowDomains),
		"deny_ip_count", len(pol.DenyIPs),
		"deny_domain_count", len(pol.DenyDomains),
	)

	return pol, nil
}

func parseCommaSeparated(input string) []string {
	if input == "" {
		return nil
	}

	parts := strings.Split(input, ",")
	result := make([]string, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}

	return result
}

func validateIPs(lg *slog.Logger, file string, ips []string) ([]string, error) {
	cleanIPs := make([]string, 0, len(ips))

	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}

		err := validateIP(ip)
		if err != nil {
			lg.Error("policy.validation_error",
				"component", "policy",
				"file", file,
				"field", "ip",
				"value", ip,
				"err", err,
			)

			return nil, fmt.Errorf("IP validation failed: %w", err)
		}

		lg.Debug("policy.ip_validated", "ip", ip)

		cleanIPs = append(cleanIPs, ip)
	}

	return cleanIPs, nil
}

func validateDomains(lg *slog.Logger, file string, domains []string) ([]string, error) {
	cleanDomains := make([]string, 0, len(domains))

	for _, dom := range domains {
		dom = strings.TrimSpace(dom)
		if dom == "" {
			continue
		}

		err := validateDomain(dom)
		if err != nil {
			lg.Error("policy.validation_error",
				"component", "policy",
				"file", file,
				"field", "domain",
				"value", dom,
				"err", err,
			)

			return nil, fmt.Errorf("domain validation failed: %w", err)
		}

		lg.Debug("policy.domain_validated", "domain", dom)

		cleanDomains = append(cleanDomains, dom)
	}

	return cleanDomains, nil
}

// AppendDomain validates and appends a domain to the policy file's allowlist.
// Returns an error if validation fails or file cannot be updated.
func AppendDomain(file string, domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return fmt.Errorf("%w: empty", errInvalidDomain)
	}

	err := validateDomain(domain)
	if err != nil {
		return err
	}

	return appendToAllowlist(file, "domains", domain)
}

// AppendIP validates and appends an IP address or CIDR range to the policy file's allowlist.
// Returns an error if validation fails or file cannot be updated.
func AppendIP(file string, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("%w: empty", errInvalidIP)
	}

	err := validateIP(ip)
	if err != nil {
		return err
	}

	return appendToAllowlist(file, "ips", ip)
}

// appendToAllowlist appends a value to the specified field in the allowlist.
func appendToAllowlist(file, field, value string) error {
	cfg, err := loadConfig(file)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	// Check for duplicates
	switch field {
	case "domains":
		for _, d := range cfg.AllowList.Domains {
			if strings.EqualFold(d, value) {
				return nil // Already exists, no-op
			}
		}

		cfg.AllowList.Domains = append(cfg.AllowList.Domains, value)
	case "ips":
		if slices.Contains(cfg.AllowList.IPs, value) {
			return nil // Already exists, no-op
		}

		cfg.AllowList.IPs = append(cfg.AllowList.IPs, value)
	default:
		return fmt.Errorf("%w: %s", errUnknownAllowlistField, field)
	}

	// Write back to file
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	cleanPath := filepath.Clean(file)

	//nolint:gosec // File permissions are intentionally 0644 for policy files
	err = os.WriteFile(cleanPath, data, 0o644)
	if err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	return nil
}
