package filter

import (
	"log/slog"
	"strings"
)

const (
	maxHostLength      = 253 // RFC 1035
	maxLabelLength     = 63  // RFC 1035
	minValidHostLength = 1   // At least one character

	unknownValue = "unknown"
)

// sanitizeHost validates and sanitizes a host/domain extracted from HTTP Host header or TLS SNI.
// Returns the sanitized host and true if valid, or empty string and false if invalid.
// This rejects anything suspicious rather than attempting repair.
func sanitizeHost(host string) (string, bool) {
	return sanitizeHostWithLogger(host, nil, "")
}

// sanitizeHostWithLogger validates and sanitizes a host/domain with trace logging support.
// The source parameter helps identify where the validation is being called from (e.g., "http", "https").
func sanitizeHostWithLogger(host string, logger *slog.Logger, source string) (string, bool) {
	log := validationLogger(logger, source)

	log("validation_start", "host", host, "length", len(host))

	if !hasValidLength(host) {
		log("validation_failed", "host", host, "reason", "invalid_length",
			"length", len(host), "max", maxHostLength)

		return "", false
	}

	if !hasValidCharacters(host) {
		log("validation_failed", "host", host, "reason", "invalid_characters")

		return "", false
	}

	if !hasValidStructure(host) {
		log("validation_failed", "host", host, "reason", "invalid_structure",
			"detail", determineStructureFailureReason(host))

		return "", false
	}

	if !hasValidLabels(host) {
		log("validation_failed", "host", host, "reason", "invalid_labels",
			"detail", determineLabelFailureReason(host))

		return "", false
	}

	log("validation_success", "host", host)

	return host, true
}

// validationLogger returns a log function scoped to the given source prefix.
// Returns a no-op when logger or source is not set.
func validationLogger(logger *slog.Logger, source string) func(suffix string, args ...any) {
	if logger == nil || source == "" {
		return func(_ string, _ ...any) {}
	}

	return func(suffix string, args ...any) {
		logger.Debug(source+"."+suffix, args...)
	}
}

func determineStructureFailureReason(host string) string {
	if strings.HasPrefix(host, ".") {
		return "starts_with_dot"
	}

	if strings.HasPrefix(host, "-") {
		return "starts_with_hyphen"
	}

	if strings.HasSuffix(host, "-") {
		return "ends_with_hyphen"
	}

	if strings.Contains(host, "..") {
		return "contains_double_dot"
	}

	return unknownValue
}

func determineLabelFailureReason(host string) string {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "insufficient_labels"
	}

	for idx, label := range labels {
		if reason := checkLabelValidity(label, idx == len(labels)-1); reason != "" {
			return reason
		}
	}

	return unknownValue
}

func checkLabelValidity(label string, isTLD bool) string {
	if !isValidLabel(label) {
		switch {
		case len(label) < 1:
			return "empty_label"
		case len(label) > maxLabelLength:
			return "label_too_long"
		case label[0] == '-':
			return "label_starts_with_hyphen"
		case label[len(label)-1] == '-':
			return "label_ends_with_hyphen"
		default:
			return "invalid_label"
		}
	}

	// Final label (TLD) validation
	if isTLD && !isValidTLD(label) {
		if len(label) < 2 {
			return "tld_too_short"
		}

		return "tld_all_numeric"
	}

	return ""
}

func hasValidLength(host string) bool {
	return len(host) >= minValidHostLength && len(host) <= maxHostLength
}

func hasValidCharacters(host string) bool {
	for _, r := range host {
		if !isValidDNSChar(r) {
			return false
		}
	}

	return true
}

// hasValidStructure checks for malformed patterns like leading/trailing dots or double characters.
func hasValidStructure(host string) bool {
	if strings.HasPrefix(host, ".") || strings.HasPrefix(host, "-") {
		return false
	}

	if strings.HasSuffix(host, "-") {
		return false
	}

	if strings.Contains(host, "..") {
		return false
	}

	return true
}

// hasValidLabels validates all DNS labels including TLD requirements.
func hasValidLabels(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}

	for idx, label := range labels {
		if !isValidLabel(label) {
			return false
		}

		// Final label (TLD) must be at least 2 characters and not all numeric
		if idx == len(labels)-1 {
			if !isValidTLD(label) {
				return false
			}
		}
	}

	return true
}

// isValidTLD checks if a TLD meets minimum requirements.
func isValidTLD(tld string) bool {
	if len(tld) < 2 {
		return false
	}

	if isAllNumeric(tld) {
		return false
	}

	return true
}

// sanitizeDNSQname validates a DNS query name and returns it lowercased. Unlike
// HTTP/SNI hosts, underscore labels (_dmarc, _service._proto) and bare
// single-label names are legal in DNS queries.
func sanitizeDNSQname(qname string) (string, bool) {
	if len(qname) < minValidHostLength || len(qname) > maxHostLength {
		return "", false
	}

	lowered := strings.ToLower(qname)

	for label := range strings.SplitSeq(lowered, ".") {
		if !isValidDNSQnameLabel(label) {
			return "", false
		}
	}

	return lowered, true
}

// isValidDNSQnameLabel validates a single label of a DNS query name.
func isValidDNSQnameLabel(label string) bool {
	if len(label) < 1 || len(label) > maxLabelLength {
		return false
	}

	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	for _, r := range label {
		if !isValidDNSChar(r) && r != '_' {
			return false
		}
	}

	return true
}

// isValidDNSChar returns true if the rune is a valid DNS character (a-z, 0-9, dot, hyphen).
func isValidDNSChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-'
}

// isAllNumeric returns true if the string contains only digits.
func isAllNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}

	return len(s) > 0
}

// isValidLabel validates a single DNS label (between dots).
func isValidLabel(label string) bool {
	labelLen := len(label)

	// RFC 1035: label must be 1-63 characters
	if labelLen < 1 || labelLen > maxLabelLength {
		return false
	}

	// Cannot start or end with hyphen
	if label[0] == '-' || label[labelLen-1] == '-' {
		return false
	}

	return true
}
