// Package actions defines shared action and filter mode constants used across
// multiple internal packages without introducing import cycles.
package actions

// Action constants represent the outcome of a filter decision.
const (
	ActionAllowed    = "ALLOWED"
	ActionBlocked    = "BLOCKED"
	ActionRedirected = "REDIRECTED"
	// ActionAudit marks traffic that would have been blocked but was allowed
	// because audit (dry-run) enforcement is active.
	ActionAudit = "AUDIT"

	ModeHTTPS = "https"
	ModeDNS   = "dns"
	// ModeDNSStrict is DNS mode plus connection-time enforcement: resolved IPs of
	// allowed domains are pushed into a kernel timeout set and everything else drops.
	ModeDNSStrict = "dns-strict"
)

// KeyAlert is the structured-log attribute a producer sets to true to mark a
// record as a genuine enforcement event worth a notification. Alerting keys off
// this flag, not the action label, so audit-mode or benign events that carry a
// block-shaped action never page.
const KeyAlert = "alert"
