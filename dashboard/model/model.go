// Package model holds the dashboard domain types shared by the HTTP layer
// and storage implementations. It must stay a leaf package (stdlib imports
// only) so stores and the dashboard package can both depend on it.
//
//nolint:tagliatelle // JSON uses snake_case for API compatibility
package model

import (
	"encoding/json"
	"errors"
	"time"
)

// ErrAPIKeyNotFound is returned when revoking an unknown or already revoked key.
var ErrAPIKeyNotFound = errors.New("api key not found")

// LogEntry represents a single ingested or synthetic log event.
type LogEntry struct {
	ID       int64           `json:"id,omitempty"`
	Time     time.Time       `json:"time"`
	Message  string          `json:"msg"`
	Fields   json.RawMessage `json:"fields,omitempty"`
	RemoteIP string          `json:"remote_ip,omitempty"`

	// Flattened (derived from Fields for API / SSE convenience)
	Action          string `json:"action,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	PolicyHit       string `json:"policy_hit,omitempty"`
	PayloadLen      int    `json:"payload_len,omitempty"`
	HTTPS           string `json:"https,omitempty"`
	HTTPHost        string `json:"http_host,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	FlowID          string `json:"flow_id,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	Src             string `json:"src,omitempty"`
	Dst             string `json:"dst,omitempty"`
	Version         string `json:"version,omitempty"`
}

// UnblockRequest represents a pending request to remove a block rule.
type UnblockRequest struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"` // "domain" or "ip"
	Value          string    `json:"value"`
	TargetHostname string    `json:"target_hostname"` // empty means "all"
	CreatedAt      time.Time `json:"created_at"`
}

// CompletedUnblock records an unblock operation that has been acknowledged and applied.
type CompletedUnblock struct {
	Type           string    `json:"type"`
	Value          string    `json:"value"`
	TargetHostname string    `json:"target_hostname"`
	CompletedAt    time.Time `json:"completed_at"`
}

// APIKey describes a machine credential. The key itself is never stored;
// only its SHA-256 hash is persisted and compared.
type APIKey struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Prefix     string     `json:"prefix"` // first characters of the key, for identification only
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// Session is an authenticated browser session. The token is never stored;
// only its SHA-256 hash is persisted.
type Session struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// User is a dashboard login. PasswordHash is a bcrypt hash.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// Group is a named set of instances sharing a policy and settings.
type Group struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Policy     string    `json:"policy"`
	FilterMode string    `json:"filter_mode,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Instance is a g0efilter node known to the fleet control plane.
type Instance struct {
	ID              string    `json:"id"`
	Hostname        string    `json:"hostname"`
	GroupID         string    `json:"group_id,omitempty"`
	GroupName       string    `json:"group_name,omitempty"`
	PolicyOverride  *string   `json:"policy_override,omitempty"`
	FilterMode      string    `json:"filter_mode,omitempty"`
	ReportedVersion string    `json:"reported_version,omitempty"`
	ReportedHash    string    `json:"reported_hash,omitempty"`
	DesiredHash     string    `json:"desired_hash,omitempty"`
	InSync          bool      `json:"in_sync"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	CreatedAt       time.Time `json:"created_at"`
}

// DesiredConfig is the resolved config a synced instance should apply.
type DesiredConfig struct {
	Policy     string `json:"policy,omitempty"`
	FilterMode string `json:"filter_mode,omitempty"`
	Hash       string `json:"config_hash"`
	// Managed is false when the instance belongs to no group and has no policy
	// override: the dashboard has no desired policy for it, so it must keep its
	// local file rather than be pushed an empty policy.
	Managed bool `json:"managed"`
}

// SyncReport is what an instance sends to POST /api/v1/sync.
type SyncReport struct {
	Hostname   string `json:"hostname"`
	FilterMode string `json:"filter_mode"`
	Version    string `json:"version"`
	ConfigHash string `json:"config_hash"`
}
