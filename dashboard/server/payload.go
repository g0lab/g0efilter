package server

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/shared/actions"
	"github.com/g0lab/g0efilter/shared/logging"
)

// processPayloads converts raw payloads to LogEntry structs, inserts them, and broadcasts to SSE clients.
//
//nolint:cyclop // Complexity from probe detection, filtering, insertion, and broadcast logic
func (s *Server) processPayloads(ctx context.Context, payloads []map[string]any, remoteIP string) []map[string]any {
	results := make([]map[string]any, 0, len(payloads))
	filtered := 0
	isProbe := false

	for _, in := range payloads {
		SanitizePayloadFields(in)

		if msg, ok := in["msg"].(string); ok && (msg == "_dashboard_probe" || strings.HasPrefix(msg, "_dashboard_")) {
			isProbe = true
		}

		entry := s.processPayload(ctx, in, remoteIP)
		if entry == nil {
			filtered++

			continue
		}

		id, err := s.store.Insert(ctx, entry)
		if err != nil {
			s.logger.Error("insert.failed", "err", err.Error())

			continue
		}

		entry.ID = id
		results = append(results, map[string]any{"id": id, keyStatus: "ok"})

		s.logger.Log(ctx, logging.LevelTrace, "log.stored",
			"id", id,
			"action", entry.Action,
			"protocol", entry.Protocol,
			"message", entry.Message,
		)

		out, err := json.Marshal(entry)
		if err == nil && out != nil {
			s.broadcaster.Send(out)
			s.logger.Log(ctx, logging.LevelTrace, "log.broadcast",
				"id", id,
				"bytes", len(out),
			)
		}
	}

	// Only warn if non-probe messages were filtered
	if filtered > 0 && !isProbe {
		s.logger.Warn("ingest.filtered",
			"count", filtered,
			"reason", "invalid_or_non_allowed_blocked",
			"total_received", len(payloads),
			"stored", len(results),
		)
	}

	return results
}

// processPayload converts a raw log payload map into a LogEntry struct with enriched fields.
//
//nolint:funlen,cyclop // Payload processing requires extensive field extraction and validation
func (s *Server) processPayload(ctx context.Context, in map[string]any, remoteIP string) *LogEntry {
	msg, _ := in["msg"].(string)

	// Skip probe/health check messages silently (check before empty msg check)
	if msg == "_dashboard_probe" || strings.HasPrefix(msg, "_dashboard_") {
		s.logger.Log(ctx, logging.LevelTrace, "payload.probe_skipped",
			"remote", remoteIP,
			"msg", msg,
		)

		return nil
	}

	if msg == "" {
		s.logger.Log(ctx, logging.LevelTrace, "payload.missing_message",
			"remote", remoteIP,
		)

		return nil
	}

	// Action filter: only keep ALLOWED/BLOCKED/AUDIT
	action, _ := in["action"].(string)

	act := strings.ToUpper(strings.TrimSpace(action))
	if act != actions.ActionAllowed && act != actions.ActionBlocked && act != actions.ActionAudit {
		s.logger.Debug("payload.rejected",
			"remote", remoteIP,
			"action", action,
			"msg", msg,
			"component", in["component"],
		)

		return nil
	}

	ts := time.Now().UTC()

	if tval, ok := in["time"].(string); ok && tval != "" {
		t, err := time.Parse(time.RFC3339Nano, tval)
		if err == nil {
			ts = t.UTC()
		}
	}

	fieldsMap := extractFieldsMap(in)

	fieldsRaw, err := json.Marshal(fieldsMap)
	if err != nil {
		s.logger.Warn("payload.marshal_failed",
			"remote", remoteIP,
			"error", err.Error(),
		)

		return nil
	}

	if fieldsRaw == nil {
		fieldsRaw = json.RawMessage("null")
	}

	return &LogEntry{
		Time:            ts,
		Message:         msg,
		Fields:          fieldsRaw,
		RemoteIP:        remoteIP,
		Action:          act,
		Protocol:        deriveProtocol(in),
		PolicyHit:       getStringFromPayload(in, "policy_hit"),
		TenantID:        getStringFromPayload(in, "tenant_id"),
		SourceIP:        getStringFromPayload(in, "source_ip"),
		DestinationIP:   getStringFromPayload(in, "destination_ip"),
		HTTPS:           getStringFromPayload(in, "http_host", "host", keyHTTPS, "qname"),
		HTTPHost:        getStringFromPayload(in, "http_host", "host"),
		PayloadLen:      getIntFromPayload(in, "payload_len"),
		SourcePort:      getIntFromPayload(in, "source_port"),
		DestinationPort: getIntFromPayload(in, "destination_port"),
		FlowID:          getStringFromPayload(in, "flow_id"),
		Hostname:        getStringFromPayload(in, "hostname"),
		Src:             getStringFromPayload(in, "src"),
		Dst:             getStringFromPayload(in, "dst"),
		Version:         getStringFromPayload(in, "version"),
	}
}

// extractFieldsMap builds a map of all fields from the payload.
func extractFieldsMap(in map[string]any) map[string]any {
	fieldsMap := make(map[string]any)

	if f, ok := in["fields"].(map[string]any); ok {
		maps.Copy(fieldsMap, f)
	}

	// Merge top-level fields
	for _, k := range []string{
		"action", "component", "protocol", "policy_hit", "payload_len",
		"reason", "tenant_id", "flow_id", "hostname", "source_ip", "source_port",
		"destination_ip", "destination_port", "src", "dst", "http_host", "host", keyHTTPS,
		"qname", "qtype", "version",
	} {
		if v, ok := in[k]; ok && v != nil {
			fieldsMap[k] = v
		}
	}

	return fieldsMap
}

func deriveProtocol(in map[string]any) string {
	protocol, _ := in["protocol"].(string)
	if protocol != "" {
		return protocol
	}

	if comp, ok := in["component"].(string); ok {
		switch strings.ToLower(comp) {
		case "http", keyHTTPS:
			return "TCP"
		case "dns":
			return "UDP"
		}
	}

	return ""
}

// getStringFromPayload gets the first non-empty string from multiple keys.
func getStringFromPayload(in map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := in[k].(string); ok && v != "" {
			return v
		}
	}

	return ""
}

func getIntFromPayload(in map[string]any, key string) int {
	if v, ok := in[key].(float64); ok {
		return int(v)
	}

	return 0
}

const invalidDomainPlaceholder = "[invalid]"

// SanitizeDomainField validates and sanitizes domain/hostname fields to prevent log injection.
// Returns sanitized value or invalidDomainPlaceholder if validation fails.
func SanitizeDomainField(value string) string {
	if value == "" {
		return value
	}

	if !isValidDomainChars(value) {
		return invalidDomainPlaceholder
	}

	if hasSuspiciousPatterns(value) {
		return invalidDomainPlaceholder
	}

	const maxFieldLength = 255
	if len(value) > maxFieldLength {
		return invalidDomainPlaceholder
	}

	return value
}

// isValidDomainChars checks if all characters are valid for domain/hostname fields.
func isValidDomainChars(value string) bool {
	for _, r := range value {
		// Allow only printable ASCII: control chars (<32), DEL (127), and non-ASCII (>126) are rejected.
		// This covers \n, \r, \t, \x00 and all other control characters.
		if r < 32 || r > 126 {
			return false
		}
	}

	return true
}

// hasSuspiciousPatterns checks for common injection patterns.
// Note: control characters (\r, \n, etc.) are already rejected by isValidDomainChars.
func hasSuspiciousPatterns(value string) bool {
	return strings.Contains(value, "..") ||
		strings.Contains(value, "<script") ||
		strings.HasPrefix(value, "-") ||
		strings.HasPrefix(value, ".")
}

// SanitizePayloadFields sanitizes known domain/hostname fields in the payload map.
func SanitizePayloadFields(payload map[string]any) {
	// List of fields that should contain domain names or hostnames
	domainFields := []string{
		"host",      // HTTP Host header
		"http_host", // HTTP Host header (alternative key)
		keyHTTPS,    // HTTPS SNI
		"qname",     // DNS query name
		"hostname",  // Generic hostname
		"domain",    // Generic domain
	}

	for _, field := range domainFields {
		if value, ok := payload[field].(string); ok {
			payload[field] = SanitizeDomainField(value)
		}
	}
}
