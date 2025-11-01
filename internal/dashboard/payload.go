package dashboard

import (
	"context"
	"encoding/json"
	"maps"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/internal/logging"
)

// processPayloads converts raw payloads to LogEntry structs, inserts them, and broadcasts to SSE clients.
func (s *Server) processPayloads(ctx context.Context, payloads []map[string]any, remoteIP string) []map[string]any {
	results := make([]map[string]any, 0, len(payloads))
	filtered := 0
	isProbe := false

	for _, in := range payloads {
		// Check if this is a probe message
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
		results = append(results, map[string]any{"id": id, "status": "ok"})

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
//nolint:funlen // Payload processing requires extensive field extraction
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

	// Action filter: only keep ALLOWED/BLOCKED
	action, _ := in["action"].(string)

	act := strings.ToUpper(strings.TrimSpace(action))
	if act != "ALLOWED" && act != "BLOCKED" {
		s.logger.Debug("payload.rejected",
			"remote", remoteIP,
			"action", action,
			"msg", msg,
			"component", in["component"],
		)

		return nil
	}

	// Parse timestamp
	ts := time.Now().UTC()

	if tval, ok := in["time"].(string); ok && tval != "" {
		t, err := time.Parse(time.RFC3339Nano, tval)
		if err == nil {
			ts = t.UTC()
		}
	}

	// Build fields JSON
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
		HTTPS:           getStringFromPayload(in, "http_host", "host", "https", "qname"),
		HTTPHost:        getStringFromPayload(in, "http_host", "host"),
		PayloadLen:      getIntFromPayload(in, "payload_len"),
		SourcePort:      getIntFromPayload(in, "source_port"),
		DestinationPort: getIntFromPayload(in, "destination_port"),
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
	for _, k := range []string{"action", "component", "protocol", "policy_hit", "payload_len",
		"reason", "tenant_id", "flow_id", "hostname", "source_ip", "source_port",
		"destination_ip", "destination_port", "src", "dst", "http_host", "host", "https", "qname", "qtype", "version"} {
		if v, ok := in[k]; ok && v != nil {
			fieldsMap[k] = v
		}
	}

	return fieldsMap
}

// deriveProtocol determines the protocol from the payload.
func deriveProtocol(in map[string]any) string {
	protocol, _ := in["protocol"].(string)
	if protocol != "" {
		return protocol
	}

	if comp, ok := in["component"].(string); ok {
		switch strings.ToLower(comp) {
		case "http", "https":
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

// getIntFromPayload gets float64 as int from payload.
func getIntFromPayload(in map[string]any, key string) int {
	if v, ok := in[key].(float64); ok {
		return int(v)
	}

	return 0
}
