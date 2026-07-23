// Command dev-traffic-gen posts canonical synthetic traffic to a local dashboard.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/dashboard/demo"
)

func main() {
	base := getenv("DASHBOARD_URL", "http://localhost:8081")
	apiKey := getenv("DEV_API_KEY", "dev-api-key")
	url := base + "/api/v1/logs"
	interval := 2 * time.Second

	if len(os.Args) > 1 {
		secs, err := strconv.Atoi(os.Args[1])
		if err == nil && secs > 0 {
			interval = time.Duration(secs) * time.Second
		}
	}

	fixtures, err := demo.Scenarios()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	_, _ = fmt.Fprintf(os.Stdout, ">>> posting to %s every %s (ctrl-c to stop)\n", url, interval)

	client := &http.Client{Timeout: 5 * time.Second}

	for i := 0; ; i++ {
		dest := fixtures.Destinations[i%len(fixtures.Destinations)]
		hostname := fixtures.Clients[(i*3)%len(fixtures.Clients)]
		body := buildPayload(fixtures.SourceSubnet, dest, hostname, i)

		err := postEvent(client, url, apiKey, body)
		if err != nil {
			fmt.Fprintf(os.Stderr, "!!! %v (dashboard down or wrong DEV_API_KEY?)\n", err)
		}

		time.Sleep(interval)
	}
}

func buildPayload(subnet string, dest demo.Destination, hostname string, seq int) map[string]any {
	sourceIP := fmt.Sprintf("%s.%d.%d", subnet, (seq/250)%4, seq%250+2)
	sourcePort := 1024 + (seq*37)%40000
	payload := map[string]any{
		"time":        time.Now().UTC().Format(time.RFC3339),
		"action":      dest.Verdict,
		"component":   dest.Component,
		"reason":      dest.Reason,
		"source_ip":   sourceIP,
		"source_port": sourcePort,
		"hostname":    hostname,
		"flow_id":     fmt.Sprintf("dev-%d", seq),
		"version":     "v0.demo",
	}

	switch dest.Component {
	case "dns":
		payload["msg"] = "dns." + strings.ToLower(dest.Verdict)
		payload["qname"] = dest.Domain
		payload["qtype"] = "A"
		payload["protocol"] = "UDP"
	case "nflog":
		payload["msg"] = "nflog.event"
		payload["protocol"] = "TCP"
		payload["destination_ip"] = dest.IP
		payload["destination_port"] = dest.Port
		payload["src"] = fmt.Sprintf("%s:%d", sourceIP, sourcePort)
		payload["dst"] = fmt.Sprintf("%s:%d", dest.IP, dest.Port)
	default:
		payload["msg"] = dest.Component + "." + strings.ToLower(dest.Verdict)
		payload["protocol"] = "TCP"
		payload["destination_ip"] = dest.IP
		payload["destination_port"] = dest.Port
		payload["dst"] = fmt.Sprintf("%s:%d", dest.IP, dest.Port)

		if dest.Component == "http" {
			payload["host"] = dest.Domain
		} else {
			payload["https"] = dest.Domain
		}
	}

	return payload
}

func postEvent(client *http.Client, url, apiKey string, payload map[string]any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post event: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("ingest returned %d", resp.StatusCode) //nolint:err113 // dev-only diagnostic
	}

	return nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}
