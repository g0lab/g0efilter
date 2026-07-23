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
	return map[string]any{
		"time":             time.Now().UTC().Format(time.RFC3339),
		"msg":              "flow.decision",
		"action":           dest.Verdict,
		"component":        dest.Component,
		"http_host":        dest.Domain,
		"reason":           dest.Reason,
		"source_ip":        fmt.Sprintf("%s.%d.%d", subnet, (seq/250)%4, seq%250+2),
		"source_port":      1024 + (seq*37)%40000,
		"destination_ip":   dest.IP,
		"destination_port": dest.Port,
		"hostname":         hostname,
		"flow_id":          fmt.Sprintf("dev-%d", seq),
		"version":          "dev",
	}
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
