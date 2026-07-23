// Package demo provides synthetic-traffic fixtures shared by development tools.
package demo

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
)

//go:embed scenarios.json
var scenariosJSON []byte

var errEmptyScenarios = errors.New("scenarios fixture has no destinations or clients")

// Destination is one synthetic egress target with a fixed verdict.
type Destination struct {
	Domain    string `json:"domain"`
	Category  string `json:"category"`
	Verdict   string `json:"verdict"`
	Component string `json:"component"`
	Port      int    `json:"port"`
	Reason    string `json:"reason"`
	IP        string `json:"ip"`
}

// Fixtures is the full canonical scenario set.
//
//nolint:tagliatelle // snake_case matches the shared JSON fixture + API style
type Fixtures struct {
	SourceSubnet string        `json:"source_subnet"`
	Clients      []string      `json:"clients"`
	Destinations []Destination `json:"destinations"`
}

// Scenarios returns the embedded canonical fixtures.
func Scenarios() (Fixtures, error) {
	var f Fixtures

	err := json.Unmarshal(scenariosJSON, &f)
	if err != nil {
		return Fixtures{}, fmt.Errorf("parse scenarios: %w", err)
	}

	if len(f.Destinations) == 0 || len(f.Clients) == 0 {
		return Fixtures{}, errEmptyScenarios
	}

	return f, nil
}
