// Package main is the entrypoint for g0efilter.
package main

import (
	"fmt"
	"os"

	"github.com/g0lab/g0efilter/agent/g0efilter"
)

// Set by GoReleaser via ldflags (wired in init()).
var (
	version = ""
	commit  = "" //nolint:gochecknoglobals
	date    = "" //nolint:gochecknoglobals
)

//nolint:gochecknoinits
func init() {
	if version == "" {
		version = "0.0.0-dev"
	}

	if date == "" {
		date = "unknown"
	}

	if commit == "" {
		commit = "none"
	}
}

func main() {
	if g0efilter.HandleVersionFlag(os.Args, version, date, commit) {
		return
	}

	if handled, code := g0efilter.HandleHealthcheck(os.Args); handled {
		os.Exit(code)
	}

	err := g0efilter.Run(version, date, commit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
