package nftables_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/agent/nftables"
)

func installFakeNft(t *testing.T, script string) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "nft")

	//nolint:gosec // the fixture must be executable to stand in for nft
	err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o700)
	if err != nil {
		t.Fatalf("write fake nft: %v", err)
	}

	t.Setenv("PATH", dir)
}

// PATH is process-wide, so these cases cannot run in parallel.
//
//nolint:paralleltest
func TestProbe(t *testing.T) {
	//nolint:paralleltest
	t.Run("success", func(t *testing.T) {
		installFakeNft(t, "exit 0")

		err := nftables.Probe(context.Background())
		if err != nil {
			t.Fatalf("Probe() = %v, want nil", err)
		}
	})

	//nolint:paralleltest
	t.Run("reports command output", func(t *testing.T) {
		installFakeNft(t, "echo netlink denied >&2; exit 1")

		err := nftables.Probe(context.Background())
		if err == nil {
			t.Fatal("Probe() accepted a failed nft command")
		}

		for _, want := range []string{"exit status 1", "netlink denied"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Probe() error %q omits %q", err, want)
			}
		}
	})
}
