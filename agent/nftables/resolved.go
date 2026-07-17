package nftables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	// minResolvedTTL floors short CDN TTLs so entries don't expire between the DNS
	// answer and the client's connect; established connections survive via conntrack.
	minResolvedTTL = 60 * time.Second
	maxResolvedTTL = 24 * time.Hour

	resolvedCmdTimeout = 3 * time.Second
)

var errInvalidResolvedIP = errors.New("invalid resolved IP")

// clampTTL bounds a DNS TTL to [minResolvedTTL, maxResolvedTTL].
func clampTTL(ttl time.Duration) time.Duration {
	if ttl < minResolvedTTL {
		return minResolvedTTL
	}

	if ttl > maxResolvedTTL {
		return maxResolvedTTL
	}

	return ttl
}

// resolvedElementArgs builds the nft argv for adding one IP to a resolved set with a
// timeout. IPs come from untrusted DNS answers, so they are re-validated and the
// family checked against the target set before touching the kernel.
func resolvedElementArgs(verb, ip string, ttl time.Duration) ([]string, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return nil, fmt.Errorf("%w: %q", errInvalidResolvedIP, ip)
	}

	family, table, set := "ip", "g0efilter_v4", "resolved_allow_v4"
	if parsed.To4() == nil {
		family, table, set = "ip6", "g0efilter_v6", "resolved_allow_v6"
	}

	element := parsed.String()
	if verb == "add" {
		element += " timeout " + strconv.Itoa(int(clampTTL(ttl).Seconds())) + "s"
	}

	return []string{verb, "element", family, table, set, "{ " + element + " }"}, nil
}

// addResolvedElement inserts one IP, replacing any existing entry so the timeout
// refreshes on re-resolution (nft "add element" fails with EEXIST on live entries).
func addResolvedElement(ctx context.Context, ip string, ttl time.Duration) error {
	addArgs, err := resolvedElementArgs("add", ip, ttl)
	if err != nil {
		return err
	}

	err = runNft(ctx, addArgs)
	if err == nil {
		return nil
	}

	delArgs, argsErr := resolvedElementArgs("delete", ip, 0)
	if argsErr != nil {
		return argsErr
	}

	_ = runNft(ctx, delArgs)

	return runNft(ctx, addArgs)
}

func runNft(ctx context.Context, args []string) error {
	ctx, cancel := context.WithTimeout(ctx, resolvedCmdTimeout)
	defer cancel()

	//nolint:gosec // argv only: verbs/table/set are literals, IPs re-validated by net.ParseIP
	cmd := exec.CommandContext(ctx, "nft", args...)

	var out bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nft %s failed: %w: %s", strings.Join(args[:2], " "), err, strings.TrimSpace(out.String()))
	}

	return nil
}

// AddResolvedIPs pushes IPs resolved for an allowed domain into the dns-strict
// runtime sets, with a timeout derived from the DNS TTL. Failures on individual
// IPs are collected rather than aborting the batch.
func AddResolvedIPs(ctx context.Context, ips []string, ttl time.Duration) error {
	var errs []error

	for _, ip := range ips {
		err := addResolvedElement(ctx, ip, ttl)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
