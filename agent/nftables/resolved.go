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
	"sync/atomic"
	"time"

	"github.com/g0lab/g0efilter/agent/policy"
)

const (
	// minResolvedTTL floors short CDN TTLs so entries don't expire between the DNS
	// answer and the client's connect; established connections survive via conntrack.
	minResolvedTTL = 60 * time.Second
	maxResolvedTTL = 24 * time.Hour

	resolvedCmdTimeout = 3 * time.Second
)

var (
	errInvalidResolvedIP         = errors.New("invalid resolved IP")
	errInvalidResolvedConstraint = errors.New("invalid resolved port constraint")
)

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
// family checked against the target set before touching the kernel. A non-zero
// rule targets the "addr . proto . port" concatenation set instead.
func resolvedElementArgs(
	verb, tablePrefix, ip string,
	ttl time.Duration,
	rule policy.DomainRule,
) ([]string, error) {
	parsed, err := validateResolved(ip, rule)
	if err != nil {
		return nil, err
	}

	family, table, set := "ip", tablePrefix+"_v4", "resolved_allow_v4"
	if parsed.To4() == nil {
		family, table, set = "ip6", tablePrefix+"_v6", "resolved_allow_v6"
	}

	element := parsed.String()

	if rule.Constrained() {
		set += "_port"
		element += " . " + rule.Proto + " . " + strconv.Itoa(rule.Port)
	}

	if verb == "add" {
		element += " timeout " + strconv.Itoa(int(clampTTL(ttl).Seconds())) + "s"
	}

	return []string{verb, "element", family, table, set, "{ " + element + " }"}, nil
}

func validateResolved(ip string, rule policy.DomainRule) (net.IP, error) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return nil, fmt.Errorf("%w: %q", errInvalidResolvedIP, ip)
	}

	err := validateConstraint(rule)
	if err != nil {
		return nil, err
	}

	return parsed, nil
}

func validateConstraint(rule policy.DomainRule) error {
	if !rule.Constrained() {
		return nil
	}

	if rule.Proto != policy.ProtoTCP && rule.Proto != policy.ProtoUDP {
		return fmt.Errorf("%w: %q", errInvalidResolvedConstraint, rule.Proto)
	}

	if rule.Port < 1 || rule.Port > 65535 {
		return fmt.Errorf("%w: %d", errInvalidResolvedConstraint, rule.Port)
	}

	return nil
}

// addResolvedElement inserts one IP, replacing any existing entry so the timeout
// refreshes on re-resolution (nft "add element" fails with EEXIST on live entries).
func addResolvedElement(ctx context.Context, ip string, ttl time.Duration, rule policy.DomainRule) error {
	err := addResolvedToTable(ctx, "g0efilter", ip, ttl, rule)

	if !bridgeFilteringEnabled() {
		return err
	}

	// Both tables are attempted even on failure, or the two sets diverge.
	return errors.Join(err, addResolvedToTable(ctx, "g0efilter_bridge", ip, ttl, rule))
}

func addResolvedToTable(
	ctx context.Context,
	tablePrefix, ip string,
	ttl time.Duration,
	rule policy.DomainRule,
) error {
	addArgs, err := resolvedElementArgs("add", tablePrefix, ip, ttl, rule)
	if err != nil {
		return err
	}

	err = runNft(ctx, addArgs)
	if err == nil {
		return nil
	}

	delArgs, err := resolvedElementArgs("delete", tablePrefix, ip, 0, rule)
	if err != nil {
		return err
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
// IPs are collected rather than aborting the batch. Each rule in rules adds a
// protocol/port-constrained element instead of a whole-IP one; an empty rules
// slice allows the address on every port.
func AddResolvedIPs(ctx context.Context, ips []string, ttl time.Duration, rules []policy.DomainRule) error {
	if len(rules) == 0 {
		rules = []policy.DomainRule{{}}
	}

	prefixes := resolvedTablePrefixes()

	script, validationErrs := buildResolvedScript(prefixes, ips, ttl, rules)
	if script == "" || !resolvedBatchSupported(ctx) {
		return errors.Join(addResolvedIndividually(ctx, ips, ttl, rules)...)
	}

	err := runNftScript(ctx, script)
	if err == nil {
		return errors.Join(validationErrs...)
	}

	return errors.Join(append([]error{err}, addResolvedIndividually(ctx, ips, ttl, rules)...)...)
}

func addResolvedIndividually(
	ctx context.Context,
	ips []string,
	ttl time.Duration,
	rules []policy.DomainRule,
) []error {
	var errs []error

	for _, ip := range ips {
		for _, rule := range rules {
			err := addResolvedElement(ctx, ip, ttl, rule)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}

	return errs
}

func resolvedTablePrefixes() []string {
	if bridgeFilteringEnabled() {
		return []string{"g0efilter", "g0efilter_bridge"}
	}

	return []string{"g0efilter"}
}

func buildResolvedScript(
	prefixes, ips []string,
	ttl time.Duration,
	rules []policy.DomainRule,
) (string, []error) {
	var (
		script strings.Builder
		errs   []error
	)

	for _, ip := range ips {
		for _, rule := range rules {
			_, err := validateResolved(ip, rule)
			if err != nil {
				errs = append(errs, err)

				continue
			}

			for _, prefix := range prefixes {
				writeResolvedLine(&script, "destroy", prefix, ip, 0, rule)
				writeResolvedLine(&script, "add", prefix, ip, ttl, rule)
			}
		}
	}

	return script.String(), errs
}

func writeResolvedLine(
	script *strings.Builder,
	verb, prefix, ip string,
	ttl time.Duration,
	rule policy.DomainRule,
) {
	args, err := resolvedElementArgs(verb, prefix, ip, ttl, rule)
	if err != nil {
		return
	}

	script.WriteString(strings.Join(args, " "))
	script.WriteString("\n")
}

func runNftScript(ctx context.Context, script string) error {
	ctx, cancel := context.WithTimeout(ctx, resolvedCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)

	var out bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nft batch failed: %w: %s", err, strings.TrimSpace(out.String()))
	}

	return nil
}

//nolint:gochecknoglobals // capability probe of the nft binary, cached once answered
var (
	batchProbed    atomic.Bool
	batchSupported atomic.Bool
)

func resolvedBatchSupported(ctx context.Context) bool {
	if batchProbed.Load() {
		return batchSupported.Load()
	}

	version, err := Version(ctx)
	if err != nil {
		return false
	}

	batchSupported.Store(supportsDestroyElement(version))
	batchProbed.Store(true)

	return batchSupported.Load()
}

func supportsDestroyElement(version string) bool {
	field, _, _ := strings.Cut(strings.TrimSpace(version), " ")

	parts := strings.Split(strings.TrimPrefix(field, "v"), ".")
	if len(parts) < 3 {
		return false
	}

	nums := make([]int, 3)

	for i := range nums {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return false
		}

		nums[i] = n
	}

	if nums[0] != 1 {
		return nums[0] > 1
	}

	if nums[1] != 0 {
		return nums[1] > 0
	}

	return nums[2] >= 8
}
