package nftables

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/g0lab/g0efilter/agent/policy"
	nft "github.com/google/nftables"
)

const (
	// minResolvedTTL floors short CDN TTLs so entries don't expire between the DNS
	// answer and the client's connect; established connections survive via conntrack.
	minResolvedTTL = 60 * time.Second
	maxResolvedTTL = 24 * time.Hour
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

// AddResolvedIPs allows ips in the dns-strict sets until the clamped TTL expires,
// on every port or, per rule, one protocol and port. Invalid entries are skipped.
func AddResolvedIPs(ctx context.Context, ips []string, ttl time.Duration, rules []policy.DomainRule) error {
	if len(rules) == 0 {
		rules = []policy.DomainRule{{}}
	}

	pending := map[string]*pendingSet{}
	prefixes := resolvedTablePrefixes()

	var errs []error

	for _, ip := range ips {
		for _, rule := range rules {
			// SECURITY: IPs originate in untrusted DNS, so validate the address and
			// constraint before they become set keys.
			parsed, err := validateResolved(ip, rule)
			if err != nil {
				errs = append(errs, err)

				continue
			}

			for _, prefix := range prefixes {
				set, key := resolvedElement(prefix, parsed, rule)
				pendingFor(pending, set).add(key)
			}
		}
	}

	if len(pending) > 0 {
		errs = append(errs, refreshResolved(ctx, pending, clampTTL(ttl)))
	}

	return errors.Join(errs...)
}

type pendingSet struct {
	set  *nft.Set
	keys map[string]bool
}

func pendingFor(pending map[string]*pendingSet, set *nft.Set) *pendingSet {
	id := set.Table.Name + "/" + set.Name
	if pending[id] == nil {
		pending[id] = &pendingSet{set: set, keys: map[string]bool{}}
	}

	return pending[id]
}

// add de-duplicates: deleting one key twice would abort the whole transaction.
func (p *pendingSet) add(key []byte) {
	p.keys[string(key)] = true
}

// refreshResolved resets every timeout in one transaction, whether or not the
// element exists: add is a no-op on a live entry, then delete and add renew it.
func refreshResolved(ctx context.Context, pending map[string]*pendingSet, timeout time.Duration) error {
	batchBytes := 0
	for _, p := range pending {
		batchBytes += 3 * len(p.keys) * 96
	}

	err := withRuleset(ctx, resolveTimeout, batchBytes, func(conn *nft.Conn) error {
		for _, p := range pending {
			adds := make([]nft.SetElement, 0, len(p.keys))
			deletes := make([]nft.SetElement, 0, len(p.keys))

			for key := range p.keys {
				adds = append(adds, nft.SetElement{Key: []byte(key), Timeout: timeout})
				deletes = append(deletes, nft.SetElement{Key: []byte(key)})
			}

			err := errors.Join(
				queueElements(conn.SetAddElements, p.set, adds),
				queueElements(conn.SetDeleteElements, p.set, deletes),
				queueElements(conn.SetAddElements, p.set, adds),
			)
			if err != nil {
				return err
			}
		}

		return conn.Flush()
	})
	if err != nil {
		return fmt.Errorf("update resolved sets: %w", err)
	}

	return nil
}

func resolvedElement(prefix string, ip net.IP, rule policy.DomainRule) (*nft.Set, []byte) {
	set := &nft.Set{
		Table:      &nft.Table{Family: nft.TableFamilyIPv4, Name: prefix + "_v4"},
		Name:       "resolved_allow_v4",
		KeyType:    nft.TypeIPAddr,
		HasTimeout: true,
	}

	key := slices.Clone(ip.To4())
	if key == nil {
		set.Table = &nft.Table{Family: nft.TableFamilyIPv6, Name: prefix + "_v6"}
		set.Name, set.KeyType, key = "resolved_allow_v6", nft.TypeIP6Addr, slices.Clone(ip.To16())
	}

	if rule.Constrained() {
		set.Name += "_port"
		set.Concatenation = true
		set.KeyType = nft.MustConcatSetType(set.KeyType, nft.TypeInetProto, nft.TypeInetService)

		key = append(key, concatTail(l4Protos[rule.Proto], uint16(rule.Port))...) //nolint:gosec // validated 1-65535
	}

	return set, key
}

func resolvedTablePrefixes() []string {
	if bridgeFilteringEnabled() {
		return []string{"g0efilter", "g0efilter_bridge"}
	}

	return []string{"g0efilter"}
}
