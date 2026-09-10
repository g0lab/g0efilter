package webhook

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	"github.com/g0lab/g0efilter/controller/internal/render"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const clusterPolicyKind = "ClusterEgressPolicy"

// ErrInvalidUpstream means a DNS upstream is not a usable `host:port`.
var ErrInvalidUpstream = errors.New("invalid DNS upstream")

// Validator rejects bad edits before they replace a working spec, reading uncached to see commits.
type Validator struct {
	Client  client.Reader
	Decoder admission.Decoder
}

// Handle denies any edit that would leave a selected sidecar unable to enforce the policy.
// It reads the other policies as committed, so concurrent namespaced and cluster edits can
// still commit an unenforceable pair. That pair is never enforced: the reconciler keeps the
// previous ConfigMap and pod admission re-renders the merged result before injecting.
func (v *Validator) Handle(ctx context.Context, req admission.Request) admission.Response {
	var clusters v1alpha1.ClusterEgressPolicyList

	err := v.Client.List(ctx, &clusters)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	namespaces := newNamespaceCache(v.Client)

	affected, refused := v.affectedPolicies(ctx, req, &clusters, namespaces)
	if refused != nil {
		return *refused
	}

	for _, candidate := range affected {
		labels, nsErr := namespaces.labels(ctx, candidate.Namespace)
		if nsErr != nil {
			return admission.Errored(http.StatusInternalServerError, nsErr)
		}

		err = validateCandidate(candidate, labels, clusters.Items)
		if err != nil {
			return admission.Denied(fmt.Sprintf("policy %s/%s: %s", candidate.Namespace, candidate.Name, err))
		}
	}

	return admission.Allowed("policy is enforceable")
}

// affectedPolicies returns every namespaced policy whose rendering this request could change.
func (v *Validator) affectedPolicies(
	ctx context.Context,
	req admission.Request,
	clusters *v1alpha1.ClusterEgressPolicyList,
	namespaces *namespaceCache,
) ([]v1alpha1.EgressPolicy, *admission.Response) {
	if req.Kind.Kind != clusterPolicyKind {
		var candidate v1alpha1.EgressPolicy

		err := v.Decoder.Decode(req, &candidate)
		if err != nil {
			return nil, new(admission.Errored(http.StatusBadRequest, err))
		}

		candidate.Namespace = req.Namespace

		return []v1alpha1.EgressPolicy{candidate}, nil
	}

	var candidate v1alpha1.ClusterEgressPolicy

	err := v.Decoder.Decode(req, &candidate)
	if err != nil {
		return nil, new(admission.Errored(http.StatusBadRequest, err))
	}

	_, err = render.Rules(candidate.Spec.Egress)
	if err != nil {
		return nil, new(admission.Denied(err.Error()))
	}

	clusters.Items = append(withoutPolicy(clusters.Items, candidate.Name), candidate)

	var policies v1alpha1.EgressPolicyList

	err = v.Client.List(ctx, &policies)
	if err != nil {
		return nil, new(admission.Errored(http.StatusInternalServerError, err))
	}

	return selectedPolicies(ctx, policies.Items, candidate, namespaces)
}

// selectedPolicies narrows a baseline edit to the policies it can actually change.
// Dropping a namespace only removes rules from it, so a policy there cannot become
// unenforceable; validating it anyway would let one already-broken policy block every
// later baseline edit, including edits for unrelated namespaces.
func selectedPolicies(
	ctx context.Context,
	policies []v1alpha1.EgressPolicy,
	candidate v1alpha1.ClusterEgressPolicy,
	namespaces *namespaceCache,
) ([]v1alpha1.EgressPolicy, *admission.Response) {
	selector, err := metav1.LabelSelectorAsSelector(&candidate.Spec.NamespaceSelector)
	if err != nil {
		return nil, new(admission.Denied(fmt.Sprintf("namespaceSelector: %s", err)))
	}

	kept := make([]v1alpha1.EgressPolicy, 0, len(policies))

	for _, policy := range policies {
		policyLabels, err := namespaces.labels(ctx, policy.Namespace)
		if err != nil {
			return nil, new(admission.Errored(http.StatusInternalServerError, err))
		}

		if selector.Matches(labels.Set(policyLabels)) {
			kept = append(kept, policy)
		}
	}

	return kept, nil
}

func validateCandidate(
	candidate v1alpha1.EgressPolicy,
	namespaceLabels map[string]string,
	clusters []v1alpha1.ClusterEgressPolicy,
) error {
	baseline, err := render.ClusterRules(namespaceLabels, clusters)
	if err != nil {
		return fmt.Errorf("merge cluster baselines: %w", err)
	}

	_, err = render.RulesForMode(candidate.Spec.Sidecar.Mode, candidate.Spec.Egress, baseline)
	if err != nil {
		return fmt.Errorf("render rules: %w", err)
	}

	return ValidateUpstreams(candidate.Spec.Sidecar.DNS.Upstreams)
}

// ValidateUpstreams checks each resolver is a usable `host:port`.
func ValidateUpstreams(upstreams []string) error {
	for _, upstream := range upstreams {
		host, port, err := net.SplitHostPort(upstream)
		if err != nil || host == "" {
			return fmt.Errorf("%w: %q must be host:port", ErrInvalidUpstream, upstream)
		}

		number, convErr := strconv.Atoi(port)
		if convErr != nil || number < 1 || number > 65535 {
			return fmt.Errorf("%w: %q must be host:port", ErrInvalidUpstream, upstream)
		}
	}

	return nil
}

func withoutPolicy(policies []v1alpha1.ClusterEgressPolicy, name string) []v1alpha1.ClusterEgressPolicy {
	kept := make([]v1alpha1.ClusterEgressPolicy, 0, len(policies))

	for _, policy := range policies {
		if policy.Name != name {
			kept = append(kept, policy)
		}
	}

	return kept
}

// namespaceCache keeps one Get per namespace when a baseline re-validates every policy.
type namespaceCache struct {
	reader client.Reader
	seen   map[string]map[string]string
}

func newNamespaceCache(reader client.Reader) *namespaceCache {
	return &namespaceCache{reader: reader, seen: make(map[string]map[string]string)}
}

func (c *namespaceCache) labels(ctx context.Context, name string) (map[string]string, error) {
	labels, ok := c.seen[name]
	if ok {
		return labels, nil
	}

	var namespace corev1.Namespace

	err := c.reader.Get(ctx, client.ObjectKey{Name: name}, &namespace)
	if err != nil {
		return nil, fmt.Errorf("get namespace %s: %w", name, err)
	}

	c.seen[name] = namespace.Labels

	return namespace.Labels, nil
}
