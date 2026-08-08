package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	"github.com/g0lab/g0efilter/controller/internal/render"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	errNoSuchPolicy    = errors.New("no matching policy")
	errAmbiguousPolicy = errors.New("ambiguous policy")
	errPolicyNotReady  = errors.New("policy is not ready")
	errProcessInfoPID  = errors.New("processInfo requires shareProcessNamespace unless hostPID is enabled")
)

const (
	// InjectAnnotation set to "false" on a pod opts it out of injection.
	InjectAnnotation = "g0efilter.io/inject"

	// PolicyAnnotation names the policy to use when several select the pod.
	PolicyAnnotation = "g0efilter.io/policy"

	// InjectedAnnotation records the policy a pod was filtered by.
	InjectedAnnotation = "g0efilter.io/injected-from"
)

// Injector adds the sidecar to pods selected by an EgressPolicy in their namespace.
type Injector struct {
	Client   client.Client
	Decoder  admission.Decoder
	Defaults Defaults
}

// Handle implements the admission webhook.
func (i *Injector) Handle(ctx context.Context, req admission.Request) admission.Response {
	pod := &corev1.Pod{} //nolint:exhaustruct // decoded into

	err := i.Decoder.Decode(req, pod)
	if err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	// The object has no namespace yet on create; the request carries it.
	namespace := req.Namespace

	skip, reason := shouldSkip(pod)
	if skip {
		return admission.Allowed(reason)
	}

	policy, err := i.selectPolicy(ctx, namespace, pod)
	if err != nil {
		return admission.Denied(err.Error())
	}

	if policy == nil {
		return admission.Allowed("no EgressPolicy selects this pod")
	}

	err = i.policyReady(ctx, namespace, policy)
	if err != nil {
		return admission.Denied(err.Error())
	}

	settings := resolve(policy.Spec.Sidecar, i.Defaults)

	err = validateProcessInfo(pod, settings)
	if err != nil {
		return admission.Denied(err.Error())
	}

	inject(pod, settings, configMapFor(policy), policy.Name)

	patched, err := json.Marshal(pod)
	if err != nil {
		return admission.Errored(http.StatusInternalServerError, err)
	}

	log.FromContext(ctx).Info("injected the sidecar",
		"namespace", namespace, "pod", pod.GenerateName+pod.Name, "policy", policy.Name)

	return admission.PatchResponseFromRaw(req.Object.Raw, patched)
}

func validateProcessInfo(pod *corev1.Pod, settings sidecarSettings) error {
	if !settings.processInfo || pod.Spec.HostPID || pod.Spec.ShareProcessNamespace == nil ||
		*pod.Spec.ShareProcessNamespace {
		return nil
	}

	return errProcessInfoPID
}

func (i *Injector) policyReady(
	ctx context.Context,
	namespace string,
	policy *v1alpha1.EgressPolicy,
) error {
	if policy.Status.ObservedGeneration != policy.Generation || policy.Status.ConfigMapName == "" {
		return fmt.Errorf("%w: %s has not rendered generation %d",
			errPolicyNotReady, policy.Name, policy.Generation)
	}

	for _, condition := range policy.Status.Conditions {
		if condition.Type == "Ready" && condition.Status == metav1.ConditionTrue &&
			condition.ObservedGeneration == policy.Generation {
			return i.policyConfigCurrent(ctx, namespace, policy)
		}
	}

	return fmt.Errorf("%w: %s generation %d is not Ready", errPolicyNotReady, policy.Name, policy.Generation)
}

func (i *Injector) policyConfigCurrent(
	ctx context.Context,
	namespace string,
	policy *v1alpha1.EgressPolicy,
) error {
	var ns corev1.Namespace

	err := i.Client.Get(ctx, client.ObjectKey{Name: namespace}, &ns)
	if err != nil {
		return fmt.Errorf("%w: read namespace %s: %w", errPolicyNotReady, namespace, err)
	}

	var clusters v1alpha1.ClusterEgressPolicyList

	err = i.Client.List(ctx, &clusters)
	if err != nil {
		return fmt.Errorf("%w: list cluster policies: %w", errPolicyNotReady, err)
	}

	clusterRules, err := render.ClusterRules(ns.Labels, clusters.Items)
	if err != nil {
		return fmt.Errorf("%w: %w", errPolicyNotReady, err)
	}

	desired, err := render.RulesForMode(policy.Spec.Sidecar.Mode, policy.Spec.Egress, clusterRules)
	if err != nil {
		return fmt.Errorf("%w: %w", errPolicyNotReady, err)
	}

	var configMap corev1.ConfigMap

	key := client.ObjectKey{Namespace: namespace, Name: policy.Status.ConfigMapName}

	err = i.Client.Get(ctx, key, &configMap)
	if err != nil {
		return fmt.Errorf("%w: read ConfigMap %s/%s: %w", errPolicyNotReady, namespace, key.Name, err)
	}

	if configMap.Data["policy.yaml"] != desired.Document() {
		return fmt.Errorf("%w: ConfigMap %s/%s is stale", errPolicyNotReady, namespace, key.Name)
	}

	return nil
}

func shouldSkip(pod *corev1.Pod) (bool, string) {
	if pod.Annotations[InjectAnnotation] == "false" {
		return true, "opted out with " + InjectAnnotation
	}

	// Already filtered by a render-time sidecar; a second copy is a name clash.
	for _, list := range [][]corev1.Container{pod.Spec.InitContainers, pod.Spec.Containers} {
		for _, existing := range list {
			if existing.Name == ContainerName {
				return true, "the pod already has a " + ContainerName + " container"
			}
		}
	}

	// The sidecar programs the whole network namespace, so this would filter the node.
	if pod.Spec.HostNetwork {
		return true, "host network pods are not filtered"
	}

	return false, ""
}

// selectPolicy finds the one policy that selects the pod. Several is an error, not
// a guess: each renders its own ConfigMap.
func (i *Injector) selectPolicy(
	ctx context.Context,
	namespace string,
	pod *corev1.Pod,
) (*v1alpha1.EgressPolicy, error) {
	var list v1alpha1.EgressPolicyList

	err := i.Client.List(ctx, &list, client.InNamespace(namespace))
	if err != nil {
		return nil, fmt.Errorf("list policies in %s: %w", namespace, err)
	}

	matched, err := matching(list.Items, pod)
	if err != nil {
		return nil, err
	}

	if named := pod.Annotations[PolicyAnnotation]; named != "" {
		for idx := range matched {
			if matched[idx].Name == named {
				return &matched[idx], nil
			}
		}

		return nil, fmt.Errorf("%w: %s names %q, which does not select this pod",
			errNoSuchPolicy, PolicyAnnotation, named)
	}

	switch len(matched) {
	case 0:
		return nil, nil //nolint:nilnil // no policy is not an error
	case 1:
		return &matched[0], nil
	default:
		return nil, fmt.Errorf("%w: %s; set %s to choose one",
			errAmbiguousPolicy, names(matched), PolicyAnnotation)
	}
}

func matching(policies []v1alpha1.EgressPolicy, pod *corev1.Pod) ([]v1alpha1.EgressPolicy, error) {
	matched := make([]v1alpha1.EgressPolicy, 0, len(policies))

	for _, policy := range policies {
		selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", policy.Name, err)
		}

		if selector.Matches(labels.Set(pod.Labels)) {
			matched = append(matched, policy)
		}
	}

	sort.Slice(matched, func(a, b int) bool { return matched[a].Name < matched[b].Name })

	return matched, nil
}

func names(policies []v1alpha1.EgressPolicy) string {
	out := make([]string, 0, len(policies))
	for _, policy := range policies {
		out = append(out, policy.Name)
	}

	return "several policies select this pod: " + strings.Join(out, ", ")
}

// inject prepends the sidecar: anything ordered before it has unfiltered egress.
func inject(pod *corev1.Pod, settings sidecarSettings, configMapName, policyName string) {
	pod.Spec.InitContainers = append([]corev1.Container{container(settings, configMapName)}, pod.Spec.InitContainers...)
	pod.Spec.Volumes = append(pod.Spec.Volumes, policyVolume(configMapName))

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}

	pod.Annotations[InjectedAnnotation] = policyName

	maps.Copy(pod.Annotations, scrapeAnnotations(settings))

	if settings.events {
		mount := true
		pod.Spec.AutomountServiceAccountToken = &mount
	}

	// hostPID already exposes the processes; otherwise opt into the pod's shared
	// process namespace without overriding an explicit setting.
	if settings.processInfo && !pod.Spec.HostPID && pod.Spec.ShareProcessNamespace == nil {
		share := true
		pod.Spec.ShareProcessNamespace = &share
	}
}
