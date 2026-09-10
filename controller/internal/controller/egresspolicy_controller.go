// Package controller reconciles egress policies into the ConfigMaps the g0efilter
// sidecar mounts.
package controller

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"time"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	"github.com/g0lab/g0efilter/controller/internal/render"
	"github.com/g0lab/g0efilter/controller/internal/webhook"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// PolicyKey is the ConfigMap key the sidecar reads.
	PolicyKey = "policy.yaml"

	conditionReady              = "Ready"
	conditionConfigurationReady = "ConfigurationReady"
	conditionPodsUpToDate       = "PodsUpToDate"

	reasonRendered      = "Rendered"
	reasonInvalidPolicy = "InvalidPolicy"
	reasonPodsCurrent   = "PodsCurrent"
	reasonPodsOutOfDate = "PodsOutOfDate"

	managedByLabel = "app.kubernetes.io/managed-by"
	policyLabel    = "g0efilter.g0lab.com/policy"
	managedByValue = "g0efilter-controller"

	maxConfigMapName = 253
	nameHashLength   = 12
)

// EgressPolicyReconciler renders each EgressPolicy into its own ConfigMap, merging
// in the rules of every ClusterEgressPolicy that selects the namespace.
type EgressPolicyReconciler struct {
	Client   client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder
	Defaults webhook.Defaults
}

// +kubebuilder:rbac:groups=g0efilter.g0lab.com,resources=egresspolicies;clusteregresspolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=g0efilter.g0lab.com,resources=egresspolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// The manager's recorder writes through events.k8s.io/v1; the core group is still
// needed because leader election records its own Events there.
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile renders one EgressPolicy.
func (r *EgressPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var policy v1alpha1.EgressPolicy

	err := r.Client.Get(ctx, req.NamespacedName, &policy)
	if err != nil {
		// A deleted policy takes its ConfigMap with it through the owner reference.
		return ctrl.Result{}, client.IgnoreNotFound(err) //nolint:wrapcheck // controller-runtime sentinel handling
	}

	clusterRules, err := r.clusterRulesFor(ctx, policy.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}

	rendered, err := render.RulesForMode(policy.Spec.Sidecar.Mode, policy.Spec.Egress, clusterRules)
	if err != nil {
		logger.Error(err, "invalid policy")

		return ctrl.Result{}, r.markDegraded(ctx, &policy, err)
	}

	name := ConfigMapNameFor(policy.Name)

	document, err := rendered.DocumentFor(policy.Spec.Sidecar)
	if err != nil {
		return ctrl.Result{}, r.markDegraded(ctx, &policy, err)
	}

	err = r.applyConfigMap(ctx, &policy, name, document)
	if err != nil {
		return ctrl.Result{}, err
	}

	pods, stale, err := r.selectedPodState(ctx, &policy)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: 15 * time.Second}, r.markPodState(ctx, &policy, name, pods, stale)
}

// ConfigMapNameFor is the ConfigMap a policy renders into. Pods mount it by name,
// so it is derived from the policy name rather than generated.
func ConfigMapNameFor(policyName string) string {
	const prefix = "g0efilter-"

	name := prefix + policyName
	if len(name) <= maxConfigMapName {
		return name
	}

	sum := fmt.Sprintf("%x", sha256.Sum256([]byte(policyName)))[:nameHashLength]
	keep := maxConfigMapName - len(prefix) - 1 - len(sum)

	return prefix + policyName[:keep] + "-" + sum
}

// SetupWithManager wires the reconciler, re-reconciling namespaced policies when a
// cluster policy changes so a baseline edit reaches every namespace.
func (r *EgressPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.EgressPolicy{}).
		Owns(&corev1.ConfigMap{}).
		Watches(&v1alpha1.ClusterEgressPolicy{}, handler.EnqueueRequestsFromMapFunc(r.allPolicies)).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.policiesInNamespace)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.policiesInNamespace)).
		Complete(r)
	if err != nil {
		return fmt.Errorf("build controller: %w", err)
	}

	return nil
}

func (r *EgressPolicyReconciler) policiesInNamespace(ctx context.Context, object client.Object) []ctrl.Request {
	namespace := object.GetNamespace()
	if namespace == "" {
		namespace = object.GetName()
	}

	var list v1alpha1.EgressPolicyList

	err := r.Client.List(ctx, &list, client.InNamespace(namespace))
	if err != nil {
		log.FromContext(ctx).Error(err, "listing policies", "namespace", namespace)

		return nil
	}

	requests := make([]ctrl.Request, 0, len(list.Items))
	for _, policy := range list.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKey{
			Namespace: policy.Namespace,
			Name:      policy.Name,
		}})
	}

	return requests
}

func (r *EgressPolicyReconciler) allPolicies(ctx context.Context, _ client.Object) []ctrl.Request {
	var list v1alpha1.EgressPolicyList

	err := r.Client.List(ctx, &list)
	if err != nil {
		log.FromContext(ctx).Error(err, "listing policies after a cluster policy change")

		return nil
	}

	requests := make([]ctrl.Request, 0, len(list.Items))

	for _, policy := range list.Items {
		requests = append(requests, ctrl.Request{
			NamespacedName: client.ObjectKey{Namespace: policy.Namespace, Name: policy.Name},
		})
	}

	return requests
}

// clusterRulesFor collects the rules of every ClusterEgressPolicy whose namespace
// selector matches, in a stable order so the rendered document does not churn.
func (r *EgressPolicyReconciler) clusterRulesFor(ctx context.Context, namespace string) ([]v1alpha1.EgressRule, error) {
	var ns corev1.Namespace

	err := r.Client.Get(ctx, client.ObjectKey{Name: namespace}, &ns)
	if err != nil {
		return nil, fmt.Errorf("get namespace %s: %w", namespace, err)
	}

	var list v1alpha1.ClusterEgressPolicyList

	err = r.Client.List(ctx, &list)
	if err != nil {
		return nil, fmt.Errorf("list cluster policies: %w", err)
	}

	rules, err := render.ClusterRules(ns.Labels, list.Items)
	if err != nil {
		return nil, fmt.Errorf("select cluster policies: %w", err)
	}

	return rules, nil
}

func (r *EgressPolicyReconciler) applyConfigMap(
	ctx context.Context,
	policy *v1alpha1.EgressPolicy,
	name, document string,
) error {
	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: policy.Namespace},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, configMap, func() error {
		if configMap.Labels == nil {
			configMap.Labels = map[string]string{}
		}

		configMap.Labels[managedByLabel] = managedByValue
		configMap.Labels[policyLabel] = policy.Name

		configMap.Data = map[string]string{PolicyKey: document}

		// The owner reference is what garbage-collects the ConfigMap with the policy.
		return controllerutil.SetControllerReference(policy, configMap, r.Scheme)
	})
	if err != nil {
		return fmt.Errorf("apply ConfigMap %s/%s: %w", policy.Namespace, name, err)
	}

	return nil
}

func (r *EgressPolicyReconciler) selectedPodState(
	ctx context.Context,
	policy *v1alpha1.EgressPolicy,
) (int32, int32, error) {
	selector, err := metav1.LabelSelectorAsSelector(&policy.Spec.PodSelector)
	if err != nil {
		return 0, 0, fmt.Errorf("pod selector: %w", err)
	}

	desired, err := webhook.StartupRevision(policy.Spec.Sidecar, r.Defaults, ConfigMapNameFor(policy.Name))
	if err != nil {
		return 0, 0, fmt.Errorf("startup revision: %w", err)
	}

	var pods corev1.PodList

	err = r.Client.List(ctx, &pods,
		client.InNamespace(policy.Namespace),
		client.MatchingLabelsSelector{Selector: selector})
	if err != nil {
		return 0, 0, fmt.Errorf("list pods: %w", err)
	}

	var running, stale int32

	for _, pod := range pods.Items {
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}

		running++

		if !podIsCurrent(pod, policy.Name, desired) {
			stale++
		}
	}

	return running, stale, nil
}

// podIsCurrent reports whether a pod runs the current startup settings and its sidecar is ready.
func podIsCurrent(pod corev1.Pod, policyName, desired string) bool {
	if pod.Annotations[webhook.InjectedAnnotation] != policyName ||
		pod.Annotations[webhook.StartupRevisionAnnotation] != desired {
		return false
	}

	for _, status := range pod.Status.InitContainerStatuses {
		if status.Name == webhook.ContainerName {
			return status.Ready
		}
	}

	return false
}

func (r *EgressPolicyReconciler) markPodState(
	ctx context.Context,
	policy *v1alpha1.EgressPolicy,
	name string,
	pods, stale int32,
) error {
	before := policy.Status.DeepCopy()

	policy.Status.ObservedGeneration = policy.Generation
	policy.Status.ConfigMapName = name
	policy.Status.SelectedPods = pods
	policy.Status.OutOfDatePods = stale

	rendered := "rendered into ConfigMap " + name

	// Ready tracks the rendered configuration alone, so stale pods never block admission of their replacements.
	setCondition(policy, metav1.ConditionTrue, reasonRendered, rendered)
	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionConfigurationReady,
		Status:             metav1.ConditionTrue,
		Reason:             reasonRendered,
		Message:            rendered,
		ObservedGeneration: policy.Generation,
	})

	status, reason, message := podRolloutCondition(pods, stale)
	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionPodsUpToDate,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: policy.Generation,
	})

	err := r.updateStatusIfChanged(ctx, policy, before)
	if err != nil {
		return err
	}

	if stale > 0 && before.OutOfDatePods != stale && r.Recorder != nil {
		r.Recorder.Eventf(policy, nil, corev1.EventTypeWarning, reason, "ObservePods", "%s", message)
	}

	return nil
}

func podRolloutCondition(pods, stale int32) (metav1.ConditionStatus, string, string) {
	if stale == 0 {
		return metav1.ConditionTrue, reasonPodsCurrent,
			"every selected running sidecar reports ready with the current startup settings"
	}

	return metav1.ConditionFalse, reasonPodsOutOfDate,
		fmt.Sprintf("%d of %d selected running pods need a sidecar reload or rollout", stale, pods)
}

func (r *EgressPolicyReconciler) markDegraded(ctx context.Context, policy *v1alpha1.EgressPolicy, cause error) error {
	before := policy.Status.DeepCopy()

	policy.Status.ObservedGeneration = policy.Generation

	// The previous ConfigMap is deliberately left in place: replacing a working
	// policy with an empty one because the new spec is invalid would open egress.
	setCondition(policy, metav1.ConditionFalse, reasonInvalidPolicy, cause.Error())
	meta.SetStatusCondition(&policy.Status.Conditions, metav1.Condition{
		Type:               conditionConfigurationReady,
		Status:             metav1.ConditionFalse,
		Reason:             reasonInvalidPolicy,
		Message:            cause.Error(),
		ObservedGeneration: policy.Generation,
	})

	return r.updateStatusIfChanged(ctx, policy, before)
}

func setCondition(policy *v1alpha1.EgressPolicy, status metav1.ConditionStatus, reason, message string) {
	condition := metav1.Condition{
		Type:               conditionReady,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: policy.Generation,
	}

	meta := &policy.Status.Conditions

	for i := range *meta {
		if (*meta)[i].Type != conditionReady {
			continue
		}

		if (*meta)[i].Status == status {
			condition.LastTransitionTime = (*meta)[i].LastTransitionTime
		} else {
			condition.LastTransitionTime = metav1.Now()
		}

		(*meta)[i] = condition

		return
	}

	condition.LastTransitionTime = metav1.Now()
	*meta = append(*meta, condition)
}

func (r *EgressPolicyReconciler) updateStatusIfChanged(
	ctx context.Context,
	policy *v1alpha1.EgressPolicy,
	before *v1alpha1.EgressPolicyStatus,
) error {
	if reflect.DeepEqual(*before, policy.Status) {
		return nil
	}

	err := r.Client.Status().Update(ctx, policy)
	if err != nil {
		return fmt.Errorf("update status: %w", err)
	}

	return nil
}
