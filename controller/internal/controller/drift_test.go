//nolint:testpackage // Need access to internal implementation details
package controller

import (
	"strings"
	"testing"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
	"github.com/g0lab/g0efilter/controller/internal/webhook"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const driftPolicy = "web"

func selectedPolicy() *v1alpha1.EgressPolicy {
	policy := egressPolicy(driftPolicy, rule("apis", []string{"api.example.com"}, nil))
	policy.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"app": driftPolicy}}

	return policy
}

// currentPod carries what the injector writes, so the reconciler should see it as up to date.
func currentPod(t *testing.T, policy *v1alpha1.EgressPolicy, ready bool) *corev1.Pod {
	t.Helper()

	revision, err := webhook.StartupRevision(policy.Spec.Sidecar, webhook.Defaults{}, ConfigMapNameFor(policy.Name))
	if err != nil {
		t.Fatalf("startup revision: %v", err)
	}

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      policy.Name + "-1",
			Namespace: testNS,
			Labels:    map[string]string{"app": policy.Name},
			Annotations: map[string]string{
				webhook.InjectedAnnotation:        policy.Name,
				webhook.StartupRevisionAnnotation: revision,
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: webhook.ContainerName, Ready: ready},
			},
		},
	}
}

func conditionOf(t *testing.T, c client.Client, conditionType string) *metav1.Condition {
	t.Helper()

	policy := getPolicy(t, c, driftPolicy)

	condition := meta.FindStatusCondition(policy.Status.Conditions, conditionType)
	if condition == nil {
		t.Fatalf("policy %s has no %s condition", driftPolicy, conditionType)
	}

	return condition
}

func TestUpToDatePodsReportNoDrift(t *testing.T) {
	t.Parallel()

	policy := selectedPolicy()
	r, c := newReconciler(t, namespace(nil), policy, currentPod(t, policy, true))

	reconcile(t, r, "web")

	if got := getPolicy(t, c, "web").Status.OutOfDatePods; got != 0 {
		t.Errorf("outOfDatePods = %d, want 0", got)
	}

	if got := conditionOf(t, c, conditionPodsUpToDate); got.Status != metav1.ConditionTrue {
		t.Errorf("PodsUpToDate = %s (%s), want True", got.Status, got.Reason)
	}
}

func TestPodsAreOutOfDateUntilTheirSidecarReportsReady(t *testing.T) {
	t.Parallel()

	policy := selectedPolicy()
	r, c := newReconciler(t, namespace(nil), policy, currentPod(t, policy, false))

	reconcile(t, r, "web")

	if got := getPolicy(t, c, "web").Status.OutOfDatePods; got != 1 {
		t.Errorf("outOfDatePods = %d, want 1", got)
	}

	if got := conditionOf(t, c, conditionPodsUpToDate); got.Reason != reasonPodsOutOfDate {
		t.Errorf("PodsUpToDate reason = %s, want %s", got.Reason, reasonPodsOutOfDate)
	}
}

// A pod injected before this feature carries no revision annotation, so it predates the settings.
func TestPodsWithoutAStartupRevisionAreOutOfDate(t *testing.T) {
	t.Parallel()

	policy := selectedPolicy()
	pod := currentPod(t, policy, true)
	delete(pod.Annotations, webhook.StartupRevisionAnnotation)

	r, c := newReconciler(t, namespace(nil), policy, pod)

	reconcile(t, r, "web")

	if got := getPolicy(t, c, "web").Status.OutOfDatePods; got != 1 {
		t.Errorf("outOfDatePods = %d, want 1", got)
	}
}

// This is what lets a rollout finish: a stale pod must not make the configuration unusable.
func TestStalePodsDoNotMakeTheRenderedConfigurationUnready(t *testing.T) {
	t.Parallel()

	policy := selectedPolicy()
	r, c := newReconciler(t, namespace(nil), policy, currentPod(t, policy, false))

	reconcile(t, r, "web")

	for _, conditionType := range []string{conditionReady, conditionConfigurationReady} {
		got := conditionOf(t, c, conditionType)
		if got.Status != metav1.ConditionTrue {
			t.Errorf("%s = %s (%s), want True while only the pods are stale", conditionType, got.Status, got.Reason)
		}
	}
}

func TestAnInvalidSpecMarksTheConfigurationUnready(t *testing.T) {
	t.Parallel()

	policy := selectedPolicy()
	policy.Spec.Egress = []v1alpha1.EgressRule{rule("bad", []string{"not a domain"}, nil)}

	r, c := newReconciler(t, namespace(nil), policy)

	reconcile(t, r, "web")

	for _, conditionType := range []string{conditionReady, conditionConfigurationReady} {
		got := conditionOf(t, c, conditionType)
		if got.Status != metav1.ConditionFalse || got.Reason != reasonInvalidPolicy {
			t.Errorf("%s = %s (%s), want False/%s", conditionType, got.Status, got.Reason, reasonInvalidPolicy)
		}
	}
}

// Conditions must report their generation, or admission cannot spot a status left by the old spec.
func TestConditionsCarryTheObservedGeneration(t *testing.T) {
	t.Parallel()

	policy := selectedPolicy()
	policy.Generation = 7

	r, c := newReconciler(t, namespace(nil), policy)

	reconcile(t, r, "web")

	for _, conditionType := range []string{conditionReady, conditionConfigurationReady, conditionPodsUpToDate} {
		if got := conditionOf(t, c, conditionType); got.ObservedGeneration != 7 {
			t.Errorf("%s observedGeneration = %d, want 7", conditionType, got.ObservedGeneration)
		}
	}
}

func TestPodRolloutConditionWording(t *testing.T) {
	t.Parallel()

	status, reason, message := podRolloutCondition(3, 0)
	if status != metav1.ConditionTrue || reason != reasonPodsCurrent || message == "" {
		t.Errorf("podRolloutCondition(3, 0) = %s/%s/%q", status, reason, message)
	}

	status, reason, message = podRolloutCondition(3, 2)
	if status != metav1.ConditionFalse || reason != reasonPodsOutOfDate {
		t.Errorf("podRolloutCondition(3, 2) = %s/%s", status, reason)
	}

	if want := "2 of 3"; !strings.Contains(message, want) {
		t.Errorf("message = %q, want it to report %q", message, want)
	}
}
