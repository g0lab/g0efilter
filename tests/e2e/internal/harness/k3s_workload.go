package harness

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// AgentImage is the tag the agent image is loaded into k3s under.
const AgentImage = "g0efilter:e2e"

// LoadAgentImage retags the compose-built agent image and loads it into the cluster,
// so the pod tests exercise the same binary the other phases do.
func (k *K3sCluster) LoadAgentImage(t *testing.T, source string) {
	t.Helper()

	run(t, dockerTimeout, "docker", "tag", source, AgentImage)

	ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
	defer cancel()

	err := k.container.LoadImages(ctx, AgentImage)
	if err != nil {
		t.Fatalf("load %s into k3s: %v", AgentImage, err)
	}
}

// TryApplyManifest applies YAML and returns the error instead of failing, for the
// cases where rejection is the expected outcome.
func (k *K3sCluster) TryApplyManifest(t *testing.T, manifest string) (string, error) {
	t.Helper()

	path := writeTemp(t, "manifest.yaml", manifest)

	return k.tryKubectl("apply", "-f", path)
}

// WaitForPodReady blocks until a pod matching the selector is Ready.
func (k *K3sCluster) WaitForPodReady(t *testing.T, namespace, selector string) string {
	t.Helper()

	deadline := time.Now().Add(readinessTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("no pod for %s appeared in %s\n%s", selector, namespace,
				k.describePods(namespace))
		}

		out, err := k.tryKubectlTimeout(min(30*time.Second, remaining),
			"get", "-n", namespace, "pod", "-l", selector, "-o", "name")
		if err == nil && strings.TrimSpace(out) != "" {
			break
		}

		remaining = time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("no pod for %s appeared in %s\n%s", selector, namespace,
				k.describePods(namespace))
		}

		time.Sleep(min(pollInterval, remaining))
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		t.Fatalf("no ready pod for %s in %s\n%s", selector, namespace,
			k.describePods(namespace))
	}

	_, err := k.tryKubectlTimeout(remaining, "wait", "--for=condition=Ready", "-n", namespace,
		"pod", "-l", selector, "--timeout="+remaining.String())
	if err != nil {
		t.Fatalf("no ready pod for %s in %s: %v\n%s", selector, namespace, err,
			k.describePods(namespace))
	}

	return k.PodName(t, namespace, selector)
}

// PodName returns the first pod matching a selector.
func (k *K3sCluster) PodName(t *testing.T, namespace, selector string) string {
	t.Helper()

	out := k.Kubectl(t, "get", "-n", namespace, podsResource, "-l", selector,
		"-o", "jsonpath={.items[0].metadata.name}")

	name := strings.TrimSpace(out)
	if name == "" {
		t.Fatalf("no pod matched %s in %s", selector, namespace)
	}

	return name
}

// describePods gathers pod state for a failure message.
func (k *K3sCluster) describePods(namespace string) string {
	var b strings.Builder

	for _, args := range [][]string{
		{"get", "-n", namespace, podsResource, "-o", "wide"},
		{"describe", "-n", namespace, podsResource},
	} {
		out, _ := k.tryKubectl(args...)

		_, _ = fmt.Fprintf(&b, "\n$ kubectl %s\n", strings.Join(args, " "))
		b.WriteString(out)
	}

	return b.String()
}

// Exec runs a command in a pod container and returns its output and whether it
// succeeded, so a blocked request can be asserted without ending the test.
func (k *K3sCluster) Exec(t *testing.T, namespace, pod, container string, command ...string) (string, bool) {
	t.Helper()

	args := append([]string{"exec", "-n", namespace, pod, "-c", container, "--"}, command...)

	out, err := k.tryKubectl(args...)

	return out, err == nil
}

// CurlExternal retries an expected-success request because public DNS, CDNs and
// origins are outside the test's control. Block assertions deliberately use Exec:
// an upstream outage must never count as proof that g0efilter denied a request.
func (k *K3sCluster) CurlExternal(t *testing.T, namespace, pod, container, url string) (string, bool) {
	t.Helper()

	return k.Exec(t, namespace, pod, container,
		"curl", "-fsS", "-o", "/dev/null",
		"--connect-timeout", "5", "--max-time", "20",
		"--retry", "2", "--retry-delay", "2", "--retry-all-errors",
		url)
}

// PodLogs returns a container's logs.
func (k *K3sCluster) PodLogs(t *testing.T, namespace, pod, container string) string {
	t.Helper()

	out, _ := k.tryKubectl("logs", "-n", namespace, pod, "-c", container, "--tail=200")

	return out
}

// WaitForPodLog blocks until a container's logs contain a substring.
func (k *K3sCluster) WaitForPodLog(t *testing.T, namespace, pod, container, want string) {
	t.Helper()

	deadline := time.Now().Add(readinessTimeout)

	var last string

	for time.Now().Before(deadline) {
		last = k.PodLogs(t, namespace, pod, container)
		if strings.Contains(last, want) {
			return
		}

		time.Sleep(pollInterval)
	}

	t.Fatalf("%s/%s (%s) logs never contained %q:\n%s", namespace, pod, container, want, last)
}

// WaitForEvent blocks until an Event with the given reason exists for a pod.
func (k *K3sCluster) WaitForEvent(t *testing.T, namespace, pod, reason string) string {
	t.Helper()

	deadline := time.Now().Add(readinessTimeout)

	var last string

	for time.Now().Before(deadline) {
		out, err := k.tryKubectl("get", "-n", namespace, "events",
			"--field-selector", "involvedObject.name="+pod+",reason="+reason,
			"-o", "jsonpath={.items[*].message}")
		if err == nil && strings.TrimSpace(out) != "" {
			return out
		}

		last = out

		time.Sleep(pollInterval)
	}

	t.Fatalf("no %s event for %s/%s: %s", reason, namespace, pod, last)

	return ""
}
