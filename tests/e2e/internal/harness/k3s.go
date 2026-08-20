package harness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
)

const (
	k3sImage = "docker.io/rancher/k3s:latest"

	controllerImage = "g0efilter-controller:e2e"

	podsResource = "pods"

	k3sStartTimeout  = 5 * time.Minute
	kubectlTimeout   = 2 * time.Minute
	pollInterval     = 2 * time.Second
	readinessTimeout = 3 * time.Minute

	dockerBuildAttempts = 3
	dockerRetryDelay    = 2 * time.Second
)

var (
	errKubectlFailed          = errors.New("kubectl failed")
	errUnexpectedRBACDecision = errors.New("unexpected RBAC decision")
)

var controllerBuild struct { //nolint:gochecknoglobals // shared by parallel Kubernetes phases
	sync.Once

	err    error
	output []byte
}

// K8sEnabled reports whether the Kubernetes phase should run. It is opt-in: it starts
// a privileged k3s container, which is far heavier than the compose stack.
func K8sEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("E2E_K8S")), "true")
}

// RepoPath resolves a path relative to the repository root.
func RepoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

// K3sCluster is a running k3s container plus the kubeconfig to reach it.
type K3sCluster struct {
	container  *k3s.K3sContainer
	kubeconfig string
}

// StartK3s builds and loads the controller image, then starts a cluster.
func StartK3s(t *testing.T) *K3sCluster {
	t.Helper()

	buildControllerImage(t)

	ctx, cancel := context.WithTimeout(context.Background(), k3sStartTimeout)
	defer cancel()

	container, err := k3s.Run(ctx, k3sImage, testcontainers.WithAlwaysPull())
	if err != nil {
		t.Fatalf("start k3s: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()

		_ = container.Terminate(cleanupCtx)
	})

	raw, err := container.GetKubeConfig(ctx)
	if err != nil {
		t.Fatalf("get kubeconfig: %v", err)
	}

	path := filepath.Join(t.TempDir(), "kubeconfig")

	err = os.WriteFile(path, raw, 0o600)
	if err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}

	// Loading beats pulling: the image only exists on this machine.
	err = container.LoadImages(ctx, controllerImage)
	if err != nil {
		t.Fatalf("load %s into k3s: %v", controllerImage, err)
	}

	cluster := &K3sCluster{container: container, kubeconfig: path}
	cluster.WaitForNode(t)

	return cluster
}

// buildControllerImage builds the controller from source every run. E2E_BUILD is
// deliberately ignored: nothing pre-loads this image, so skipping the build only
// ever means testing the previous controller against the current tree.
func buildControllerImage(t *testing.T) {
	t.Helper()

	args := []string{
		"build",
		"-f", RepoPath("examples", "build", "Containerfile.controller"),
		"-t", controllerImage, RepoPath(),
	}

	controllerBuild.Do(func() {
		t.Logf("building %s", controllerImage)
		controllerBuild.output, controllerBuild.err = buildControllerWithRetry(t, args)
	})

	if controllerBuild.err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "),
			controllerBuild.err, controllerBuild.output)
	}
}

func buildControllerWithRetry(t *testing.T, args []string) ([]byte, error) {
	t.Helper()

	for attempt := 1; attempt <= dockerBuildAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), dockerTimeout)
		//nolint:gosec // fixed tool name with repository-owned arguments
		cmd := exec.CommandContext(ctx, "docker", args...)
		out, err := cmd.CombinedOutput()

		cancel()

		if err == nil || attempt == dockerBuildAttempts || !transientDockerFailure(out) {
			if err != nil {
				return out, fmt.Errorf("build controller image: %w", err)
			}

			return out, nil
		}

		t.Logf("docker build attempt %d/%d hit a transient registry failure; retrying in %s:\n%s",
			attempt, dockerBuildAttempts, dockerRetryDelay, out)
		time.Sleep(dockerRetryDelay)
	}

	panic("unreachable")
}

func transientDockerFailure(out []byte) bool {
	message := strings.ToLower(string(out))

	for _, marker := range []string{
		"tls handshake timeout",
		"i/o timeout",
		"connection reset by peer",
		"temporary failure in name resolution",
		"no such host",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}

	for _, status := range []string{
		"403 forbidden",
		"429 too many requests",
		"500 internal server error",
		"502 bad gateway",
		"503 service unavailable",
		"504 gateway timeout",
	} {
		if strings.Contains(message, status) &&
			(strings.Contains(message, "unexpected status from") ||
				strings.Contains(message, "failed to fetch anonymous token")) {
			return true
		}
	}

	return false
}

const dockerTimeout = 10 * time.Minute

// run executes a command and fails the test with its combined output.
func run(t *testing.T, timeout time.Duration, name string, args ...string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	//nolint:gosec // fixed tool names with literal arguments
	cmd := exec.CommandContext(ctx, name, args...)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// Kubectl runs kubectl against the cluster and returns its output.
func (c *K3sCluster) Kubectl(t *testing.T, args ...string) string {
	t.Helper()

	return c.kubectl(t, kubectlTimeout, args...)
}

// CanI checks the effective RBAC of a service account without granting the test
// process that identity.
func (c *K3sCluster) CanI(t *testing.T, serviceAccount, namespace, verb, resource string) bool {
	t.Helper()

	args := []string{
		"auth", "can-i", verb, resource,
		"--as=system:serviceaccount:g0efilter-system:" + serviceAccount,
	}
	if namespace != "" {
		args = append(args, "--namespace="+namespace)
	}

	stdout, stderr, err := c.tryKubectlStreams(args...)

	allowed, decisionErr := parseCanIDecision(stdout, stderr, err)
	if decisionErr != nil {
		t.Fatalf("kubectl %s: %v", strings.Join(args, " "), decisionErr)
	}

	return allowed
}

func parseCanIDecision(stdout, stderr string, commandErr error) (bool, error) {
	switch strings.TrimSpace(stdout) {
	case "yes":
		if commandErr != nil {
			return false, canICommandError(stderr, commandErr)
		}

		return true, nil
	case "no":
		var exitErr interface{ ExitCode() int }
		if commandErr == nil || (errors.As(commandErr, &exitErr) && exitErr.ExitCode() == 1) {
			return false, nil
		}

		return false, canICommandError(stderr, commandErr)
	default:
		if commandErr != nil {
			return false, canICommandError(stderr, commandErr)
		}

		return false, fmt.Errorf("%w: %q", errUnexpectedRBACDecision, stdout)
	}
}

func canICommandError(stderr string, _ error) error {
	if detail := strings.TrimSpace(stderr); detail != "" {
		return fmt.Errorf("%w: %s", errKubectlFailed, detail)
	}

	return errKubectlFailed
}

// Apply applies manifests from paths or flags.
func (c *K3sCluster) Apply(t *testing.T, args ...string) {
	t.Helper()

	c.Kubectl(t, append([]string{"apply"}, args...)...)
}

// ApplyKustomize builds an overlay and applies it.
func (c *K3sCluster) ApplyKustomize(t *testing.T, dir string) {
	t.Helper()

	c.Kubectl(t, "apply", "--server-side", "-k", dir)
}

// ApplyManifest applies inline YAML.
func (c *K3sCluster) ApplyManifest(t *testing.T, manifest string) {
	t.Helper()

	c.Kubectl(t, "apply", "-f", writeTemp(t, "manifest.yaml", manifest))
}

// writeTemp writes contents to a per-test temporary file and returns its path.
func writeTemp(t *testing.T, name, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)

	err := os.WriteFile(path, []byte(contents), 0o600)
	if err != nil {
		t.Fatalf("write %s: %v", name, err)
	}

	return path
}

// Get returns a single field via a jsonpath expression.
func (c *K3sCluster) Get(t *testing.T, namespace, kind, name, jsonpath string) string {
	t.Helper()

	out := c.Kubectl(t, "get", "-n", namespace, kind, name, "-o", "jsonpath="+jsonpath)

	return strings.TrimSpace(out)
}

// WaitForNode blocks until the single k3s node is ready.
func (c *K3sCluster) WaitForNode(t *testing.T) {
	t.Helper()

	c.kubectl(t, readinessTimeout, "wait", "--for=condition=Ready", "nodes", "--all",
		"--timeout="+readinessTimeout.String())
}

// WaitForCRDs blocks until each CRD is established, which is what makes its API
// usable; applying a custom resource before that fails with "no matches for kind".
func (c *K3sCluster) WaitForCRDs(t *testing.T, names ...string) {
	t.Helper()

	for _, name := range names {
		c.kubectl(t, readinessTimeout, "wait", "--for=condition=Established",
			"crd/"+name, "--timeout="+readinessTimeout.String())
	}
}

// WaitForDeployment blocks until a deployment reports Available.
func (c *K3sCluster) WaitForDeployment(t *testing.T, namespace, name string) {
	t.Helper()

	_, err := c.tryKubectl("wait", "--for=condition=Available", "-n", namespace,
		"deployment/"+name, "--timeout="+readinessTimeout.String())
	if err != nil {
		t.Fatalf("%s/%s never became available: %v\n%s", namespace, name, err,
			c.describeFailure(namespace, name))
	}
}

// WaitForConfigMapKey blocks until a ConfigMap key exists and returns its value.
func (c *K3sCluster) WaitForConfigMapKey(t *testing.T, namespace, name, key string) string {
	t.Helper()

	jsonpath := "jsonpath={.data['" + strings.ReplaceAll(key, ".", `\.`) + "']}"

	var last string

	deadline := time.Now().Add(readinessTimeout)

	for time.Now().Before(deadline) {
		out, err := c.tryKubectl("get", "-n", namespace, "configmap", name, "-o", jsonpath)
		if err == nil && strings.TrimSpace(out) != "" {
			return out
		}

		last = out

		time.Sleep(pollInterval)
	}

	t.Fatalf("ConfigMap %s/%s never gained key %s: %s", namespace, name, key, last)

	return ""
}

// WaitForConfigMapContains blocks until a rendered key contains a substring, which is
// how a re-reconcile triggered by another object is observed.
func (c *K3sCluster) WaitForConfigMapContains(t *testing.T, namespace, name, key, want string) {
	t.Helper()

	jsonpath := "jsonpath={.data['" + strings.ReplaceAll(key, ".", `\.`) + "']}"

	var last string

	deadline := time.Now().Add(readinessTimeout)

	for time.Now().Before(deadline) {
		out, err := c.tryKubectl("get", "-n", namespace, "configmap", name, "-o", jsonpath)
		if err == nil && strings.Contains(out, want) {
			return
		}

		last = out

		time.Sleep(pollInterval)
	}

	t.Fatalf("ConfigMap %s/%s key %s never contained %q:\n%s", namespace, name, key, want, last)
}

// WaitForAbsent blocks until an object is gone.
func (c *K3sCluster) WaitForAbsent(t *testing.T, namespace, kind, name string) {
	t.Helper()

	deadline := time.Now().Add(readinessTimeout)

	for time.Now().Before(deadline) {
		_, err := c.tryKubectl("get", "-n", namespace, kind, name)
		if err != nil {
			return
		}

		time.Sleep(pollInterval)
	}

	t.Fatalf("%s %s/%s still exists", kind, namespace, name)
}

func (c *K3sCluster) kubectl(t *testing.T, timeout time.Duration, args ...string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	//nolint:gosec // literal arguments supplied by the tests
	cmd := exec.CommandContext(ctx, "kubectl", args...)

	cmd.Env = append(os.Environ(), "KUBECONFIG="+c.kubeconfig)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, out)
	}

	return string(out)
}

// tryKubectl is the polling variant: it reports failure instead of ending the test.
func (c *K3sCluster) tryKubectl(args ...string) (string, error) {
	return c.tryKubectlTimeout(30*time.Second, args...)
}

func (c *K3sCluster) tryKubectlStreams(args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	//nolint:gosec // literal arguments supplied by the tests
	cmd := exec.CommandContext(ctx, "kubectl", args...)

	cmd.Env = append(os.Environ(), "KUBECONFIG="+c.kubeconfig)

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

func (c *K3sCluster) tryKubectlTimeout(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	//nolint:gosec // literal arguments supplied by the tests
	cmd := exec.CommandContext(ctx, "kubectl", args...)

	cmd.Env = append(os.Environ(), "KUBECONFIG="+c.kubeconfig)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%w: %s", errKubectlFailed, strings.TrimSpace(string(out)))
	}

	return string(out), nil
}

// describeFailure gathers the context needed to diagnose a deployment that never
// came up, since the wait error alone says nothing about why.
func (c *K3sCluster) describeFailure(namespace, name string) string {
	var b strings.Builder

	for _, args := range [][]string{
		{"describe", "-n", namespace, "deployment/" + name},
		{"get", "-n", namespace, podsResource, "-o", "wide"},
		{"logs", "-n", namespace, "deployment/" + name, "--all-containers", "--tail=50"},
	} {
		out, _ := c.tryKubectl(args...)

		_, _ = fmt.Fprintf(&b, "\n$ kubectl %s\n", strings.Join(args, " "))
		b.WriteString(out)
	}

	return b.String()
}
