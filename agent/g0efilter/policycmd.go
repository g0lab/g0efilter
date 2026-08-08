package g0efilter

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/g0lab/g0efilter/agent/policy"
)

const configMapIndent = "    "

var errPolicyEmpty = errors.New("policy file is empty")

// HandlePolicy runs the `policy` subcommand: it validates the active policy file
// and prints it as a ConfigMap ready to apply. In learning mode this turns the
// learned allowlist into something committable without retyping it:
//
//	kubectl exec <pod> -c g0efilter -- /app/g0efilter policy | kubectl apply -f -
//
// Returns handled=true and the process exit code.
func HandlePolicy(args []string) (bool, int) {
	return handlePolicy(args, os.Stdout, os.Stderr)
}

func handlePolicy(args []string, out, errOut io.Writer) (bool, int) {
	if len(args) < 2 || args[1] != "policy" {
		return false, 0
	}

	path := policyCmdPath(args)

	// Validating first means a malformed learned policy fails here rather than on the
	// cluster, where a bad ConfigMap would take out the next pod that mounts it.
	pol, err := policy.ReadFile(path)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "g0efilter: cannot read %s: %v\n", path, err)

		return true, 1
	}

	raw, err := os.ReadFile(path) //nolint:gosec // the path is operator-supplied configuration
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "g0efilter: cannot read %s: %v\n", path, err)

		return true, 1
	}

	document := strings.TrimRight(string(raw), "\n")
	if strings.TrimSpace(document) == "" {
		_, _ = fmt.Fprintf(errOut, "g0efilter: %v: %s\n", errPolicyEmpty, path)

		return true, 1
	}

	_, _ = fmt.Fprint(out, renderConfigMap(configMapName(), podNamespace(), fileKey(path), document))

	_, _ = fmt.Fprintf(errOut, "g0efilter: %d allowed domains, %d allowed IPs from %s\n",
		len(pol.AllowDomains), len(pol.AllowIPs), path)

	return true, 0
}

// policyCmdPath prefers an explicit argument so the command also works against a
// policy file the running agent is not using.
func policyCmdPath(args []string) string {
	if len(args) > 2 && strings.TrimSpace(args[2]) != "" {
		return strings.TrimSpace(args[2])
	}

	if path := strings.TrimSpace(os.Getenv("POLICY_PATH")); path != "" {
		return path
	}

	if fileExists(fallbackPolicyPath) {
		return fallbackPolicyPath
	}

	return getenvDefault("POLICY_PATH", "/app/policy.yaml")
}

func configMapName() string {
	return getenvDefault("POLICY_CONFIGMAP", "g0efilter-policy")
}

// podNamespace comes from the downward API when the packaging supplies it; without
// it the ConfigMap is namespace-less and applies to whatever kubectl targets.
func podNamespace() string {
	return strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
}

// fileKey keeps the ConfigMap key equal to the mounted file name, which is what
// POLICY_PATH points at.
func fileKey(path string) string {
	parts := strings.Split(path, "/")

	name := parts[len(parts)-1]
	if name == "" {
		return "policy.yaml"
	}

	return name
}

func renderConfigMap(name, namespace, key, document string) string {
	var b strings.Builder

	b.WriteString("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ")
	b.WriteString(name)
	b.WriteString("\n")

	if namespace != "" {
		b.WriteString("  namespace: ")
		b.WriteString(namespace)
		b.WriteString("\n")
	}

	b.WriteString("data:\n  ")
	b.WriteString(key)
	b.WriteString(": |\n")

	for line := range strings.SplitSeq(document, "\n") {
		if line == "" {
			b.WriteString("\n")

			continue
		}

		b.WriteString(configMapIndent)
		b.WriteString(line)
		b.WriteString("\n")
	}

	return b.String()
}
