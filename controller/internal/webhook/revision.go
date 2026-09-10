package webhook

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/g0lab/g0efilter/controller/api/v1alpha1"
)

// StartupRevisionAnnotation identifies settings that cannot be reloaded in place.
const StartupRevisionAnnotation = "g0efilter.g0lab.com/startup-revision"

// StartupRevision excludes settings the live policy document delivers; the prefix marks the schema.
func StartupRevision(spec v1alpha1.SidecarSpec, defaults Defaults, configMap string) (string, error) {
	startup := spec.DeepCopy()
	startup.Mode = ""
	startup.Enforcement = ""
	startup.DNS = v1alpha1.DNSSpec{}

	data, err := json.Marshal(container(resolve(*startup, defaults), configMap))
	if err != nil {
		return "", fmt.Errorf("hash the sidecar's startup settings: %w", err)
	}

	return fmt.Sprintf("runtime-v1:%x", sha256.Sum256(data)), nil
}
