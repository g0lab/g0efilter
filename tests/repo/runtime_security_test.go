package repo_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

type composeService struct {
	CapAdd      []string `yaml:"cap_add"`      //nolint:tagliatelle // Docker Compose's key.
	CapDrop     []string `yaml:"cap_drop"`     //nolint:tagliatelle // Docker Compose's key.
	ReadOnly    bool     `yaml:"read_only"`    //nolint:tagliatelle // Docker Compose's key.
	SecurityOpt []string `yaml:"security_opt"` //nolint:tagliatelle // Docker Compose's key.
}

func readComposeServices(t *testing.T, name string) map[string]composeService {
	t.Helper()

	content, err := os.ReadFile(filepath.Join("..", "..", name)) //nolint:gosec // a fixed repository path
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	var compose struct {
		Services map[string]composeService `yaml:"services"`
	}

	err = yaml.Unmarshal(content, &compose)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}

	return compose.Services
}

func assertComposeSecurity(t *testing.T, service composeService, add []string) {
	t.Helper()

	if !service.ReadOnly {
		t.Error("root filesystem is writable")
	}

	if !reflect.DeepEqual(service.CapDrop, []string{"ALL"}) {
		t.Errorf("cap_drop = %v, want [ALL]", service.CapDrop)
	}

	if !reflect.DeepEqual(service.CapAdd, add) {
		t.Errorf("cap_add = %v, want %v", service.CapAdd, add)
	}

	if !reflect.DeepEqual(service.SecurityOpt, []string{"no-new-privileges"}) {
		t.Errorf("security_opt = %v, want [no-new-privileges]", service.SecurityOpt)
	}
}

func TestComposeImagesAreHardened(t *testing.T) {
	t.Parallel()

	published := readComposeServices(t, "examples/docker-compose.yaml")
	assertComposeSecurity(t, published["g0efilter"], []string{"NET_ADMIN"})
	assertComposeSecurity(t, published["g0efilter-dashboard"], nil)

	built := readComposeServices(t, "examples/build/docker-compose-build.yaml")
	assertComposeSecurity(t, built["g0efilter"], []string{"NET_ADMIN"})
	assertComposeSecurity(t, built["g0efilter-dashboard"], nil)
	assertComposeSecurity(t, built["g0efilter-controller"], nil)
}

func TestPodmanAgentIsHardened(t *testing.T) {
	t.Parallel()

	content, err := os.ReadFile(filepath.Join("..", "..", "examples", "podman", "g0efilter.container"))
	if err != nil {
		t.Fatalf("read Quadlet: %v", err)
	}

	unit := string(content)
	for _, setting := range []string{
		"DropCapability=ALL",
		"AddCapability=NET_ADMIN",
		"NoNewPrivileges=true",
		"ReadOnly=true",
	} {
		if !strings.Contains(unit, setting) {
			t.Errorf("Quadlet does not set %s", setting)
		}
	}
}
