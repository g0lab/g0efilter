#!/usr/bin/env bash
# Regenerates the controller's deepcopy methods and CRD manifests from the Go types
# in controller/api. Run after changing anything under controller/api/.
#   scripts/gen-controller.sh
# controller-gen is a tool dependency of the controller module, so its version is
# pinned in controller/go.mod and tracked by Dependabot.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/controller"

echo ">>> deepcopy methods"
GOWORK=off go tool controller-gen object paths="./api/..."

echo ">>> CRD manifests"
GOWORK=off go tool controller-gen crd paths="./api/..." output:crd:artifacts:config="$ROOT/deploy/crds"

echo ">>> RBAC"
GOWORK=off go tool controller-gen rbac:roleName=g0efilter-controller paths="./internal/..." \
	output:rbac:artifacts:config="$ROOT/deploy/controller"

# The controller chart installs the same CRDs from its own templates, so they are
# wrapped rather than copied: deploy/crds stays the single source of truth.
echo ">>> chart CRD templates"
"$ROOT/scripts/gen-chart-crds.sh" "$ROOT"

echo ">>> tidy"
GOWORK=off go mod tidy
