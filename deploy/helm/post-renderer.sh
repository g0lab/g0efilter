#!/usr/bin/env bash
# Helm post-renderer that injects the g0efilter sidecar into a chart you do not
# control, so no fork and no values contract are needed:
#
#   helm install app oci://example.com/app \
#     --post-renderer deploy/helm/post-renderer.sh
#
# Helm pipes the rendered manifests in on stdin and expects the result on stdout.
# Point G0EFILTER_COMPONENT at a pinned remote ref to use this outside this repo:
#
#   G0EFILTER_COMPONENT='github.com/g0lab/g0efilter//deploy/kustomize/sidecar?ref=v0.9.4'
#
# The workload namespace still needs a g0efilter-policy ConfigMap and Pod Security
# `privileged`, exactly as with the Kustomize component.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPONENT="${G0EFILTER_COMPONENT:-$ROOT/deploy/kustomize/sidecar}"

command -v kubectl >/dev/null || {
	echo "post-renderer: kubectl is required" >&2
	exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat >"$WORK/rendered.yaml"

# Kustomize rejects absolute local paths, so a local component is copied in and
# referenced relatively. Remote refs are passed through untouched.
REF="$COMPONENT"
if [ -d "$COMPONENT" ]; then
	cp -r "$COMPONENT" "$WORK/component"
	REF="./component"
fi

cat >"$WORK/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - rendered.yaml
components:
  - $REF
EOF

kubectl kustomize "$WORK"
