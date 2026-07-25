#!/usr/bin/env bash
# Entrypoint privilege drop: the container drops to a non-root user when it has
# the startup caps, falls back to root without them (fail-closed only when
# ALLOW_ROOT_FALLBACK=false), and requires effective NET_ADMIN either way.
# Runs the real image entrypoint directly under different cap sets; `healthcheck`
# makes the binary exit at once, so we only observe the entrypoint's startup log.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

if [ "$FILTER_MODE" != "https" ]; then
  log "Skipping entrypoint-caps phase in $FILTER_MODE matrix (runs once, in the https lane)"
  exit 0
fi

log "=== Phase 15: entrypoint capability drop ==="

IMAGE="g0efilter:e2e"

caps_run() {
  timeout 30 docker run --rm --cap-drop=ALL "$@" "$IMAGE" healthcheck 2>&1 || true
}

log "[caps] Full set (NET_ADMIN,SETUID,SETGID,CHOWN) drops to nobody, keeps net_admin"
OUT=$(caps_run --cap-add=NET_ADMIN --cap-add=SETUID --cap-add=SETGID --cap-add=CHOWN)
echo "$OUT" | grep -q "running as uid:gid 65534:65534 (retained cap: net_admin)" \
  || fail "full caps did not drop to nobody: $OUT"

log "[caps] Missing SETUID/SETGID falls back to root by default (with a warning)"
OUT=$(caps_run --cap-add=NET_ADMIN --cap-add=CHOWN)
echo "$OUT" | grep -q "running as root (weakens container isolation; set ALLOW_ROOT_FALLBACK=false to fail closed)" \
  || fail "missing drop caps did not fall back to root: $OUT"

log "[caps] Missing SETUID/SETGID with ALLOW_ROOT_FALLBACK=false fails closed (non-zero exit)"
OUT=$(timeout 30 docker run --rm --cap-drop=ALL -e ALLOW_ROOT_FALLBACK=false --cap-add=NET_ADMIN --cap-add=CHOWN "$IMAGE" healthcheck 2>&1) && RC=0 || RC=$?
echo "$OUT" | grep -q "ALLOW_ROOT_FALLBACK=false, refusing to run as root" \
  || fail "ALLOW_ROOT_FALLBACK=false did not fail closed: $OUT"
[ "$RC" -ne 0 ] || fail "ALLOW_ROOT_FALLBACK=false should exit non-zero, got $RC"

log "[caps] Pre-set non-root user without effective NET_ADMIN fails closed"
# Docker's --cap-add does not make a capability effective after switching to a
# non-root --user (the kernel clears it on the uid change and Docker sets no
# ambient cap), so the entrypoint must abort rather than run unprotected.
OUT=$(timeout 30 docker run --rm --cap-drop=ALL --cap-add=NET_ADMIN --user 65534:65534 "$IMAGE" healthcheck 2>&1) && RC=0 || RC=$?
echo "$OUT" | grep -q "CAP_NET_ADMIN missing" \
  || fail "pre-set non-root user without effective cap did not fail closed: $OUT"
[ "$RC" -ne 0 ] || fail "pre-set non-root user without effective cap should exit non-zero, got $RC"

log "[caps] Non-numeric PUID is rejected before startup"
OUT=$(caps_run -e PUID=nobody --cap-add=NET_ADMIN --cap-add=SETUID --cap-add=SETGID --cap-add=CHOWN)
echo "$OUT" | grep -q "PUID must be a non-negative integer" \
  || fail "non-numeric PUID was not rejected: $OUT"

log "[caps] Missing NET_ADMIN aborts startup (fail closed, non-zero exit)"
OUT=$(timeout 30 docker run --rm --cap-drop=ALL --cap-add=SETUID --cap-add=SETGID --cap-add=CHOWN "$IMAGE" healthcheck 2>&1) && RC=0 || RC=$?
echo "$OUT" | grep -q "ERROR: CAP_NET_ADMIN missing" \
  || fail "missing NET_ADMIN did not error: $OUT"
[ "$RC" -ne 0 ] || fail "missing NET_ADMIN should exit non-zero, got $RC"

log "[caps] PUID=0 stays root explicitly"
OUT=$(caps_run -e PUID=0 --cap-add=NET_ADMIN)
echo "$OUT" | grep -q "running as uid:gid 0:0" \
  || fail "PUID=0 did not report running as root: $OUT"

log "OK: entrypoint capability drop scenarios passed"
