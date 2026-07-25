#!/bin/sh
# Drops to a non-root user (default nobody 65534; PUID/PGID override, PUID=0 stays
# root). NET_ADMIN is required at runtime and carried across the drop as an ambient
# cap. SETUID/SETGID/CHOWN are used once for the drop and not retained; if they are
# missing the entrypoint falls back to root (ALLOW_ROOT_FALLBACK=false fails closed
# instead - more secure, but breaks deployments without those caps).
set -eu

PUID="${PUID:-65534}"
PGID="${PGID:-65534}"
ALLOW_ROOT_FALLBACK="${ALLOW_ROOT_FALLBACK:-true}"

# Reject non-numeric PUID/PGID: they are passed unquoted as setpriv IDs.
is_uint() {
	case "$1" in
	'' | *[!0-9]*) return 1 ;;
	*) return 0 ;;
	esac
}

if ! is_uint "$PUID"; then
	echo "g0efilter: ERROR: PUID must be a non-negative integer (got '$PUID')" >&2
	exit 1
fi

if ! is_uint "$PGID"; then
	echo "g0efilter: ERROR: PGID must be a non-negative integer (got '$PGID')" >&2
	exit 1
fi

# NET_ADMIN (cap bit 12) is required whether or not we drop: without it filtering
# fails open, so exit rather than run unprotected.
if [ $(( 0x$(awk '/^CapEff:/{print $2}' /proc/self/status) & 0x1000 )) -eq 0 ]; then
	echo "g0efilter: ERROR: CAP_NET_ADMIN missing; cannot enforce filtering (add cap_add: NET_ADMIN)" >&2
	exit 1
fi

# Already non-root with effective NET_ADMIN (docker --user + --cap-add does not
# grant it effectively - caught by the check above). Make it ambient so it
# survives execve of the unprivileged binary.
if [ "$(id -u)" -ne 0 ]; then
	echo "g0efilter: running as uid:gid $(id -u):$(id -g)"
	exec setpriv --inh-caps=-all,+net_admin --ambient-caps=-all,+net_admin -- /app/g0efilter "$@"
fi

# Explicit root (PUID=0): caps survive execve for root, so no ambient handling.
if [ "$PUID" = "0" ]; then
	echo "g0efilter: running as uid:gid 0:0"
	exec /app/g0efilter "$@"
fi

# Root: drop to PUID:PGID carrying only NET_ADMIN. Needs SETUID/SETGID to switch
# user. On failure fall back to root by default; ALLOW_ROOT_FALLBACK=false makes
# this fail closed instead.
if ! setpriv --reuid "$PUID" --regid "$PGID" --clear-groups \
	--inh-caps=-all,+net_admin --ambient-caps=-all,+net_admin -- true 2>/dev/null; then
	if [ "$ALLOW_ROOT_FALLBACK" = "false" ]; then
		echo "g0efilter: ERROR: cannot drop to uid $PUID (need cap_add SETUID,SETGID); ALLOW_ROOT_FALLBACK=false, refusing to run as root" >&2
		exit 1
	fi

	echo "g0efilter: WARNING: cannot drop to uid $PUID (need cap_add SETUID,SETGID); running as root (weakens container isolation; set ALLOW_ROOT_FALLBACK=false to fail closed)" >&2
	exec /app/g0efilter "$@"
fi

# Hand the writable dirs to the runtime user (only it needs to write them; the
# binary stays root-owned and read-only). Needs CAP_CHOWN.
for dir in /app/policy /app/data; do
	if [ -d "$dir" ] && ! chown -R "$PUID:$PGID" "$dir" 2>/dev/null; then
		echo "g0efilter: cannot chown $dir (need cap_add CHOWN); writes may fail" >&2
	fi
done

echo "g0efilter: running as uid:gid $PUID:$PGID (retained cap: net_admin)"
exec setpriv --reuid "$PUID" --regid "$PGID" --clear-groups \
	--inh-caps=-all,+net_admin --ambient-caps=-all,+net_admin -- /app/g0efilter "$@"
