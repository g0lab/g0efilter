#!/bin/sh
# Drops to a non-root user (default nobody, 65534). Override with PUID/PGID; set
# PUID=0 to stay root. NET_ADMIN is a hard runtime requirement (nftables + the
# SO_MARK dialer): without it the entrypoint exits rather than run unprotected. It
# is carried across the drop as an ambient cap. The startup-only caps SETUID/SETGID
# (switch user) and CHOWN (hand over the writable dirs) are used once and not
# retained; if they are missing the entrypoint warns and stays root.
set -eu

PUID="${PUID:-65534}"
PGID="${PGID:-65534}"

# NET_ADMIN (cap bit 12) is required whether or not we drop: without it the filter
# cannot program nftables and would fail open (traffic unfiltered), so exit rather
# than run unprotected.
if [ $(( 0x$(awk '/^CapEff:/{print $2}' /proc/self/status) & 0x1000 )) -eq 0 ]; then
	echo "g0efilter: ERROR: CAP_NET_ADMIN missing; cannot enforce filtering (add cap_add: NET_ADMIN)" >&2
	exit 1
fi
ambient="--inh-caps=+net_admin --ambient-caps=+net_admin"

# Already non-root (compose set `user:`) or root explicitly requested: exec as-is.
if [ "$(id -u)" -ne 0 ] || [ "$PUID" = "0" ]; then
	echo "g0efilter: running as uid:gid $(id -u):$(id -g)"
	exec /app/g0efilter "$@"
fi

drop="setpriv --reuid $PUID --regid $PGID --clear-groups $ambient"

if ! $drop -- true 2>/dev/null; then
	echo "g0efilter: cannot drop to uid $PUID (need cap_add SETUID,SETGID); running as root" >&2
	exec /app/g0efilter "$@"
fi

# Hand the writable dirs to the runtime user (only it needs to write them; the
# binary stays root-owned and read-only). Needs CAP_CHOWN.
for dir in /app/policy /app/data; do
	if [ -d "$dir" ] && ! chown -R "$PUID:$PGID" "$dir" 2>/dev/null; then
		echo "g0efilter: cannot chown $dir (need cap_add CHOWN); writes may fail" >&2
	fi
done

echo "g0efilter: running as uid:gid $PUID:$PGID${ambient:+ (retained cap: net_admin)}"
exec $drop -- /app/g0efilter "$@"
