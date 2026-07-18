#!/bin/sh
# Drops to a non-root user (default nobody, 65534). Override with PUID/PGID; set
# PUID=0 to stay root. NET_ADMIN/NET_RAW are kept as ambient caps so nftables and
# SO_MARK still work after the drop. Falls back to root if the caps needed to
# drop (SETUID/SETGID/SETPCAP) are absent, so it never fails closed.
set -eu

PUID="${PUID:-65534}"
PGID="${PGID:-65534}"

# Already non-root (compose set `user:`) or root explicitly requested: exec as-is.
if [ "$(id -u)" -ne 0 ] || [ "$PUID" = "0" ]; then
	exec /app/g0efilter "$@"
fi

drop="setpriv --reuid $PUID --regid $PGID --clear-groups \
	--inh-caps=+net_admin,+net_raw --ambient-caps=+net_admin,+net_raw"

if ! $drop -- true 2>/dev/null; then
	echo "g0efilter: cannot drop to uid $PUID (need cap_add SETUID,SETGID,SETPCAP); running as root" >&2
	exec /app/g0efilter "$@"
fi

# Hand the writable dirs to the runtime user (only it needs to write them; the
# binary stays root-owned and read-only).
for dir in /app/policy /app/data; do
	[ -d "$dir" ] && chown -R "$PUID:$PGID" "$dir" 2>/dev/null || true
done

exec $drop -- /app/g0efilter "$@"
