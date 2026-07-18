# Dashboard control-plane plan

The dashboard uses HTTP transports matched to each data flow. A WebSocket-only
protocol is deliberately out of scope: it would add connection recovery,
acknowledgement, replay, backpressure, and multi-node connection ownership
without improving g0efilter's durable delivery semantics.

## Transport decisions

| Flow | Transport | Reason |
| --- | --- | --- |
| Instance log delivery | Batched REST `POST` | Independent retries and bounded uploads survive dashboard outages. |
| Browser live events and status invalidation | SSE | The browser flow is server-to-client and already reconnects automatically. |
| Instance desired policy and commands | Bounded long-poll `POST /api/v1/sync?wait=30s` | Near-immediate delivery without a custom bidirectional protocol. The timeout also supplies the instance heartbeat. |
| Instance command acknowledgement | Idempotent REST `POST` | Explicit retry and deduplication behavior. |

Every reconcile reports the instance's current state and `config_hash`. The
dashboard returns immediately when desired state differs, wakes a waiting
request when an administrator changes relevant fleet state, or returns an
unchanged response when the bounded wait expires. Instances reconnect with
backoff after transport failures. The dashboard caps the requested wait so it
remains below common reverse-proxy timeouts.

SSE is an optimization, not the source of truth. The browser fetches snapshots
on initial load and after reconnecting. Likewise, an instance always reconciles
from persistent desired state after reconnecting; notifications do not need to
be durable.

## Delivery sequence

1. Keep REST log ingestion and browser SSE as separate data-plane paths.
2. Support bounded long-poll reconcile on the dashboard while retaining an
   immediate reconcile when `wait` is omitted for compatibility and tests.
3. Add the managed instance client using long-poll reconcile, bounded backoff,
   hashes, and atomic live policy application.
4. Fold remote-unblock delivery into reconcile as commands with stable IDs;
   retain the existing unblock poll endpoints during migration.
5. Remove the legacy instance unblock poll only after compatibility coverage is
   in place. Do not replace these paths with WebSockets.

## Current alignment

- REST log ingestion remains unchanged.
- Browser traffic and unblock-status invalidations use SSE; status snapshots
  recover state after initial load or reconnect.
- The dashboard supports bounded long-poll fleet reconciliation and wakes
  waiters after desired fleet state changes.
- The managed instance client and command unification are subsequent steps;
  current remote-unblock clients still use their documented compatibility poll.

Horizontal dashboard replication is a separate scaling milestone. Before that,
the SQLite store and in-process notification broadcaster are the practical
limits. A replicated deployment will require a shared store/event bus regardless
of whether client connections use SSE, long-polling, or WebSockets.
