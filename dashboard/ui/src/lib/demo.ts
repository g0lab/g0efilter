/* Static demo data, shared with the Go development tools. */
import scenariosData from '$demo/scenarios.json';
import type {
  LogEntry, BrowseResponse, AggregateResponse, AggregateRow, AggregateBucket,
} from './types';

export const DEMO = import.meta.env.VITE_DEMO_MODE === 'true';

interface Destination {
  domain: string; category: string; verdict: string;
  component: string; port: number; reason: string; ip: string;
}
interface Fixtures { source_subnet: string; clients: string[]; destinations: Destination[]; }

const fixtures = scenariosData as Fixtures;

const DAY = 86_400_000;
const DATASET_SIZE = 2400;
const VERDICTS = new Set(['ALLOWED', 'BLOCKED', 'AUDIT']);

function makeEntry(id: number, timeMs: number, dest: Destination, client: string, seq: number): LogEntry {
  return {
    id,
    time: new Date(timeMs).toISOString(),
    msg: 'flow.decision',
    action: dest.verdict,
    component: dest.component,
    http_host: dest.domain,
    https: dest.domain,
    source_ip: `${fixtures.source_subnet}.${Math.floor(seq / 250) % 4}.${(seq % 250) + 2}`,
    source_port: 1024 + (seq * 37) % 40000,
    destination_ip: dest.ip,
    destination_port: dest.port,
    protocol: 'TCP',
    hostname: client,
    flow_id: `demo-${seq + 1}`,
    version: 'demo',
    fields: {
      action: dest.verdict, component: dest.component, http_host: dest.domain,
      hostname: client, reason: dest.reason,
    },
  };
}

/* Ninety days of history, weighted toward the present and ordered newest first. */
const demoEvents: LogEntry[] = (() => {
  const now = Date.now();
  const dests = fixtures.destinations;
  const clients = fixtures.clients;
  const out: LogEntry[] = [];
  for (let k = 0; k < DATASET_SIZE; k++) {
    const frac = k / (DATASET_SIZE - 1);
    const age = (1 - frac) ** 2 * 90 * DAY;
    const dest = dests[(k * 7) % dests.length];
    const client = clients[(k * 3) % clients.length];
    out.push(makeEntry(k + 1, now - age, dest, client, k));
  }
  return out.reverse(); // newest first
})();

let liveSeq = DATASET_SIZE;

export function demoLiveEvent(): LogEntry {
  const dest = fixtures.destinations[liveSeq % fixtures.destinations.length];
  const client = fixtures.clients[(liveSeq * 3) % fixtures.clients.length];
  liveSeq += 1;
  return makeEntry(liveSeq, Date.now(), dest, client, liveSeq);
}

export function demoConfig(): Record<string, unknown> {
  return { auth_mode: 'none', fleet_enabled: false, buffer_size: DATASET_SIZE, read_limit: 500 };
}

const RANGES: Record<string, number> = {
  '15m': 15 * 60_000, '1h': 3_600_000, '6h': 6 * 3_600_000,
  '24h': DAY, '1d': DAY, '7d': 7 * DAY, '30d': 30 * DAY, '90d': 90 * DAY,
};

function rangeFromMs(range: string): number {
  const key = (range || '24h').toLowerCase();
  if (key === 'all') return 0;
  const span = RANGES[key] ?? DAY;
  return Date.now() - span;
}

function componentOf(e: LogEntry): string {
  const fromField = typeof e.fields === 'object' && e.fields
    ? String((e.fields as Record<string, unknown>).component ?? '')
    : '';
  return (e.component || fromField).toLowerCase();
}

function haystack(e: LogEntry): string {
  const f = typeof e.fields === 'object' && e.fields ? JSON.stringify(e.fields) : String(e.fields ?? '');
  return [
    e.msg, f, e.action, e.http_host, e.https, e.source_ip,
    e.destination_ip, e.hostname, e.protocol, e.src, e.dst,
  ].join('\n').toLowerCase();
}

function destKey(e: LogEntry): string {
  const host = e.http_host || e.https || e.dst;
  if (host) return host;
  if (!e.destination_ip) return '';
  return e.destination_port ? `${e.destination_ip}:${e.destination_port}` : e.destination_ip;
}

function dimensionKey(e: LogEntry, dimension: string): string {
  switch (dimension) {
    case 'client': return e.hostname || '';
    case 'ip': return e.destination_ip || '';
    case 'domain': return e.http_host || e.https || '';
    default: return destKey(e);
  }
}

export function demoBrowse(params: URLSearchParams): BrowseResponse {
  const fromMs = rangeFromMs(params.get('range') || '24h');
  const q = (params.get('q') || '').toLowerCase();
  const action = (params.get('action') || '').toUpperCase();
  const component = (params.get('component') || '').toLowerCase();
  const limit = Math.max(1, Math.min(Number(params.get('limit')) || 500, 5000));
  const offset = Math.max(0, Number(params.get('offset')) || 0);

  const matched = demoEvents.filter((e) => {
    const t = new Date(e.time ?? 0).getTime();
    if (fromMs && t < fromMs) return false;
    if (action && (e.action || '').toUpperCase() !== action) return false;
    if (component && componentOf(e) !== component) return false;
    if (q && !haystack(e).includes(q)) return false;
    return true;
  });

  return { total: matched.length, rows: matched.slice(offset, offset + limit) };
}

export function demoLogs(params: URLSearchParams): LogEntry[] {
  const limit = Math.max(1, Math.min(Number(params.get('limit')) || 500, 5000));
  return demoEvents.slice(0, limit);
}

function emptyAggregate(fromMs: number): AggregateResponse {
  return {
    from: new Date(fromMs || Date.now()).toISOString(),
    to: new Date().toISOString(),
    events: 0,
    totals: { allowed: 0, blocked: 0, audit: 0 },
    buckets: [],
    rows: [],
  };
}

function bump(counts: { allowed: number; blocked: number; audit: number }, verdict: string): void {
  if (verdict === 'ALLOWED') counts.allowed += 1;
  else if (verdict === 'BLOCKED') counts.blocked += 1;
  else if (verdict === 'AUDIT') counts.audit += 1;
}

export function demoAggregate(params: URLSearchParams): AggregateResponse {
  const fromMs = rangeFromMs(params.get('range') || '24h');
  const q = (params.get('q') || '').toLowerCase();
  const component = (params.get('component') || '').toLowerCase();
  const dimension = params.get('dimension') || '';

  const now = Date.now();
  const totals = { allowed: 0, blocked: 0, audit: 0 };
  const rowMap = new Map<string, AggregateRow>();
  const events: { t: number; verdict: string }[] = [];

  for (const e of demoEvents) {
    const t = new Date(e.time ?? 0).getTime();
    if (fromMs && t < fromMs) continue;
    const verdict = (e.action || '').toUpperCase();
    if (!VERDICTS.has(verdict)) continue;
    if (component && componentOf(e) !== component) continue;
    const key = dimensionKey(e, dimension);
    if (q && !key.toLowerCase().includes(q)) continue;

    bump(totals, verdict);
    events.push({ t, verdict });
    if (!key) continue;

    let row = rowMap.get(key);
    if (!row) { row = { key, last_seen: e.time ?? '', total: 0, allowed: 0, blocked: 0, audit: 0 }; rowMap.set(key, row); }
    row.total += 1;
    bump(row, verdict);
    if ((e.time ?? '') > row.last_seen) row.last_seen = e.time ?? '';
  }

  if (events.length === 0) return emptyAggregate(fromMs);

  const rows = [...rowMap.values()].sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));
  const lo = fromMs || Math.min(...events.map((x) => x.t));
  const hi = now;
  const span = Math.max(hi - lo, 60_000);
  const buckets: AggregateBucket[] = Array.from({ length: 24 }, (_, i) => ({
    start: new Date(lo + (i * span) / 24).toISOString(), allowed: 0, blocked: 0, audit: 0,
  }));
  for (const ev of events) {
    const idx = Math.min(23, Math.max(0, Math.floor(((ev.t - lo) * 24) / span)));
    bump(buckets[idx], ev.verdict);
  }

  return {
    from: new Date(lo).toISOString(),
    to: new Date(hi).toISOString(),
    events: events.length,
    totals,
    buckets,
    rows,
  };
}
