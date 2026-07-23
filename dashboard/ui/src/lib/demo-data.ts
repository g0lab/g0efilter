import type {
  AggregateBucket, AggregateResponse, AggregateRow, BrowseResponse, DashboardConfig, LogEntry,
} from './types';

export interface DemoDestination {
  domain: string;
  category: string;
  verdict: string;
  component: string;
  port: number;
  reason: string;
  ip: string;
}

export interface DemoFixtures {
  source_subnet: string;
  clients: string[];
  destinations: DemoDestination[];
}

export interface DemoRuntime {
  liveEvent(): LogEntry;
  config(): DashboardConfig;
  logs(params: URLSearchParams): LogEntry[];
  browse(params: URLSearchParams): BrowseResponse;
  aggregate(params: URLSearchParams): AggregateResponse;
}

interface DemoRuntimeOptions {
  datasetSize?: number;
  now?: () => number;
}

const DAY = 86_400_000;
const DEFAULT_DATASET_SIZE = 2400;
const VERDICTS = new Set(['ALLOWED', 'BLOCKED', 'AUDIT']);
const RANGES: Record<string, number> = {
  '15m': 15 * 60_000,
  '1h': 3_600_000,
  '6h': 6 * 3_600_000,
  '24h': DAY,
  '1d': DAY,
  '7d': 7 * DAY,
  '30d': 30 * DAY,
  '90d': 90 * DAY,
};

function componentOf(entry: LogEntry): string {
  const fromField = typeof entry.fields === 'object' && entry.fields
    ? String((entry.fields as Record<string, unknown>).component ?? '')
    : '';
  return (entry.component || fromField).toLowerCase();
}

function haystack(entry: LogEntry): string {
  const fields = typeof entry.fields === 'object' && entry.fields
    ? JSON.stringify(entry.fields)
    : String(entry.fields ?? '');
  return [
    entry.msg, fields, entry.action, entry.http_host, entry.https, entry.source_ip,
    entry.destination_ip, entry.hostname, entry.protocol, entry.src, entry.dst,
  ].join('\n').toLowerCase();
}

function destinationKey(entry: LogEntry): string {
  const host = entry.http_host || entry.https || entry.dst;
  if (host) return host;
  if (!entry.destination_ip) return '';
  return entry.destination_port
    ? `${entry.destination_ip}:${entry.destination_port}`
    : entry.destination_ip;
}

function dimensionKey(entry: LogEntry, dimension: string): string {
  switch (dimension) {
    case 'client': return entry.hostname || '';
    case 'ip': return entry.destination_ip || '';
    case 'domain': return entry.http_host || entry.https || '';
    default: return destinationKey(entry);
  }
}

function bump(counts: { allowed: number; blocked: number; audit: number }, verdict: string): void {
  if (verdict === 'ALLOWED') counts.allowed += 1;
  else if (verdict === 'BLOCKED') counts.blocked += 1;
  else if (verdict === 'AUDIT') counts.audit += 1;
}

export function createDemoRuntime(
  fixtures: DemoFixtures,
  options: DemoRuntimeOptions = {},
): DemoRuntime {
  if (fixtures.destinations.length === 0 || fixtures.clients.length === 0) {
    throw new Error('demo fixtures require destinations and clients');
  }

  const datasetSize = Math.max(2, options.datasetSize ?? DEFAULT_DATASET_SIZE);
  const currentTime = options.now ?? Date.now;

  function makeEntry(
    id: number,
    timeMs: number,
    destination: DemoDestination,
    client: string,
    sequence: number,
  ): LogEntry {
    const sourceIp = `${fixtures.source_subnet}.${Math.floor(sequence / 250) % 4}.${(sequence % 250) + 2}`;
    const sourcePort = 1024 + (sequence * 37) % 40000;
    const baseFields: Record<string, unknown> = {
      action: destination.verdict,
      component: destination.component,
      hostname: client,
      reason: destination.reason,
    };
    const entry: LogEntry = {
      id,
      time: new Date(timeMs).toISOString(),
      action: destination.verdict,
      component: destination.component,
      source_ip: sourceIp,
      source_port: sourcePort,
      hostname: client,
      flow_id: `demo-${sequence + 1}`,
      version: 'v0.demo',
      fields: baseFields,
    };

    if (destination.component === 'dns') {
      entry.msg = `dns.${destination.verdict.toLowerCase()}`;
      entry.https = destination.domain;
      entry.protocol = 'UDP';
      entry.fields = { ...baseFields, qname: destination.domain, qtype: 'A' };
      return entry;
    }

    entry.protocol = 'TCP';
    entry.destination_ip = destination.ip;
    entry.destination_port = destination.port;
    entry.dst = `${destination.ip}:${destination.port}`;

    if (destination.component === 'nflog') {
      entry.msg = 'nflog.event';
      entry.src = `${sourceIp}:${sourcePort}`;
      entry.fields = {
        ...baseFields,
        protocol: 'TCP',
        source_ip: sourceIp,
        source_port: sourcePort,
        destination_ip: destination.ip,
        destination_port: destination.port,
      };
      return entry;
    }

    entry.msg = `${destination.component}.${destination.verdict.toLowerCase()}`;
    entry.https = destination.domain;
    if (destination.component === 'http') entry.http_host = destination.domain;
    entry.fields = {
      ...baseFields,
      [destination.component === 'http' ? 'host' : 'https']: destination.domain,
    };
    return entry;
  }

  const generatedAt = currentTime();
  const events: LogEntry[] = [];
  for (let sequence = 0; sequence < datasetSize; sequence += 1) {
    const fraction = sequence / (datasetSize - 1);
    const age = (1 - fraction) ** 2 * 90 * DAY;
    const destination = fixtures.destinations[(sequence * 7) % fixtures.destinations.length];
    const client = fixtures.clients[(sequence * 3) % fixtures.clients.length];
    events.push(makeEntry(sequence + 1, generatedAt - age, destination, client, sequence));
  }
  events.reverse();

  let liveSequence = datasetSize;

  function rangeStart(range: string, nowMs: number): number {
    const key = (range || '24h').toLowerCase();
    if (key === 'all') return 0;
    return nowMs - (RANGES[key] ?? DAY);
  }

  function liveEvent(): LogEntry {
    const sequence = liveSequence;
    const destination = fixtures.destinations[sequence % fixtures.destinations.length];
    const client = fixtures.clients[(sequence * 3) % fixtures.clients.length];
    liveSequence += 1;

    const event = makeEntry(sequence + 1, currentTime(), destination, client, sequence);
    events.unshift(event);
    if (events.length > datasetSize) events.pop();
    return event;
  }

  function config(): DashboardConfig {
    return {
      auth_mode: 'none',
      fleet_enabled: false,
      buffer_size: datasetSize,
      read_limit: 500,
    };
  }

  function logs(params: URLSearchParams): LogEntry[] {
    const limit = Math.max(1, Math.min(Number(params.get('limit')) || 500, 5000));
    return events.slice(0, limit);
  }

  function browse(params: URLSearchParams): BrowseResponse {
    const fromMs = rangeStart(params.get('range') || '24h', currentTime());
    const query = (params.get('q') || '').toLowerCase();
    const action = (params.get('action') || '').toUpperCase();
    const component = (params.get('component') || '').toLowerCase();
    const limit = Math.max(1, Math.min(Number(params.get('limit')) || 500, 5000));
    const offset = Math.max(0, Number(params.get('offset')) || 0);

    const matched = events.filter((entry) => {
      const timestamp = new Date(entry.time ?? 0).getTime();
      if (fromMs && timestamp < fromMs) return false;
      if (action && (entry.action || '').toUpperCase() !== action) return false;
      if (component && componentOf(entry) !== component) return false;
      if (query && !haystack(entry).includes(query)) return false;
      return true;
    });

    return { total: matched.length, rows: matched.slice(offset, offset + limit) };
  }

  function emptyAggregate(fromMs: number, nowMs: number): AggregateResponse {
    return {
      from: new Date(fromMs || nowMs).toISOString(),
      to: new Date(nowMs).toISOString(),
      events: 0,
      totals: { allowed: 0, blocked: 0, audit: 0 },
      buckets: [],
      rows: [],
    };
  }

  function aggregate(params: URLSearchParams): AggregateResponse {
    const nowMs = currentTime();
    const fromMs = rangeStart(params.get('range') || '24h', nowMs);
    const query = (params.get('q') || '').toLowerCase();
    const component = (params.get('component') || '').toLowerCase();
    const dimension = params.get('dimension') || '';
    const totals = { allowed: 0, blocked: 0, audit: 0 };
    const rowMap = new Map<string, AggregateRow>();
    const matchedEvents: { timestamp: number; verdict: string }[] = [];

    for (const entry of events) {
      const timestamp = new Date(entry.time ?? 0).getTime();
      if (fromMs && timestamp < fromMs) continue;
      const verdict = (entry.action || '').toUpperCase();
      if (!VERDICTS.has(verdict)) continue;
      if (component && componentOf(entry) !== component) continue;
      const key = dimensionKey(entry, dimension);
      if (query && !key.toLowerCase().includes(query)) continue;

      bump(totals, verdict);
      matchedEvents.push({ timestamp, verdict });
      if (!key) continue;

      let row = rowMap.get(key);
      if (!row) {
        row = { key, last_seen: entry.time ?? '', total: 0, allowed: 0, blocked: 0, audit: 0 };
        rowMap.set(key, row);
      }
      row.total += 1;
      bump(row, verdict);
      if ((entry.time ?? '') > row.last_seen) row.last_seen = entry.time ?? '';
    }

    if (matchedEvents.length === 0) return emptyAggregate(fromMs, nowMs);

    const rows = [...rowMap.values()]
      .sort((a, b) => b.total - a.total || a.key.localeCompare(b.key));
    const lowerBound = fromMs || Math.min(...matchedEvents.map((event) => event.timestamp));
    const span = Math.max(nowMs - lowerBound, 60_000);
    const buckets: AggregateBucket[] = Array.from({ length: 24 }, (_, index) => ({
      start: new Date(lowerBound + (index * span) / 24).toISOString(),
      allowed: 0,
      blocked: 0,
      audit: 0,
    }));

    for (const event of matchedEvents) {
      const index = Math.min(
        23,
        Math.max(0, Math.floor(((event.timestamp - lowerBound) * 24) / span)),
      );
      bump(buckets[index], event.verdict);
    }

    return {
      from: new Date(lowerBound).toISOString(),
      to: new Date(nowMs).toISOString(),
      events: matchedEvents.length,
      totals,
      buckets,
      rows,
    };
  }

  return { liveEvent, config, logs, browse, aggregate };
}
