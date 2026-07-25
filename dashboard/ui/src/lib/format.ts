/* Pure helpers for log entries. Svelte escapes all interpolated text, so no
   HTML/JS escaping helpers are needed here. */
import type { LogEntry } from './types';

export function rel(t: string | number): string {
  const d = Date.now() - new Date(t).getTime();
  if (!isFinite(d)) return '';
  const s = Math.floor(d / 1000);
  if (s < 60) return s + 's';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm';
  const h = Math.floor(m / 60);
  if (h < 24) return h + 'h';
  return Math.floor(h / 24) + 'd';
}

export function sanitizeRemoteData(s: unknown): string {
  if (s === null || s === undefined) return '';
  return String(s).substring(0, 1000); // limit length to prevent DoS
}

export function norm(it: LogEntry): LogEntry {
  try {
    if (it && typeof it.fields === 'string' && it.fields && it.fields !== 'null') {
      it.fields = JSON.parse(it.fields);
    }
  } catch { /* ignore parse errors */ }
  return it;
}

function fields(it: LogEntry): Record<string, unknown> {
  return (it && typeof it.fields === 'object' && it.fields) || {};
}

export function getAction(it: LogEntry): string {
  return sanitizeRemoteData(it && (it.action || fields(it).action || '')).toUpperCase();
}

export function getComp(it: LogEntry): string {
  return sanitizeRemoteData(it && (it.component || fields(it).component || '')).toLowerCase();
}

export function hostOf(it: LogEntry): string {
  const f = fields(it);
  return sanitizeRemoteData(
    (it && (it.http_host || it.host || it.https || it.qname)) ||
    f.http_host || f.host || f.https || f.qname || ''
  );
}

export function joinHostPort(ip: string, port: number | string): string {
  return ip && ip.indexOf(':') !== -1 && ip.indexOf('[') === -1
    ? '[' + ip + ']:' + port
    : ip + ':' + port;
}

export function dstOf(it: LogEntry): string {
  if (it && it.dst) return sanitizeRemoteData(it.dst);
  if (it && it.destination_ip && it.destination_port) {
    return sanitizeRemoteData(joinHostPort(it.destination_ip, it.destination_port));
  }
  return it && it.destination_ip ? sanitizeRemoteData(it.destination_ip) : '';
}

export function srcOf(it: LogEntry): string {
  if (it && it.src) return sanitizeRemoteData(it.src);
  if (it && it.source_ip && it.source_port) {
    return sanitizeRemoteData(joinHostPort(it.source_ip, it.source_port));
  }
  return it && it.source_ip ? sanitizeRemoteData(it.source_ip) : '';
}

export function hostnameOf(it: LogEntry): string {
  return sanitizeRemoteData(it.hostname || fields(it).hostname || '');
}

export function flowIdOf(it: LogEntry): string {
  return sanitizeRemoteData(it.flow_id || fields(it).flow_id || '');
}

export function versionOf(it: LogEntry): string {
  return sanitizeRemoteData(it.version || fields(it).version || '');
}

export function protoOf(it: LogEntry): string {
  return sanitizeRemoteData(it.protocol || fields(it).protocol || '').toUpperCase();
}

export function whenOf(it: LogEntry): string {
  return it.time || it.ts || new Date().toISOString();
}

export function sanitizeInput(s: unknown): string {
  if (!s) return '';
  return String(s).slice(0, 200).replace(/[^\w\s\-.:@]/g, '');
}

export function matches(it: LogEntry, action: string, comp: string, query: string): boolean {
  const act = getAction(it);
  if (action && act !== action) return false;
  const c = getComp(it);
  if (comp && c !== comp) return false;
  if (!query) return true;
  const hay = [act, c, hostOf(it), srcOf(it), dstOf(it), hostnameOf(it), flowIdOf(it), versionOf(it), protoOf(it)]
    .join(' ')
    .toLowerCase();
  return hay.indexOf(query) !== -1;
}

/* Strip a port suffix from an IP for unblock requests.
   IPv6 addresses are passed without a port; bracketed "[::1]:80" is handled. */
export function cleanIP(ip: string): string {
  if (ip.charAt(0) === '[') {
    const m = ip.match(/^\[([^\]]+)\]/);
    if (m) return m[1];
  } else if (ip.indexOf('.') !== -1 && ip.indexOf(':') !== -1) {
    return ip.split(':')[0];
  }
  return ip;
}

/* Prefer the clean destination_ip field over parsing dst, which uses
   non-standard "ipv6addr:port" notation for IPv6. */
export function unblockIPOf(it: LogEntry): string {
  if (it.destination_ip) return sanitizeRemoteData(it.destination_ip);
  const dst = dstOf(it);
  return dst ? cleanIP(dst) : '';
}
