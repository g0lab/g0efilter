/* Shared reactive state (Svelte 5 runes). */
import { SvelteSet } from 'svelte/reactivity';
import { apiFetch } from './api';
import { norm } from './format';
import type { LogEntry, UnblockStatus } from './types';

interface AppState {
  live: boolean;
  view: string;
  page: string; // stream | search | agg | keys | fleet
  streamLimit: number;
  connected: boolean;
  loading: boolean;
  authMode: string;
  fleetEnabled: boolean;
  items: LogEntry[];
  filterAction: string;
  filterComp: string;
  filterQuery: string;
  range: string;
  aggQuery: string;
  aggDimension: string;
  aggComponent: string;
  searchQuery: string;
  searchAction: string;
  searchComponent: string;
}

const ranges = new Set(['15m', '1h', '6h', '24h', '7d', '30d', '90d', 'all']);

function initialRange(): string {
  const stored = localStorage.getItem('range') || '';
  return ranges.has(stored) ? stored : '24h';
}

function initialStreamLimit(): number {
  const stored = Number(localStorage.getItem('streamRows'));
  return Number.isInteger(stored) && stored > 0 && stored <= 5000 ? stored : 500;
}

export const app: AppState = $state({
  live: JSON.parse(localStorage.getItem('autoRefresh') || 'true'),
  view: localStorage.getItem('view') || 'stream',
  page: 'stream',
  streamLimit: initialStreamLimit(),
  connected: true,
  loading: false,
  authMode: '',
  fleetEnabled: false,
  items: [],
  filterAction: '',
  filterComp: '',
  filterQuery: '',
  range: initialRange(),
  aggQuery: '',
  aggDimension: 'domain',
  aggComponent: '',
  searchQuery: '',
  searchAction: '',
  searchComponent: '',
});

/* value + "\0" + target_hostname keys, mirroring the server's unblock model */
export const pendingUnblocks = new SvelteSet<string>();
export const completedUnblocks = new SvelteSet<string>();

export function setLive(v: boolean): void {
  app.live = v;
  localStorage.setItem('autoRefresh', JSON.stringify(v));
}

export function setView(v: string): void {
  app.view = v;
  localStorage.setItem('view', v);
}

export function setStreamLimit(value: number): void {
  app.streamLimit = Math.max(1, Math.min(value, 5000));
  app.items = app.items.slice(0, app.streamLimit);
  localStorage.setItem('streamRows', String(app.streamLimit));
}

export function setRange(value: string): void {
  app.range = ranges.has(value) ? value : '24h';
  localStorage.setItem('range', app.range);
}

export function go(page: string): void {
  app.page = page;
  localStorage.setItem('view', page);
  if (page === 'stream') void reload();
}

export function searchFor(key: string, opts: { range?: string } = {}): void {
  app.searchQuery = (key || '').toLowerCase();
  app.searchAction = '';
  app.searchComponent = '';
  if (opts.range) setRange(opts.range);
  go('search');
}

export function aggregateFor(key: string, opts: { range?: string; dimension?: string } = {}): void {
  app.aggQuery = (key || '').toLowerCase();
  if (opts.range) setRange(opts.range);
  if (opts.dimension) app.aggDimension = opts.dimension;
  go('agg');
}

/* Matches exact (value, hostname) pair OR (value, "") meaning all hosts. */
export function isUnblocked(set: SvelteSet<string>, value: string, hostname: string): boolean {
  const v = value.toLowerCase();
  const h = (hostname || '').toLowerCase();
  return set.has(v + '\0' + h) || set.has(v + '\0');
}

export function clearItems(): void {
  app.items = [];
}

export function pushItem(it: LogEntry): void {
  app.items.unshift(norm(it));
  if (app.items.length > app.streamLimit) app.items.pop();
}

/* Backfill with the newest retained events. */
export async function reload(): Promise<void> {
  app.loading = true;
  try {
    const res = await apiFetch('/api/v1/logs?limit=' + app.streamLimit);
    if (!res.ok) { console.error('reload failed:', res.status); return; }
    const raw: LogEntry[] = await res.json();
    const snapshot = raw.map(norm);
    // A live SSE event can land while this fetch is in flight; the snapshot is
    // newest-first, so keep items newer than its head rather than let the
    // replace drop them.
    const newest = snapshot.length ? (snapshot[0].id ?? 0) : 0;
    const pending = app.items.filter((it) => (it.id ?? 0) > newest);
    app.items = [...pending, ...snapshot].slice(0, app.streamLimit);
  } catch (e) {
    console.error('reload error:', e);
  } finally {
    app.loading = false;
  }
}

/* Unblock status snapshot for initial load and SSE reconnection recovery. */
export async function loadUnblockStatus(): Promise<void> {
  try {
    const res = await apiFetch('/api/v1/unblocks/status');
    if (!res.ok) return;
    const data: { pending?: UnblockStatus[]; completed?: UnblockStatus[] } = await res.json();

    const key = (u: UnblockStatus) => u.value.toLowerCase() + '\0' + (u.target_hostname || '').toLowerCase();

    syncSet(pendingUnblocks, (data.pending || []).map(key));
    syncSet(completedUnblocks, (data.completed || []).map(key));
  } catch { /* best-effort */ }
}

function syncSet(set: SvelteSet<string>, keys: string[]): void {
  const next = new Set(keys);
  for (const k of set) if (!next.has(k)) set.delete(k);
  for (const k of next) set.add(k);
}
