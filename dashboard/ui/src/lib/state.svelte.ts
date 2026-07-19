/* Shared reactive state (Svelte 5 runes). */
import { SvelteSet } from 'svelte/reactivity';
import { apiFetch } from './api';
import { norm } from './format';
import type { LogEntry, UnblockStatus } from './types';

interface AppState {
  live: boolean;
  view: string;
  page: string; // stream | agg | keys | fleet
  maxRows: number;
  connected: boolean;
  loading: boolean;
  authMode: string;
  fleetEnabled: boolean;
  items: LogEntry[];
  filterAction: string;
  filterComp: string;
  filterQuery: string;
}

export const app: AppState = $state({
  live: JSON.parse(localStorage.getItem('autoRefresh') || 'true'),
  view: localStorage.getItem('view') || 'stream',
  page: 'stream',
  maxRows: 5000, // fallback - overwritten by /api/v1/config (mirrors BUFFER_SIZE)
  connected: true,
  loading: false,
  authMode: '',
  fleetEnabled: false,
  items: [],
  filterAction: '',
  filterComp: '',
  filterQuery: '',
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
  if (app.items.length > app.maxRows) app.items.pop();
}

/* Backfill from the server's in-memory buffer. */
export async function reload(): Promise<void> {
  app.loading = true;
  try {
    const res = await apiFetch('/api/v1/logs?limit=' + app.maxRows);
    if (!res.ok) { console.error('reload failed:', res.status); return; }
    const raw: LogEntry[] = await res.json();
    const snapshot = raw.map(norm);
    // A live SSE event can land while this fetch is in flight; the snapshot is
    // newest-first, so keep items newer than its head rather than let the
    // replace drop them.
    const newest = snapshot.length ? (snapshot[0].id ?? 0) : 0;
    const pending = app.items.filter((it) => (it.id ?? 0) > newest);
    app.items = [...pending, ...snapshot].slice(0, app.maxRows);
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
