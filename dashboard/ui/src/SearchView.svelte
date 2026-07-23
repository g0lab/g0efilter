<script lang="ts">
  import { apiFetch } from './lib/api';
  import { app, setRange, aggregateFor } from './lib/state.svelte';
  import {
    sanitizeInput, getAction, getComp, hostOf, srcOf, dstOf,
    hostnameOf, flowIdOf, versionOf, whenOf, cleanIP,
  } from './lib/format';
  import LookupActions from './LookupActions.svelte';
  import type { LogEntry, BrowseResponse } from './lib/types';

  const ranges = [
    { value: '15m', label: 'Last 15 minutes' },
    { value: '1h', label: 'Last hour' },
    { value: '6h', label: 'Last 6 hours' },
    { value: '24h', label: 'Last 24 hours' },
    { value: '7d', label: 'Last 7 days' },
    { value: '30d', label: 'Last 30 days' },
    { value: '90d', label: 'Last 90 days' },
    { value: 'all', label: 'All retained history' },
  ];
  const pageSizes = [50, 100, 250, 500];

  let pageSize = $state(100);
  let page = $state(1);
  let rows = $state<LogEntry[]>([]);
  let total = $state(0);
  let loading = $state(false);
  let loadError = $state('');
  let requestID = 0;

  const totalPages = $derived(Math.max(1, Math.ceil(total / pageSize)));
  const rangeStart = $derived(total === 0 ? 0 : (page - 1) * pageSize + 1);
  const rangeEnd = $derived(Math.min(page * pageSize, total));

  const filterKey = $derived(
    [app.range, app.searchQuery, app.searchAction, app.searchComponent, pageSize].join('\0')
  );

  async function load(): Promise<void> {
    const id = ++requestID;
    loading = true;
    loadError = '';
    try {
      const params = [
        'range=' + encodeURIComponent(app.range),
        'limit=' + pageSize,
        'offset=' + (page - 1) * pageSize,
      ];
      if (app.searchQuery) params.push('q=' + encodeURIComponent(app.searchQuery));
      if (app.searchAction) params.push('action=' + encodeURIComponent(app.searchAction));
      if (app.searchComponent) params.push('component=' + encodeURIComponent(app.searchComponent));

      const res = await apiFetch('/api/v1/logs/browse?' + params.join('&'));
      if (!res.ok) throw new Error('request failed (' + res.status + ')');
      const data: BrowseResponse = await res.json();
      if (id !== requestID) return;
      rows = data.rows ?? [];
      total = data.total ?? 0;
    } catch (error) {
      if (id === requestID) { loadError = (error as Error).message; rows = []; total = 0; }
    } finally {
      if (id === requestID) loading = false;
    }
  }

  let prevKey = '';
  $effect(() => {
    const key = filterKey;
    if (key !== prevKey) { prevKey = key; page = 1; }
  });

  $effect(() => {
    const _ = [filterKey, page];
    void _;
    const delay = app.searchQuery ? 300 : 0;
    const timer = window.setTimeout(load, delay);
    return () => window.clearTimeout(timer);
  });

  function goToPage(next: number): void {
    page = Math.max(1, Math.min(next, totalPages));
  }

  function dstKey(it: LogEntry): string {
    return it.destination_ip || cleanIP(dstOf(it));
  }
</script>

<section class="view">
  <div class="controls">
    <label class="inline">Range
      <select class="select" value={app.range} onchange={(e) => setRange(e.currentTarget.value)}>
        {#each ranges as r (r.value)}<option value={r.value}>{r.label}</option>{/each}
      </select>
    </label>
    <label class="inline">Action
      <select class="select" value={app.searchAction}
        onchange={(e) => app.searchAction = sanitizeInput(e.currentTarget.value).toUpperCase()}>
        <option value="">All</option>
        <option value="ALLOWED">ALLOWED</option>
        <option value="BLOCKED">BLOCKED</option>
        <option value="AUDIT">AUDIT</option>
      </select>
    </label>
    <label class="inline">Filter
      <select class="select" value={app.searchComponent}
        onchange={(e) => app.searchComponent = sanitizeInput(e.currentTarget.value).toLowerCase()}>
        <option value="">Any</option>
        <option value="https">https</option>
        <option value="http">http</option>
        <option value="dns">dns</option>
        <option value="nflog">nflog</option>
      </select>
    </label>
    <input type="search" class="input" placeholder="Search host, IP, client…" value={app.searchQuery}
      aria-label="Search retained traffic"
      oninput={(e) => app.searchQuery = sanitizeInput(e.currentTarget.value).toLowerCase()}/>
    <label class="inline">Per page
      <select class="select" value={pageSize} onchange={(e) => pageSize = Number(e.currentTarget.value)}>
        {#each pageSizes as n (n)}<option value={n}>{n}</option>{/each}
      </select>
    </label>
    <button type="button" class="btn btn-sm btn-ghost" onclick={() => load()} disabled={loading}>Refresh</button>
    {#if loading}<span class="spinner" role="status" aria-label="Loading"></span>{/if}
    <span class="grow"></span>
    {#if loadError}<span class="aggregate-error">Search failed: {loadError}</span>{/if}
  </div>

  <div class="card fill">
    <div class="scrollbox">
      <table class="table">
        <colgroup>
          <col class="c-action"/><col class="c-filter"/>
          <col class="c-host"/><col class="c-src"/><col class="c-dst"/>
          <col class="c-client"/><col class="c-flow"/><col class="c-ver"/><col class="c-time"/>
        </colgroup>
        <thead>
          <tr>
            <th>Action</th><th>Filter</th><th>Host</th><th>Src</th><th>Dst</th>
            <th>Client</th><th>Flow ID</th><th>Version</th><th>Time</th>
          </tr>
        </thead>
        <tbody>
          {#each rows as it (it.id ?? it)}
            {@const when = whenOf(it)}
            <tr>
              <td><span class="badge badge-{getAction(it)}">{getAction(it)}</span></td>
              <td>{getComp(it)}</td>
              <td title="Aggregate {hostOf(it)}">
                <LookupActions value={hostOf(it)}
                  activateLabel="Aggregate {hostOf(it)}"
                  onactivate={() => aggregateFor(hostOf(it), { range: app.range, dimension: 'domain' })}/>
              </td>
              <td class="mono">{srcOf(it)}</td>
              <td class="mono" title="Aggregate {dstKey(it)}">
                <LookupActions value={dstOf(it)} target={dstKey(it)} kind="ip"
                  activateLabel="Aggregate {dstKey(it)}"
                  onactivate={() => aggregateFor(dstKey(it), { range: app.range, dimension: 'ip' })}/>
              </td>
              <td>{hostnameOf(it)}</td>
              <td class="mono">{flowIdOf(it)}</td>
              <td class="mono">{versionOf(it)}</td>
              <td><small>{new Date(when).toLocaleString()}</small></td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if rows.length === 0 && !loading}
        <div class="empty">
          <div class="big">No matching traffic</div>
          Try a wider time range or a different search.
        </div>
      {/if}
    </div>

    {#if total > 0}
      <div class="pagination">
        <span class="faint">Showing {rangeStart}-{rangeEnd} of {total.toLocaleString()} events</span>
        <div class="pagination-controls">
          <button type="button" class="btn btn-sm btn-ghost" onclick={() => goToPage(page - 1)} disabled={page <= 1}>Previous</button>
          <select class="select" value={page} onchange={(e) => goToPage(Number(e.currentTarget.value))} aria-label="Page">
            {#each Array.from({ length: totalPages }, (_, i) => i + 1) as p (p)}
              <option value={p}>{p} / {totalPages}</option>
            {/each}
          </select>
          <button type="button" class="btn btn-sm btn-ghost" onclick={() => goToPage(page + 1)} disabled={page >= totalPages}>Next</button>
        </div>
      </div>
    {/if}
  </div>
</section>
