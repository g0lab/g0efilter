<script lang="ts">
  import { apiFetch } from './lib/api';
  import { app, reload } from './lib/state.svelte';
  import { rel, sanitizeInput } from './lib/format';
  import TimeSeries from './lib/charts/TimeSeries.svelte';
  import BarList from './lib/charts/BarList.svelte';
  import LookupActions from './LookupActions.svelte';
  import type { AggregateResponse, AggregateRow, Bucket } from './lib/types';

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

  type SortKey = 'key' | 'total' | 'allowed' | 'blocked' | 'audit' | 'rate' | 'lastSeen';
  type SortDirection = 'asc' | 'desc';

  const emptyResponse = (): AggregateResponse => ({
    from: '',
    to: '',
    events: 0,
    totals: { allowed: 0, blocked: 0, audit: 0 },
    buckets: [],
    rows: [],
  });

  let range = $state('24h');
  let query = $state('');
  let sortKey = $state<SortKey>('total');
  let sortDirection = $state<SortDirection>('desc');
  let aggregate = $state<AggregateResponse>(emptyResponse());
  let loadError = $state('');
  let requestID = 0;

  function blockRate(item: Pick<AggregateRow, 'allowed' | 'blocked'>): number {
    const enforced = item.allowed + item.blocked;
    return enforced ? (item.blocked / enforced) * 100 : 0;
  }

  const totals = $derived({
    ...aggregate.totals,
    total: aggregate.events,
    rate: blockRate(aggregate.totals),
  });

  const buckets = $derived.by(() => {
    const span = new Date(aggregate.to).getTime() - new Date(aggregate.from).getTime();
    return aggregate.buckets.map((bucket): Bucket => ({
      allowed: bucket.allowed,
      blocked: bucket.blocked,
      audit: bucket.audit,
      label: span >= 24 * 60 * 60_000
        ? new Date(bucket.start).toLocaleDateString([], { month: 'short', day: 'numeric' })
        : new Date(bucket.start).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }));
  });

  function rankBy(verdict: 'allowed' | 'blocked' | 'audit') {
    return aggregate.rows
      .filter((row) => row[verdict] > 0)
      .map((row) => ({ label: row.key, value: row[verdict] }))
      .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label))
      .slice(0, 8);
  }

  const topBlocked = $derived.by(() => rankBy('blocked'));
  const topAudit = $derived.by(() => rankBy('audit'));
  const topAllowed = $derived.by(() => rankBy('allowed'));

  const rows = $derived.by(() => [...aggregate.rows].sort((a, b) => {
      let result: number;
      if (sortKey === 'key') result = a.key.localeCompare(b.key);
      else if (sortKey === 'rate') result = blockRate(a) - blockRate(b);
      else if (sortKey === 'lastSeen') result = new Date(a.last_seen).getTime() - new Date(b.last_seen).getTime();
      else result = a[sortKey] - b[sortKey];
      return (sortDirection === 'asc' ? result : -result) || a.key.localeCompare(b.key);
    }));

  async function loadAggregates(selectedRange = range, selectedQuery = query): Promise<void> {
    const currentRequest = ++requestID;
    loadError = '';
    try {
      const params = 'range=' + encodeURIComponent(selectedRange)
        + (selectedQuery ? '&q=' + encodeURIComponent(selectedQuery) : '');
      const response = await apiFetch('/api/v1/aggregates?' + params);
      if (!response.ok) throw new Error('request failed (' + response.status + ')');
      const result: AggregateResponse = await response.json();
      if (currentRequest === requestID) aggregate = result;
    } catch (error) {
      if (currentRequest === requestID) loadError = (error as Error).message;
    }
  }

  async function refresh(): Promise<void> {
    await reload();
    await loadAggregates();
  }

  $effect(() => {
    const selectedRange = range;
    const selectedQuery = query;
    const newestID = app.items[0]?.id ?? 0;
    const delay = selectedQuery || (app.live && newestID) ? 500 : 0;
    const timer = window.setTimeout(() => loadAggregates(selectedRange, selectedQuery), delay);
    return () => window.clearTimeout(timer);
  });

  function changeSort(next: SortKey) {
    if (sortKey === next) sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    else {
      sortKey = next;
      sortDirection = next === 'key' ? 'asc' : 'desc';
    }
  }

  function sortIndicator(key: SortKey): string {
    if (sortKey !== key) return '';
    return sortDirection === 'asc' ? '↑' : '↓';
  }

  function ariaSort(key: SortKey): 'ascending' | 'descending' | 'none' {
    if (sortKey !== key) return 'none';
    return sortDirection === 'asc' ? 'ascending' : 'descending';
  }
</script>

<section class="view aggregate-view">
  <div class="aggregate-toolbar">
    <div>
      <h1>Traffic aggregates</h1>
      <div class="faint">{totals.total} verdict events · {ranges.find((item) => item.value === range)?.label}</div>
      {#if loadError}<div class="aggregate-error">Could not load aggregates: {loadError}</div>{/if}
    </div>
    <div class="controls">
      <label class="inline">Range
        <select class="select" value={range} onchange={(event) => range = event.currentTarget.value}>
          {#each ranges as range (range.value)}
            <option value={range.value}>{range.label}</option>
          {/each}
        </select>
      </label>
      <input type="search" class="input aggregate-search" placeholder="Filter host or IP…"
        aria-label="Filter aggregates by host or IP"
        value={query} oninput={(event) => query = sanitizeInput(event.currentTarget.value).toLowerCase()}/>
      <button type="button" class="btn btn-sm btn-ghost" onclick={refresh} disabled={app.loading}>Refresh</button>
    </div>
  </div>

  <div class="stats aggregate-stats">
    <div class="stat"><div class="n">{totals.total}</div><div class="k">Verdict events</div></div>
    <div class="stat ok"><div class="n">{totals.allowed}</div><div class="k">Allowed</div></div>
    <div class="stat err"><div class="n">{totals.blocked}</div><div class="k">Blocked</div></div>
    <div class="stat warn"><div class="n">{totals.audit}</div><div class="k">Audit</div></div>
    <div class="stat"><div class="n">{totals.rate.toFixed(1)}%</div><div class="k">Enforced block rate</div></div>
  </div>

  <div class="card aggregate-chart-card">
    <div class="card-head">
      <h2>Traffic over time</h2>
      <span class="grow"></span>
      <div class="legend" aria-label="Chart legend">
        <span class="item"><span class="swatch" style:background="var(--c-allow)"></span>Allowed</span>
        <span class="item"><span class="swatch" style:background="var(--c-block)"></span>Blocked</span>
        <span class="item"><span class="swatch" style:background="var(--c-audit)"></span>Audit</span>
      </div>
    </div>
    <div class="card-body"><TimeSeries {buckets}/></div>
  </div>

  <div class="grid3">
    <div class="card">
      <div class="card-head"><h2>Top blocked</h2></div>
      <div class="card-body"><BarList items={topBlocked} color="var(--c-block)" empty="No blocked traffic in range" lookups/></div>
    </div>
    <div class="card">
      <div class="card-head"><h2>Top audit</h2></div>
      <div class="card-body"><BarList items={topAudit} color="var(--c-audit)" empty="No audit traffic in range" lookups/></div>
    </div>
    <div class="card">
      <div class="card-head"><h2>Top allowed</h2></div>
      <div class="card-body"><BarList items={topAllowed} color="var(--c-allow)" empty="No allowed traffic in range" lookups/></div>
    </div>
  </div>

  <div class="card fill">
    <div class="card-head">
      <h2>By host / IP</h2><span class="grow"></span><small class="faint">{rows.length} keys</small>
    </div>
    <div class="scrollbox aggregate-table-wrap">
      <table class="table aggregate-table">
        <colgroup>
          <col class="c-aggkey"/><col class="c-total"/><col class="c-aggcount"/><col class="c-aggcount"/>
          <col class="c-aggcount"/><col class="c-aggrate"/><col class="c-last"/>
        </colgroup>
        <thead>
          <tr>
            <th aria-sort={ariaSort('key')}><button type="button" class="sort-button" onclick={() => changeSort('key')}>Host / IP <span>{sortIndicator('key')}</span></button></th>
            <th aria-sort={ariaSort('total')}><button type="button" class="sort-button" onclick={() => changeSort('total')}>Total <span>{sortIndicator('total')}</span></button></th>
            <th aria-sort={ariaSort('allowed')}><button type="button" class="sort-button" onclick={() => changeSort('allowed')}>Allowed <span>{sortIndicator('allowed')}</span></button></th>
            <th aria-sort={ariaSort('blocked')}><button type="button" class="sort-button" onclick={() => changeSort('blocked')}>Blocked <span>{sortIndicator('blocked')}</span></button></th>
            <th aria-sort={ariaSort('audit')}><button type="button" class="sort-button" onclick={() => changeSort('audit')}>Audit <span>{sortIndicator('audit')}</span></button></th>
            <th aria-sort={ariaSort('rate')}><button type="button" class="sort-button" onclick={() => changeSort('rate')}>Block rate <span>{sortIndicator('rate')}</span></button></th>
            <th aria-sort={ariaSort('lastSeen')}><button type="button" class="sort-button" onclick={() => changeSort('lastSeen')}>Last seen <span>{sortIndicator('lastSeen')}</span></button></th>
          </tr>
        </thead>
        <tbody>
          {#each rows as row (row.key)}
            <tr>
              <td title={row.key}><LookupActions value={row.key}/></td>
              <td>{row.total}</td>
              <td class="count-allowed">{row.allowed}</td>
              <td class="count-blocked">{row.blocked}</td>
              <td class="count-audit">{row.audit}</td>
              <td>{blockRate(row).toFixed(1)}%</td>
              <td>{row.last_seen ? rel(row.last_seen) + ' ago' : ''}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if rows.length === 0}
        <div class="empty"><div class="big">No matching traffic</div>Try a wider time range or clear the host filter.</div>
      {/if}
    </div>
  </div>
</section>
