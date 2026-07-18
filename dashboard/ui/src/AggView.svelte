<script lang="ts">
  import { app, reload } from './lib/state.svelte';
  import { getAction, hostOf, dstOf, rel } from './lib/format';
  import TimeSeries from './lib/charts/TimeSeries.svelte';
  import BarList from './lib/charts/BarList.svelte';
  import type { LogEntry } from './lib/types';

  const BUCKETS = 24;

  type Verdict = 'allowed' | 'blocked' | '';

  function actOf(it: LogEntry): Verdict {
    const a = getAction(it);
    if (a === 'ALLOWED') return 'allowed';
    if (a === 'BLOCKED' || a === 'AUDIT') return 'blocked';
    return '';
  }

  function keyOf(it: LogEntry): string { return hostOf(it) || dstOf(it); }
  function timeOf(it: LogEntry): number { return new Date(it.time || it.ts || Date.now()).getTime(); }

  const totals = $derived.by(() => {
    let allowed = 0;
    let blocked = 0;
    for (const it of app.items) {
      const a = actOf(it);
      if (a === 'allowed') allowed++;
      else if (a === 'blocked') blocked++;
    }
    const total = allowed + blocked;
    return { allowed, blocked, total, rate: total ? Math.round((blocked / total) * 100) : 0 };
  });

  /* Bucket events across the observed time span into a two-series series. */
  const buckets = $derived.by(() => {
    if (app.items.length === 0) return [];
    let lo = Infinity;
    let hi = -Infinity;
    for (const it of app.items) { const t = timeOf(it); if (t < lo) lo = t; if (t > hi) hi = t; }
    const span = Math.max(1, hi - lo);
    const out = Array.from({ length: BUCKETS }, () => ({ allowed: 0, blocked: 0 }));

    for (const it of app.items) {
      const idx = Math.min(BUCKETS - 1, Math.floor(((timeOf(it) - lo) / span) * BUCKETS));
      const a = actOf(it);
      if (a) out[idx][a]++;
    }

    const fmt = (t: number) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return out.map((b, i) => ({ ...b, label: fmt(lo + (span / BUCKETS) * (i + 0.5)) }));
  });

  const topBlocked = $derived.by(() => rankBy((it) => actOf(it) === 'blocked'));
  const topAllowed = $derived.by(() => rankBy((it) => actOf(it) === 'allowed'));

  function rankBy(pred: (it: LogEntry) => boolean) {
    // Local tally rebuilt each call; not reactive state, so a plain Map is correct.
    // eslint-disable-next-line svelte/prefer-svelte-reactivity
    const m = new Map<string, number>();
    for (const it of app.items) {
      if (!pred(it)) continue;
      const k = keyOf(it);
      if (!k) continue;
      m.set(k, (m.get(k) || 0) + 1);
    }
    return [...m.entries()]
      .map(([label, value]) => ({ label, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  }

  /* detail table: per-key totals */
  interface KeyStat { total: number; lastSeen: number; allowed: number; blocked: number }

  const rows = $derived.by(() => {
    // Local aggregation rebuilt each derivation; not reactive state.
    // eslint-disable-next-line svelte/prefer-svelte-reactivity
    const map = new Map<string, KeyStat>();
    for (const it of app.items) {
      const key = keyOf(it);
      if (!key) continue;
      let rec = map.get(key);
      if (!rec) { rec = { total: 0, lastSeen: 0, allowed: 0, blocked: 0 }; map.set(key, rec); }
      rec.total++;
      const t = timeOf(it);
      if (t > rec.lastSeen) rec.lastSeen = t;
      const a = actOf(it);
      if (a === 'allowed') rec.allowed++; else if (a === 'blocked') rec.blocked++;
    }
    const out: (KeyStat & { key: string })[] = [];
    map.forEach((v, k) => out.push({ key: k, ...v }));
    out.sort((a, b) => (b.total - a.total) || (b.lastSeen - a.lastSeen));
    return out;
  });
</script>

<section class="view">
  <div class="row spread">
    <div class="stats grow">
      <div class="stat"><div class="n">{totals.total}</div><div class="k">Events</div></div>
      <div class="stat ok"><div class="n">{totals.allowed}</div><div class="k">Allowed</div></div>
      <div class="stat err"><div class="n">{totals.blocked}</div><div class="k">Blocked / Audit</div></div>
      <div class="stat"><div class="n">{totals.rate}%</div><div class="k">Block rate</div></div>
    </div>
    <button type="button" class="btn btn-sm btn-ghost" onclick={reload}>Refresh</button>
  </div>

  <div class="grid2">
    <div class="card">
      <div class="card-head">
        <h2>Traffic over time</h2>
        <span class="grow"></span>
        <div class="legend">
          <span class="item"><span class="swatch" style:background="var(--c-allow)"></span>Allowed</span>
          <span class="item"><span class="swatch" style:background="var(--c-block)"></span>Blocked</span>
        </div>
      </div>
      <div class="card-body"><TimeSeries {buckets}/></div>
    </div>

    <div class="card">
      <div class="card-head"><h2>Top blocked</h2></div>
      <div class="card-body"><BarList items={topBlocked} color="var(--c-block)" empty="No blocks yet"/></div>
    </div>
  </div>

  <div class="grid2">
    <div class="card fill">
      <div class="card-head"><h2>By host / IP</h2><span class="grow"></span><small class="faint">{rows.length} keys</small></div>
      <div class="scrollbox" style:max-height="340px">
        <table class="table">
          <colgroup><col/><col class="c-total"/><col class="c-aggact"/><col class="c-last"/></colgroup>
          <thead><tr><th>Key</th><th>Total</th><th>Verdict</th><th>Last seen</th></tr></thead>
          <tbody>
            {#each rows as a (a.key)}
              {@const act = a.blocked >= a.allowed ? 'BLOCKED' : 'ALLOWED'}
              <tr>
                <td>{a.key}</td>
                <td>{a.total}</td>
                <td><span class="badge badge-{act}">{act}</span></td>
                <td>{a.lastSeen ? rel(a.lastSeen) + ' ago' : ''}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if rows.length === 0}<div class="empty"><div class="big">Nothing to aggregate</div>Totals appear as traffic arrives.</div>{/if}
      </div>
    </div>

    <div class="card">
      <div class="card-head"><h2>Top allowed</h2></div>
      <div class="card-body"><BarList items={topAllowed} color="var(--c-allow)" empty="No allowed traffic yet"/></div>
    </div>
  </div>
</section>
