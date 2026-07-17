<script lang="ts">
  /* Two-line time series: allowed vs blocked over time buckets.
     Pure SVG, responsive via measured width, crosshair + tooltip on hover.
     Two series => legend present; allowed/blocked also carry status color +
     label, so identity is never color-alone. */
  import type { Bucket } from '../types';

  let { buckets = [] }: { buckets: Bucket[] } = $props();

  const h = 210;
  const padL = 34;
  const padR = 14;
  const padT = 10;
  const padB = 22;

  let w = $state(640);
  let hover = $state(-1);

  const plotW = $derived(Math.max(10, w - padL - padR));
  const plotH = h - padT - padB;
  const maxY = $derived(Math.max(1, ...buckets.map((b) => Math.max(b.allowed, b.blocked))));

  const n = $derived(buckets.length);
  const x = (i: number) => padL + (n <= 1 ? plotW / 2 : (i / (n - 1)) * plotW);
  const y = (v: number) => padT + plotH - (v / maxY) * plotH;

  function path(key: 'allowed' | 'blocked') {
    return buckets.map((b, i) => (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(b[key]).toFixed(1)).join(' ');
  }

  const ticks = $derived.by(() => {
    const out: number[] = [];
    const steps = 3;
    for (let i = 0; i <= steps; i++) out.push(Math.round((maxY / steps) * i));
    return [...new Set(out)];
  });

  function onMove(ev: MouseEvent) {
    const rect = (ev.currentTarget as SVGSVGElement).getBoundingClientRect();
    const px = ev.clientX - rect.left;
    if (n === 0) return;
    let best = 0;
    let bd = Infinity;
    for (let i = 0; i < n; i++) {
      const d = Math.abs(x(i) - px);
      if (d < bd) { bd = d; best = i; }
    }
    hover = best;
  }
</script>

<div class="chart chart-wrap" bind:clientWidth={w} style:position="relative">
  {#if n === 0}
    <div class="empty" style:padding="32px">No data in range yet.</div>
  {:else}
    <svg viewBox="0 0 {w} {h}" role="img" aria-label="Traffic over time, allowed versus blocked"
         onmousemove={onMove} onmouseleave={() => hover = -1}>
      <!-- gridlines + y ticks -->
      {#each ticks as t (t)}
        <line class="grid-line" x1={padL} x2={w - padR} y1={y(t)} y2={y(t)}/>
        <text class="axis-label" x={padL - 6} y={y(t) + 3} text-anchor="end">{t}</text>
      {/each}
      <!-- x labels: first, middle, last -->
      {#each [0, Math.floor((n - 1) / 2), n - 1] as i (i)}
        {#if buckets[i]}
          <text class="axis-label" x={x(i)} y={h - 6}
                text-anchor={i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle'}>{buckets[i].label}</text>
        {/if}
      {/each}
      <path class="series-line" d={path('allowed')} stroke="var(--c-allow)"/>
      <path class="series-line" d={path('blocked')} stroke="var(--c-block)"/>
      <!-- hover crosshair + markers -->
      {#if hover >= 0 && buckets[hover]}
        <line class="crosshair" x1={x(hover)} x2={x(hover)} y1={padT} y2={padT + plotH}/>
        <circle class="marker" cx={x(hover)} cy={y(buckets[hover].allowed)} fill="var(--c-allow)"/>
        <circle class="marker" cx={x(hover)} cy={y(buckets[hover].blocked)} fill="var(--c-block)"/>
      {/if}
    </svg>

    {#if hover >= 0 && buckets[hover]}
      <div class="chart-tip" style:left="{x(hover)}px" style:top="{padT + 4}px">
        <div class="faint" style:margin-bottom="3px">{buckets[hover].label}</div>
        <div class="t-row"><span class="swatch" style:background="var(--c-allow)"></span>Allowed <b>{buckets[hover].allowed}</b></div>
        <div class="t-row"><span class="swatch" style:background="var(--c-block)"></span>Blocked <b>{buckets[hover].blocked}</b></div>
      </div>
    {/if}
  {/if}
</div>
