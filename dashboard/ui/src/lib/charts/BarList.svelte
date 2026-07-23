<script lang="ts">
  import { app, searchFor } from '../state.svelte';
  import LookupActions from '../../LookupActions.svelte';
  import type { BarItem } from '../types';

  let { items = [], color = 'var(--c-accent)', empty = 'No data' }:
    { items?: BarItem[]; color?: string; empty?: string } = $props();

  const max = $derived(Math.max(1, ...items.map((i) => i.value)));
</script>

{#if items.length === 0}
  <div class="empty" style:padding="24px">{empty}</div>
{:else}
  <div class="barlist">
    {#each items as it (it.label)}
      <div class="barrow" title="{it.label}: {it.value}">
        <span class="lbl clickable-key" role="button" tabindex="0"
              title="Search events for {it.label}"
              onclick={() => searchFor(it.label, { range: app.range })}
              onkeydown={(e) => e.key === 'Enter' && searchFor(it.label, { range: app.range })}>
          <LookupActions value={it.label}/>
        </span>
        <span class="val">{it.value}</span>
        <div class="bartrack">
          <div class="barfill" style:width="{(it.value / max) * 100}%" style:background={color}></div>
        </div>
      </div>
    {/each}
  </div>
{/if}
