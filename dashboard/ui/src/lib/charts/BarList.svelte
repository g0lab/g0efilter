<script lang="ts">
  /* Top-N horizontal bar list (magnitude, single series => no legend; the
     title names it). Direct value labels; CSS-drawn bars with rounded ends. */
  let { items = [], color = 'var(--c-accent)', empty = 'No data' } = $props();

  const max = $derived(Math.max(1, ...items.map((i) => i.value)));
</script>

{#if items.length === 0}
  <div class="empty" style:padding="24px">{empty}</div>
{:else}
  <div class="barlist">
    {#each items as it (it.label)}
      <div class="barrow" title="{it.label}: {it.value}">
        <span class="lbl">{it.label}</span>
        <span class="val">{it.value}</span>
        <div class="bartrack">
          <div class="barfill" style:width="{(it.value / max) * 100}%" style:background={color}></div>
        </div>
      </div>
    {/each}
  </div>
{/if}
