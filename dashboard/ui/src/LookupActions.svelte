<script lang="ts">
  import { lookupLinks, type LookupKind } from './lib/lookups';

  let {
    value, target = value, kind, activateLabel, onactivate,
  }: {
    value: string;
    target?: string;
    kind?: LookupKind;
    activateLabel: string;
    onactivate: () => void;
  } = $props();
  const links = $derived(lookupLinks(target, kind));
</script>

<span class="lookup">
  {#if value}
    <button type="button" class="lookup-value clickable-key" title={activateLabel}
      aria-label={activateLabel} onclick={onactivate}>{value}</button>
  {/if}
  {#each links as link (link.id)}
    <a class="lookup-action" href={link.url} target="_blank" rel="noopener noreferrer"
      title="Search {link.value} on {link.name}"
      aria-label="Search {link.value} on {link.name}">{link.label}</a>
  {/each}
</span>
