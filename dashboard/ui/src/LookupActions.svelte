<script lang="ts">
  import { lookupLinks, type LookupKind } from './lib/lookups';

  let { value, target = value, kind }: { value: string; target?: string; kind?: LookupKind } = $props();
  const links = $derived(lookupLinks(target, kind));
</script>

<span class="lookup">
  <span class="lookup-value">{value}</span>
  {#each links as link (link.id)}
    <a class="lookup-action" href={link.url} target="_blank" rel="noopener noreferrer"
      title="Search {link.value} on {link.name}"
      aria-label="Search {link.value} on {link.name}">{link.label}</a>
  {/each}
</span>
