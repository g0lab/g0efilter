<script lang="ts">
  import { fly } from 'svelte/transition';
  import { toasts } from './lib/toast.svelte';
</script>

<div class="toaster">
  {#each [...toasts] as [id, t] (id)}
    <div class="toast {t.kind}" transition:fly={{ y: 12, duration: 160 }}>{t.message}</div>
  {/each}
</div>
