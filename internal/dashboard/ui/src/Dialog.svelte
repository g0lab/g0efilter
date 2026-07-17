<script lang="ts">
  import { fade, scale } from 'svelte/transition';
  import { dialog, settle } from './lib/dialog.svelte';

  // confirm() resolves true/false; prompt() resolves the string or null.
  function ok() { settle(dialog.kind === 'prompt' ? dialog.value : true); }
  function cancel() { settle(dialog.kind === 'prompt' ? null : false); }

  function onKey(e: KeyboardEvent) {
    if (!dialog.open) return;
    if (e.key === 'Escape') cancel();
    else if (e.key === 'Enter' && dialog.kind === 'confirm') ok();
  }
</script>

<svelte:window onkeydown={onKey}/>

{#if dialog.open}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="modal-scrim" role="presentation" transition:fade={{ duration: 120 }} onclick={cancel}>
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="card modal narrow" role="dialog" aria-modal="true" tabindex="-1"
         transition:scale={{ duration: 140, start: 0.97 }} onclick={(e) => e.stopPropagation()}>
      <div class="card-head"><h2>{dialog.title}</h2></div>
      <div class="card-body">
        {#if dialog.message}<p class="muted" style:margin="0">{dialog.message}</p>{/if}
        {#if dialog.kind === 'prompt'}
          <!-- svelte-ignore a11y_autofocus -->
          <input class="input" autofocus placeholder={dialog.placeholder} bind:value={dialog.value}
                 onkeydown={(e) => { if (e.key === 'Enter') ok(); }}/>
        {/if}
        <div class="modal-actions">
          <button type="button" class="btn btn-sm btn-ghost" onclick={cancel}>Cancel</button>
          <button type="button" class="btn btn-sm {dialog.danger ? 'btn-danger' : 'btn-primary'}" onclick={ok}>{dialog.okLabel}</button>
        </div>
      </div>
    </div>
  </div>
{/if}
