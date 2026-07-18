<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from './lib/api';
  import { toast } from './lib/toast.svelte';
  import { confirm } from './lib/dialog.svelte';
  import { rel } from './lib/format';
  import type { APIKey } from './lib/types';

  let keys = $state<APIKey[]>([]);
  let label = $state('');
  let created = $state<{ key: string; api_key: APIKey } | null>(null); // shown once
  let loading = $state(true);

  async function load() {
    const res = await apiFetch('/api/v1/apikeys');
    keys = res.ok ? await res.json() : [];
    loading = false;
  }

  async function create(ev: Event) {
    ev.preventDefault();
    const name = label.trim();
    if (!name) return;

    const res = await apiFetch('/api/v1/apikeys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: name }),
    });
    if (!res.ok) { toast('Create failed (' + res.status + ')', 'err'); return; }

    created = await res.json();
    label = '';
    toast('API key created', 'ok');
    await load();
  }

  async function revoke(k: APIKey) {
    const ok = await confirm({
      title: 'Revoke "' + k.label + '"?',
      message: 'Any g0efilter instance using this key stops working immediately.',
      okLabel: 'Revoke key',
      danger: true,
    });
    if (!ok) return;
    const res = await apiFetch('/api/v1/apikeys/' + k.id, { method: 'DELETE' });
    if (!res.ok) { toast('Revoke failed (' + res.status + ')', 'err'); return; }
    toast('Key revoked', 'ok');
    await load();
  }

  function copyKey() {
    if (created) navigator.clipboard?.writeText(created.key).then(() => toast('Copied to clipboard', 'ok'));
  }

  onMount(load);
</script>

<section class="view">
  <div class="row spread">
    <div><h1>API Keys</h1><span class="muted">Machine credentials for g0efilter instances (log ingest, unblock poll, sync).</span></div>
  </div>

  {#if created}
    <div class="card pad">
      <p class="section-title">New key - shown once, copy it now</p>
      <div class="codebox">
        <code>{created.key}</code>
        <span class="grow"></span>
        <button class="btn btn-sm btn-primary" onclick={copyKey}>Copy</button>
        <button class="btn btn-sm btn-ghost" onclick={() => created = null}>Dismiss</button>
      </div>
    </div>
  {/if}

  <div class="card pad">
    <form class="row" onsubmit={create}>
      <input class="input grow" placeholder="Label (e.g. ci-runner)" maxlength="64" bind:value={label}/>
      <button class="btn btn-primary" type="submit" disabled={!label.trim()}>Create key</button>
    </form>
  </div>

  <div class="card fill">
    <div class="scrollbox">
      <table class="table">
        <colgroup><col/><col style:width="160px"/><col style:width="190px"/><col style:width="190px"/><col style:width="120px"/></colgroup>
        <thead><tr><th>Label</th><th>Prefix</th><th>Created</th><th>Last used</th><th></th></tr></thead>
        <tbody>
          {#each keys as k (k.id)}
            <tr>
              <td>{k.label} {#if k.revoked_at}<span class="badge badge-BLOCKED">revoked</span>{/if}</td>
              <td class="mono">{k.prefix}</td>
              <td>{new Date(k.created_at).toLocaleString()}</td>
              <td>{k.last_used_at ? rel(k.last_used_at) + ' ago' : '-'}</td>
              <td>{#if !k.revoked_at}<button class="btn btn-sm btn-danger" onclick={() => revoke(k)}>Revoke</button>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if loading}
        <div style:padding="12px">{#each Array(3) as _, i (i)}<div class="skeleton sk-row"></div>{/each}</div>
      {:else if keys.length === 0}
        <div class="empty"><div class="big">No API keys</div>Create one above, or set the API_KEY env var.</div>
      {/if}
    </div>
  </div>
</section>
