<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch } from './lib/api';
  import { toast } from './lib/toast.svelte';
  import { confirm } from './lib/dialog.svelte';
  import { rel } from './lib/format';
  import type { Instance, Group } from './lib/types';

  interface EditGroup { id: string; name: string; policy: string; filter_mode: string }

  let instances = $state<Instance[]>([]);
  let groups = $state<Group[]>([]);
  let newGroup = $state('');
  let editing = $state<EditGroup | null>(null); // group being edited in the modal
  let loading = $state(true);

  const stats = $derived.by(() => {
    const online = instances.filter((i) => Date.now() - new Date(i.last_seen_at).getTime() < 90000).length;
    const synced = instances.filter((i) => i.in_sync).length;
    return { total: instances.length, online, synced };
  });

  async function load() {
    const [ir, gr] = await Promise.all([
      apiFetch('/api/v1/fleet/instances'),
      apiFetch('/api/v1/fleet/groups'),
    ]);
    instances = ir.ok ? await ir.json() : [];
    groups = gr.ok ? await gr.json() : [];
    loading = false;
  }

  function online(i: Instance): boolean {
    return Date.now() - new Date(i.last_seen_at).getTime() < 90000;
  }

  async function put(path: string, body: unknown): Promise<boolean> {
    const res = await apiFetch(path, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) { toast('Update failed (' + res.status + ')', 'err'); return false; }
    return true;
  }

  async function assignGroup(inst: Instance, ev: Event) {
    const ok = await put('/api/v1/fleet/instances/' + inst.id + '/group',
      { group_id: (ev.currentTarget as HTMLSelectElement).value });
    if (ok) { toast('Group updated', 'ok'); await load(); }
  }

  async function deleteInstance(inst: Instance) {
    const ok = await confirm({
      title: 'Forget "' + inst.hostname + '"?',
      message: 'The record is removed; it reappears on the next sync from that instance.',
      okLabel: 'Forget',
      danger: true,
    });
    if (!ok) return;
    const res = await apiFetch('/api/v1/fleet/instances/' + inst.id, { method: 'DELETE' });
    if (!res.ok) { toast('Delete failed', 'err'); return; }
    toast('Instance removed', 'ok');
    await load();
  }

  async function createGroup(ev: Event) {
    ev.preventDefault();
    const name = newGroup.trim();
    if (!name) return;
    const res = await apiFetch('/api/v1/fleet/groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) { toast('Create failed (duplicate name?)', 'err'); return; }
    newGroup = '';
    toast('Group created', 'ok');
    await load();
  }

  async function deleteGroup(g: Group) {
    const ok = await confirm({
      title: 'Delete group "' + g.name + '"?',
      message: 'Member instances fall back to unmanaged (they keep their local policy).',
      okLabel: 'Delete group',
      danger: true,
    });
    if (!ok) return;
    const res = await apiFetch('/api/v1/fleet/groups/' + g.id, { method: 'DELETE' });
    if (!res.ok) { toast('Delete failed', 'err'); return; }
    toast('Group deleted', 'ok');
    await load();
  }

  function edit(g: Group) {
    editing = { id: g.id, name: g.name, policy: g.policy, filter_mode: g.filter_mode || '' };
  }

  async function savePolicy() {
    if (!editing) return;
    const ok = await put('/api/v1/fleet/groups/' + editing.id + '/policy', {
      policy: editing.policy, filter_mode: editing.filter_mode,
    });
    if (ok) { toast('Policy saved', 'ok'); editing = null; await load(); }
  }

  onMount(() => {
    load();
    const t = setInterval(load, 10000); // refresh online/sync state

    return () => clearInterval(t);
  });
</script>

<section class="view">
  <div class="row spread">
    <div><h1>Fleet</h1><span class="muted">Instances reconcile desired policy on each sync. Assign them to groups to manage in bulk.</span></div>
    <button class="btn btn-sm btn-ghost" onclick={load}>Refresh</button>
  </div>

  <div class="stats">
    <div class="stat"><div class="n">{stats.total}</div><div class="k">Instances</div></div>
    <div class="stat ok"><div class="n">{stats.online}</div><div class="k">Online</div></div>
    <div class="stat"><div class="n">{stats.synced}</div><div class="k">In sync</div></div>
  </div>

  <div class="card">
    <div class="card-head"><h2>Groups</h2><span class="grow"></span>
      <form class="row" onsubmit={createGroup}>
        <input class="input" placeholder="New group name" maxlength="64" bind:value={newGroup}/>
        <button class="btn btn-sm btn-primary" type="submit" disabled={!newGroup.trim()}>Add</button>
      </form>
    </div>
    <div class="card-body">
      {#if groups.length === 0}
        <div class="faint">No groups yet. Create one to attach a policy and filter mode.</div>
      {:else}
        <table class="table">
          <colgroup><col style:width="180px"/><col style:width="110px"/><col/><col style:width="160px"/></colgroup>
          <thead><tr><th>Name</th><th>Filter mode</th><th>Policy</th><th></th></tr></thead>
          <tbody>
            {#each groups as g (g.id)}
              <tr>
                <td>{g.name}</td>
                <td>{g.filter_mode || '-'}</td>
                <td class="mono faint">{g.policy ? g.policy.split('\n')[0].slice(0, 60) + (g.policy.length > 60 ? '…' : '') : 'empty'}</td>
                <td>
                  <button class="btn btn-sm btn-ghost" onclick={() => edit(g)}>Edit policy</button>
                  <button class="btn btn-sm btn-danger" onclick={() => deleteGroup(g)}>Delete</button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </div>

  <div class="card fill">
    <div class="card-head"><h2>Instances</h2></div>
    <div class="scrollbox">
      <table class="table">
        <colgroup><col style:width="200px"/><col style:width="170px"/><col style:width="110px"/><col style:width="110px"/><col style:width="100px"/><col style:width="160px"/><col style:width="90px"/></colgroup>
        <thead><tr><th>Hostname</th><th>Group</th><th>Version</th><th>Status</th><th>Sync</th><th>Last seen</th><th></th></tr></thead>
        <tbody>
          {#each instances as i (i.id)}
            <tr>
              <td>{i.hostname}</td>
              <td>
                <select class="select w-auto" value={i.group_id || ''} onchange={(e) => assignGroup(i, e)}>
                  <option value="">- unmanaged -</option>
                  {#each groups as g (g.id)}<option value={g.id}>{g.name}</option>{/each}
                </select>
              </td>
              <td class="mono">{i.reported_version || '-'}</td>
              <td>
                <span class="pill" class:online={online(i)} class:offline={!online(i)}>
                  <span class="dot2"></span>{online(i) ? 'online' : 'offline'}
                </span>
              </td>
              <td><span class="pill" class:synced={i.in_sync} class:drift={!i.in_sync}>{i.in_sync ? 'synced' : 'drift'}</span></td>
              <td>{rel(i.last_seen_at)} ago</td>
              <td><button class="btn btn-sm btn-danger" onclick={() => deleteInstance(i)}>Forget</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if loading}
        <div style:padding="12px">{#each Array(3) as _, i (i)}<div class="skeleton sk-row"></div>{/each}</div>
      {:else if instances.length === 0}
        <div class="empty"><div class="big">No instances yet</div>The managed g0efilter instance client is the next control-plane milestone.</div>
      {/if}
    </div>
  </div>
</section>

<svelte:window onkeydown={(e) => { if (e.key === 'Escape') editing = null; }}/>

{#if editing}
  <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
  <div class="modal-scrim" role="presentation" onclick={() => editing = null}>
    <!-- svelte-ignore a11y_click_events_have_key_events a11y_no_static_element_interactions -->
    <div class="card modal" role="dialog" aria-modal="true" tabindex="-1" onclick={(e) => e.stopPropagation()}>
      <div class="card-head"><h2>Policy - {editing.name}</h2></div>
      <div class="card-body">
        <label class="inline">Filter mode
          <select class="select" bind:value={editing.filter_mode}>
            <option value="">inherit / unset</option>
            <option value="https">https</option>
            <option value="dns">dns</option>
            <option value="dns-strict">dns-strict</option>
          </select>
        </label>
        <label class="section-title" for="pol">Policy file contents</label>
        <textarea class="textarea" id="pol" rows="12" bind:value={editing.policy} placeholder="# one rule per line"></textarea>
        <div class="row spread">
          <span class="faint">Pushed to members on their next sync.</span>
          <div class="row">
            <button class="btn btn-sm btn-ghost" onclick={() => editing = null}>Cancel</button>
            <button class="btn btn-sm btn-primary" onclick={savePolicy}>Save policy</button>
          </div>
        </div>
      </div>
    </div>
  </div>
{/if}
