<script lang="ts">
  import { apiFetch, apiKeyHeaders } from './lib/api';
  import { app, pendingUnblocks, completedUnblocks, isUnblocked, searchFor } from './lib/state.svelte';
  import { DEMO } from '$demo-runtime';
  import { toast } from './lib/toast.svelte';
  import { prompt } from './lib/dialog.svelte';
  import LookupActions from './LookupActions.svelte';
  import {
    getAction, getComp, hostOf, srcOf, dstOf, hostnameOf, flowIdOf, versionOf,
    whenOf, matches, unblockIPOf, cleanIP,
  } from './lib/format';
  import type { LogEntry } from './lib/types';

  type UnblockOffer = { status: 'offer'; type: 'domain' | 'ip'; value: string; hn: string };
  type UnblockView = { status: 'done' } | { status: 'pending' } | UnblockOffer | null;

  const filtered = $derived(
    app.items.filter((it) => matches(it, app.filterAction, app.filterComp, app.filterQuery))
  );

  /* Unblock status per row: 'done' > 'pending' > offer, or null. */
  function unblockState(it: LogEntry): UnblockView {
    if (DEMO) return null;
    const act = getAction(it);
    if (act !== 'BLOCKED' && act !== 'AUDIT') return null;

    const hn = hostnameOf(it);
    const host = hostOf(it);

    if (host) {
      if (isUnblocked(completedUnblocks, host, hn)) return { status: 'done' };
      if (isUnblocked(pendingUnblocks, host, hn)) return { status: 'pending' };
      return { status: 'offer', type: 'domain', value: host, hn };
    }

    const ip = unblockIPOf(it);
    if (!ip) return null;
    if (isUnblocked(completedUnblocks, ip, hn)) return { status: 'done' };
    if (isUnblocked(pendingUnblocks, ip, hn)) return { status: 'pending' };
    return { status: 'offer', type: 'ip', value: ip, hn };
  }

  async function requestUnblock(type: 'domain' | 'ip', value: string, targetHostname: string) {
    try {
      const body: Record<string, string> = { type, value };
      if (targetHostname) body.target_hostname = targetHostname;

      const res = await apiFetch('/api/v1/unblocks', {
        method: 'POST',
        headers: apiKeyHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify(body),
      });
      if (res.ok) {
        toast('Unblock queued: ' + value + ' (' + (targetHostname || 'all hosts') + ')', 'ok');
        pendingUnblocks.add(value.toLowerCase() + '\0' + (targetHostname || '').toLowerCase());
      } else {
        const err = await res.json();
        toast('Failed to queue unblock: ' + (err.error || 'error'), 'err');
      }
    } catch (e) {
      toast('Failed to queue unblock: ' + (e as Error).message, 'err');
    }
  }

  async function unblock(u: UnblockOffer) {
    const label = u.type === 'domain' ? 'domain' : 'IP';
    const targetHost = await prompt({
      title: 'Unblock ' + label,
      message: 'Queue an unblock for ' + u.value + '. Target a specific client, or leave empty for all clients.',
      value: u.hn || '',
      placeholder: 'client hostname (optional)',
      okLabel: 'Queue unblock',
    });
    if (targetHost === null) return; // cancelled
    requestUnblock(u.type, u.value, targetHost.trim());
  }
</script>

<section class="view">
  <div class="card fill">
    <div class="scrollbox">
      <table class="table">
        <colgroup>
          <col class="c-action"/><col class="c-unblock"/><col class="c-filter"/>
          <col class="c-host"/><col class="c-src"/><col class="c-dst"/>
          <col class="c-client"/><col class="c-flow"/><col class="c-ver"/><col class="c-time"/>
        </colgroup>
        <thead>
          <tr>
            <th>Action</th><th></th><th>Filter</th><th>Host</th><th>Src</th><th>Dst</th>
            <th>Client</th><th>Flow ID</th><th>Version</th><th>Time</th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as it (it.id ?? it)}
            {@const u = unblockState(it)}
            {@const when = whenOf(it)}
            {@const src = srcOf(it)}
            {@const dst = dstOf(it)}
            <tr>
              <td><span class="badge badge-{getAction(it)}">{getAction(it)}</span></td>
              <td>
                {#if u?.status === 'done'}
                  <span class="unblock-done">Unblocked</span>
                {:else if u?.status === 'pending'}
                  <span class="unblock-pending">Pending</span>
                {:else if u?.status === 'offer'}
                  <button type="button" class="iconbtn allow"
                          title="Allow {u.value} ({u.type === 'domain' ? 'domain' : 'IP'})"
                          aria-label="Allow {u.value}" onclick={() => unblock(u)}>✓</button>
                {/if}
              </td>
              <td>{getComp(it)}</td>
              <td title="Search {hostOf(it)}">
                <LookupActions value={hostOf(it)}
                  activateLabel="Search {hostOf(it)}"
                  onactivate={() => searchFor(hostOf(it), { range: app.range })}/>
              </td>
              <td class="mono">{src}</td>
              <td class="mono" title="Search {it.destination_ip || cleanIP(dst)}">
                <LookupActions value={dst} target={it.destination_ip || dst} kind="ip"
                  activateLabel="Search {it.destination_ip || cleanIP(dst)}"
                  onactivate={() => searchFor(it.destination_ip || cleanIP(dst), { range: app.range })}/>
              </td>
              <td>{hostnameOf(it)}</td>
              <td class="mono">{flowIdOf(it)}</td>
              <td class="mono">{versionOf(it)}</td>
              <td><small>{new Date(when).toLocaleString()}</small></td>
            </tr>
          {/each}
        </tbody>
      </table>
      {#if filtered.length === 0}
        <div class="empty"><div class="big">No traffic yet</div>Events appear here as instances report them.</div>
      {/if}
    </div>
  </div>
</section>
