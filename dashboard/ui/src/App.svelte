<script lang="ts">
  import { onMount } from 'svelte';
  import { apiFetch, apiKeyHeaders } from './lib/api';
  import { app, setLive, setStreamLimit, clearItems, pushItem, reload, loadUnblockStatus } from './lib/state.svelte';
  import { sanitizeInput } from './lib/format';
  import { toast } from './lib/toast.svelte';
  import { confirm } from './lib/dialog.svelte';
  import { initTheme, isDark, toggleTheme } from './lib/theme';
  import StreamView from './StreamView.svelte';
  import AggView from './AggView.svelte';
  import KeysView from './KeysView.svelte';
  import FleetView from './FleetView.svelte';
  import Toaster from './Toaster.svelte';
  import Dialog from './Dialog.svelte';

  let dark = $state(true);
  let es: EventSource | null = null;

  const isTraffic = $derived(app.page === 'stream' || app.page === 'agg');
  const rowLimitOptions = [100, 500, 1000, 2500, 5000];

  function connectSSE() {
    disconnectSSE();
    es = new EventSource('/api/v1/events');
    es.onmessage = (ev) => {
      try {
        const it = JSON.parse(ev.data);
        if (it && it.type === 'cleared') { clearItems(); return; }
        if (it && it.type === 'unblock_status') { loadUnblockStatus(); return; }
        pushItem(it);
      } catch { /* ignore parse errors */ }
    };
    es.onerror = () => { if (app.live) app.connected = false; };
    es.onopen = () => {
      app.connected = true;
      loadUnblockStatus();
      // Re-sync the log snapshot so events produced while disconnected aren't
      // lost until a manual refresh (reload replaces the list, so no dupes).
      if (isTraffic) reload();
    };
  }

  function disconnectSSE() { if (es) { es.close(); es = null; } }

  function setLiveState(v: boolean) {
    setLive(v);
    if (v) connectSSE(); else { disconnectSSE(); app.connected = false; }
  }

  function go(page: string) {
    app.page = page;
    localStorage.setItem('view', page);
    if (isTraffic) reload();
  }

  async function changeStreamLimit(value: number) {
    setStreamLimit(value);
    await reload();
  }

  async function clearLogs() {
    const ok = await confirm({
      title: 'Clear all logs?',
      message: 'This removes every event from the dashboard buffer.',
      okLabel: 'Clear logs',
      danger: true,
    });
    if (!ok) return;
    const res = await apiFetch('/api/v1/logs', { method: 'DELETE', headers: apiKeyHeaders() });
    if (!res.ok) { toast('Failed to clear logs (' + res.status + ')', 'err'); return; }
    clearItems();
    toast('Logs cleared', 'ok');
  }

  async function logout() {
    await apiFetch('/api/v1/auth/logout', { method: 'POST' });
    window.location.replace('/login.html');
  }

  onMount(() => {
    initTheme();
    dark = isDark();

    (async () => {
      try {
        const res = await apiFetch('/api/v1/config');
        const cfg = res.ok ? await res.json() : {};
        app.authMode = cfg.auth_mode || '';
        app.fleetEnabled = !!cfg.fleet_enabled;
      } catch { /* keep defaults */ }

      if (['stream', 'agg', 'keys', 'fleet'].includes(app.view)) app.page = app.view;
      await reload();
      loadUnblockStatus();
      if (app.live) connectSSE();
    })();

    return disconnectSSE;
  });
</script>

<div class="topbar">
  <div class="brand"><span class="dot"></span> g0efilter</div>
  <nav class="nav">
    <button type="button" class:active={app.page === 'stream'} onclick={() => go('stream')}>Stream</button>
    <button type="button" class:active={app.page === 'agg'} onclick={() => go('agg')}>Aggregates</button>
    <button type="button" class:active={app.page === 'keys'} onclick={() => go('keys')}>API Keys</button>
    {#if app.fleetEnabled}
      <button type="button" class:active={app.page === 'fleet'} onclick={() => go('fleet')}>Fleet</button>
    {/if}
  </nav>

  <div class="topbar-right">
    {#if app.loading}
      <span class="spinner" role="status" aria-label="Loading" title="Loading data"></span>
    {/if}
    {#if isTraffic}
      <label class="switch">
        <input type="checkbox" checked={app.live} onchange={(e) => setLiveState(e.currentTarget.checked)}/>
        <span class="track"><span class="thumb"></span></span>
        <span>Live <span class="status-dot" class:disconnected={!app.connected}></span></span>
      </label>
    {/if}
    <button type="button" class="btn btn-ghost btn-icon" title="Toggle light / dark"
            aria-label="Toggle light or dark theme" onclick={() => dark = toggleTheme()}>
      {#if dark}
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <circle cx="12" cy="12" r="4"/>
          <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>
        </svg>
      {:else}
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>
        </svg>
      {/if}
    </button>
    {#if app.authMode === 'session'}
      <button type="button" class="btn btn-sm btn-ghost" title="Sign out" onclick={logout}>Logout</button>
    {/if}
  </div>
</div>

<main>
  {#if app.page === 'stream'}
    <div class="controls">
      <label class="inline">Action
        <select class="select" value={app.filterAction} onchange={(e) => app.filterAction = sanitizeInput(e.currentTarget.value).toUpperCase()}>
          <option value="">All</option>
          <option value="ALLOWED">ALLOWED</option>
          <option value="BLOCKED">BLOCKED</option>
          <option value="AUDIT">AUDIT</option>
        </select>
      </label>
      <label class="inline">Filter
        <select class="select" value={app.filterComp} onchange={(e) => app.filterComp = sanitizeInput(e.currentTarget.value).toLowerCase()}>
          <option value="">Any</option>
          <option value="https">https</option>
          <option value="http">http</option>
          <option value="dns">dns</option>
          <option value="nflog">nflog</option>
        </select>
      </label>
      <input type="search" class="input" placeholder="Search host, IP, client…"
        oninput={(e) => app.filterQuery = sanitizeInput(e.currentTarget.value).toLowerCase()}/>
      <label class="inline">Rows
        <select class="select" value={app.streamLimit}
          onchange={(e) => changeStreamLimit(Number(e.currentTarget.value))}>
          {#each rowLimitOptions as limit (limit)}
            <option value={limit}>{limit.toLocaleString()}</option>
          {/each}
        </select>
      </label>
      <span class="grow"></span>
      <button type="button" class="btn btn-sm btn-danger" onclick={clearLogs}>Clear Logs</button>
    </div>
    <StreamView/>
  {:else if app.page === 'agg'}
    <AggView/>
  {:else if app.page === 'keys'}
    <KeysView/>
  {:else if app.page === 'fleet'}
    <FleetView/>
  {/if}
</main>

<Dialog/>
<Toaster/>
