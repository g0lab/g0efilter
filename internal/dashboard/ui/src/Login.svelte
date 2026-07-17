<script lang="ts">
  import { onMount } from 'svelte';

  let username = $state('');
  let password = $state('');
  let error = $state('');

  onMount(async () => {
    // Already authenticated (or auth disabled)? Go straight in.
    try {
      const r = await fetch('/api/v1/auth/me');
      if (r.ok) window.location.replace('/');
    } catch { /* ignore */ }
  });

  async function submit(ev: Event) {
    ev.preventDefault();
    error = '';

    let res: Response;
    try {
      res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });
    } catch {
      error = 'Network error';
      return;
    }

    if (res.ok) { window.location.replace('/'); return; }

    if (res.status === 401) error = 'Invalid username or password';
    else if (res.status === 429) error = 'Too many attempts - try again shortly';
    else error = 'Login failed (status ' + res.status + ')';
  }
</script>

<main class="login-wrap">
  <form class="box login-box" autocomplete="on" onsubmit={submit}>
    <h1>g0efilter</h1>
    <label>Username
      <input class="input" name="username" type="text" autocomplete="username" required bind:value={username}/>
    </label>
    <label>Password
      <input class="input" name="password" type="password" autocomplete="current-password" required bind:value={password}/>
    </label>
    <p class="login-error">{error}</p>
    <button class="btn btn-primary w-full" type="submit">Sign in</button>
  </form>
</main>
