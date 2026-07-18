/* API helper: same-origin fetch; any 401 means the session is gone, so we
   return to the login page. */

const origFetch = window.fetch.bind(window);

export function apiFetch(url: string, opts?: RequestInit): Promise<Response> {
  return origFetch(url, opts).then((r) => {
    if (r.status === 401) window.location.replace('/login.html');
    return r;
  });
}

/* Operators may store an API key locally to script against UI endpoints;
   when present it is sent alongside (or instead of) the session cookie. */
export function apiKeyHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const key = localStorage.getItem('apiKey') || '';
  return key ? { ...extra, 'X-Api-Key': key } : { ...extra };
}
