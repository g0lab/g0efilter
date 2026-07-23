/* API helper: same-origin fetch; any 401 means the session is gone, so we
   return to the login page. In demo mode (VITE_DEMO_MODE) requests are served
   from an in-memory dataset instead of the network. */
import { DEMO, demoConfig, demoLogs, demoBrowse, demoAggregate } from './demo';

const origFetch = window.fetch.bind(window);

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

function demoFetch(url: string): Response {
  const u = new URL(url, 'http://demo');
  const p = u.searchParams;
  switch (u.pathname) {
    case '/api/v1/config': return jsonResponse(demoConfig());
    case '/api/v1/logs/browse': return jsonResponse(demoBrowse(p));
    case '/api/v1/logs': return jsonResponse(demoLogs(p));
    case '/api/v1/aggregates': return jsonResponse(demoAggregate(p));
    case '/api/v1/unblocks/status': return jsonResponse({ pending: [], completed: [] });
    // Mutations/admin endpoints are hidden in demo; answer benignly.
    default: return jsonResponse({ status: 'ok' });
  }
}

export function apiFetch(url: string, opts?: RequestInit): Promise<Response> {
  if (DEMO) return Promise.resolve(demoFetch(url));
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
