/* API helper: same-origin fetch; any 401 means the session is gone, so we
   return to the login page. In demo mode, a browser-only adapter synthesizes
   responses from an in-memory dataset; no network requests are made. */
import { DEMO, demoConfig, demoLogs, demoBrowse, demoAggregate } from '$demo-runtime';

const origFetch = window.fetch.bind(window);

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function demoResponse(url: string, opts?: RequestInit): Response {
  const u = new URL(url, 'http://demo');
  const p = u.searchParams;
  const method = (opts?.method || 'GET').toUpperCase();
  switch (`${method} ${u.pathname}`) {
    case 'GET /api/v1/config': return jsonResponse(demoConfig());
    case 'GET /api/v1/logs/browse': return jsonResponse(demoBrowse(p));
    case 'GET /api/v1/logs': return jsonResponse(demoLogs(p));
    case 'GET /api/v1/aggregates': return jsonResponse(demoAggregate(p));
    case 'GET /api/v1/unblocks/status': return jsonResponse({ pending: [], completed: [] });
    case 'POST /api/v1/unblocks': return jsonResponse({ id: 'demo', status: 'completed' }, 201);
    default: return jsonResponse({ error: 'not available in demo mode' }, 404);
  }
}

export function apiFetch(url: string, opts?: RequestInit): Promise<Response> {
  if (DEMO) return Promise.resolve(demoResponse(url, opts));
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
