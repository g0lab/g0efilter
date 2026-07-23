import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  createDemoRuntime,
  type DemoFixtures,
} from '../src/lib/demo-data.ts';

const NOW = Date.parse('2026-07-23T12:00:00Z');
const fixtures: DemoFixtures = {
  source_subnet: '172.20',
  clients: ['runner-a', 'runner-b'],
  destinations: [
    {
      domain: 'allowed.example',
      category: 'source-hosting',
      verdict: 'ALLOWED',
      component: 'https',
      port: 443,
      reason: 'allowlisted',
      ip: '192.0.2.10',
    },
    {
      domain: 'blocked.example',
      category: 'malware',
      verdict: 'BLOCKED',
      component: 'dns',
      port: 0,
      reason: 'not-allowlisted',
      ip: '',
    },
    {
      domain: '',
      category: 'raw-egress',
      verdict: 'AUDIT',
      component: 'nflog',
      port: 4444,
      reason: 'not-allowlisted',
      ip: '192.0.2.30',
    },
  ],
};

function runtime() {
  return createDemoRuntime(fixtures, { datasetSize: 30, now: () => NOW });
}

test('demo browse mirrors range, facets, query, and pagination', () => {
  const demo = runtime();
  const all = demo.browse(new URLSearchParams({ range: 'all' }));
  assert.equal(all.total, 30);

  const blocked = demo.browse(new URLSearchParams({ range: 'all', action: 'blocked' }));
  assert.equal(blocked.total, 10);
  assert.ok(blocked.rows.every((entry) => entry.action === 'BLOCKED'));

  const dns = demo.browse(new URLSearchParams({ range: 'all', component: 'dns' }));
  assert.equal(dns.total, 10);
  assert.ok(dns.rows.every((entry) => entry.component === 'dns'));

  const client = demo.browse(new URLSearchParams({ range: 'all', q: 'RUNNER-B' }));
  assert.equal(client.total, 15);
  assert.ok(client.rows.every((entry) => entry.hostname === 'runner-b'));

  const page = demo.browse(new URLSearchParams({ range: 'all', limit: '4', offset: '3' }));
  assert.deepEqual(page.rows, all.rows.slice(3, 7));

  const recent = demo.browse(new URLSearchParams({ range: '24h' }));
  assert.ok(recent.total > 0 && recent.total < all.total);
});

test('demo aggregates preserve verdict totals, dimensions, and buckets', () => {
  const demo = runtime();
  const result = demo.aggregate(new URLSearchParams({ range: 'all', dimension: 'domain' }));

  assert.equal(result.events, 30);
  assert.deepEqual(result.totals, { allowed: 10, blocked: 10, audit: 10 });
  assert.deepEqual(result.rows.map((row) => row.key).sort(), ['allowed.example', 'blocked.example']);
  assert.equal(result.buckets.length, 24);

  const bucketEvents = result.buckets.reduce(
    (total, bucket) => total + bucket.allowed + bucket.blocked + bucket.audit,
    0,
  );
  assert.equal(bucketEvents, result.events);

  const dns = demo.aggregate(new URLSearchParams({
    range: 'all',
    dimension: 'domain',
    component: 'dns',
    q: 'blocked.example',
  }));
  assert.equal(dns.events, 10);
  assert.deepEqual(dns.totals, { allowed: 0, blocked: 10, audit: 0 });
  assert.equal(dns.rows[0]?.key, 'blocked.example');
});

test('demo entries mirror DNS query and NFLOG packet fields', () => {
  const demo = runtime();
  const dns = demo.browse(new URLSearchParams({
    range: 'all', component: 'dns', limit: '1',
  })).rows[0];
  assert.equal(dns?.https, 'blocked.example');
  assert.equal(dns?.protocol, 'UDP');
  assert.equal(dns?.destination_ip, undefined);
  assert.equal(dns?.destination_port, undefined);
  assert.equal((dns?.fields as Record<string, unknown>)?.qname, 'blocked.example');

  const nflog = demo.browse(new URLSearchParams({
    range: 'all', component: 'nflog', limit: '1',
  })).rows[0];
  assert.equal(nflog?.http_host, undefined);
  assert.equal(nflog?.https, undefined);
  assert.equal(nflog?.destination_ip, '192.0.2.30');
  assert.equal(nflog?.destination_port, 4444);
});

test('live demo events update every read model while retaining the buffer size', () => {
  const demo = runtime();
  const before = demo.aggregate(new URLSearchParams({ range: '15m' }));
  const event = demo.liveEvent();

  assert.equal(event.id, 31);
  assert.equal(event.flow_id, 'demo-31');
  assert.equal(event.version, 'v0.demo');
  assert.equal(demo.logs(new URLSearchParams({ limit: '1' }))[0]?.id, event.id);
  assert.equal(demo.browse(new URLSearchParams({ range: 'all' })).total, 30);
  assert.equal(
    demo.aggregate(new URLSearchParams({ range: '15m' })).events,
    before.events + 1,
  );
  assert.deepEqual(demo.config(), {
    auth_mode: 'none',
    fleet_enabled: false,
    buffer_size: 30,
    read_limit: 500,
  });
});

test('demo runtime rejects empty fixture collections', () => {
  assert.throws(
    () => createDemoRuntime({ ...fixtures, clients: [] }),
    /require destinations and clients/,
  );
  assert.throws(
    () => createDemoRuntime({ ...fixtures, destinations: [] }),
    /require destinations and clients/,
  );
});
