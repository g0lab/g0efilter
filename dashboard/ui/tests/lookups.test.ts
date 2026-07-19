import assert from 'node:assert/strict';
import { test } from 'node:test';

import { lookupLinks } from '../src/lib/lookups.ts';

test('normalizes bracketed IPv6 and host ports', () => {
  const ipv6 = lookupLinks('[2001:db8::1]:443');
  assert.equal(ipv6.length, 1);
  assert.equal(ipv6[0].value, '2001:db8::1');
  assert.equal(ipv6[0].url, 'https://www.virustotal.com/gui/search?query=2001%3Adb8%3A%3A1');

  const domain = lookupLinks('Example.COM:8443');
  assert.equal(domain.length, 1);
  assert.equal(domain[0].value, 'Example.COM');
});

test('infers IPv4 and domain lookup kinds', () => {
  assert.equal(lookupLinks('7.7.7.7')[0]?.value, '7.7.7.7');
  assert.equal(lookupLinks('api.example.com')[0]?.value, 'api.example.com');
  assert.equal(lookupLinks('7.7.7.7', 'domain').length, 0);
  assert.equal(lookupLinks('api.example.com', 'ip').length, 0);
});

test('rejects invalid lookup boundaries', () => {
  const invalid = [
    '',
    'localhost',
    '999.1.1.1',
    '::::',
    'bad..example',
    '-bad.example',
    'bad-.example',
    `${'a'.repeat(64)}.example`,
    '[2001:db8::1',
  ];

  for (const value of invalid) assert.deepEqual(lookupLinks(value), [], value);
});
