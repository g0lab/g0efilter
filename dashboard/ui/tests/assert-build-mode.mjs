import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const mode = process.argv[2];
assert.ok(mode === 'demo' || mode === 'production', `unknown build mode: ${mode}`);

const assetsDir = fileURLToPath(new URL('../dist/assets/', import.meta.url));
const files = (await readdir(assetsDir)).filter((name) => name.endsWith('.js'));
const bundle = (await Promise.all(
  files.map((name) => readFile(join(assetsDir, name), 'utf8')),
)).join('\n');
const containsFixtures = bundle.includes('crypto-miner.bad.example');

assert.equal(
  containsFixtures,
  mode === 'demo',
  `${mode} build fixture inclusion was ${containsFixtures}, want ${mode === 'demo'}`,
);
