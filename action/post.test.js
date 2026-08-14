// Unit tests for post.js log parsing / summary rendering.
// Dependency-free: uses Node's built-in test runner (`node --test`).
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  parseLine,
  collectDecisions,
  escapeCell,
  blockedSection,
  buildSummary,
  readManifest,
  teardown,
  maybeTeardown,
} = require("./post.js");

const { compileIgnoreRules } = require("./ignore.js");

const IGNORE_NOTHING = () => false;

const MANIFEST = {
  mode: "https",
  policy: "block",
  image: "docker.io/g0lab/g0efilter:v1.0.0",
  baseDomains: ["github.com", "api.github.com"],
  inputDomains: ["example.org"],
  baseIPs: ["168.63.129.16"],
  inputIPs: ["10.0.0.0/8"],
};

function writeManifest(contents) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "g0e-")), "policy-manifest.json");
  fs.writeFileSync(file, contents);
  return file;
}

test("parseLine extracts a blocked HTTPS decision", () => {
  const line =
    "2026-07-05T00:25:09Z WRN https.blocked action=BLOCKED component=https https=example.com dst=1.2.3.4:443";
  assert.deepEqual(parseLine(line), {
    action: "BLOCKED",
    component: "https",
    host: "example.com",
    dest: "1.2.3.4:443",
  });
});

test("parseLine reads AUDIT and DNS qname/destination_ip fields", () => {
  const line =
    "2026-07-05T00:25:09Z WRN dns.audit action=AUDIT component=dns qname=blocked.example.com destination_ip=9.9.9.9";
  assert.deepEqual(parseLine(line), {
    action: "AUDIT",
    component: "dns",
    host: "blocked.example.com",
    dest: "9.9.9.9",
  });
});

test("parseLine keeps ALLOWED decisions", () => {
  const line = "2026-07-05T00:25:09Z INF https.allowed action=ALLOWED component=https https=example.org";
  assert.equal(parseLine(line).action, "ALLOWED");
});

test("parseLine strips ANSI colour codes before matching", () => {
  const line = "\x1b[33mWRN\x1b[0m action=BLOCKED component=https \x1b[36mhttps=example.com\x1b[0m";
  assert.equal(parseLine(line).host, "example.com");
});

test("parseLine ignores lines without an action field", () => {
  assert.equal(parseLine("2026-07-05T00:25:09Z INF startup.ready component=https"), null);
  assert.equal(parseLine("action=DENIED something"), null);
});

test("collectDecisions splits the three outcomes and dedups repeats", () => {
  const raw = [
    "action=BLOCKED component=https https=example.com dst=1.2.3.4:443",
    "action=BLOCKED component=https https=example.com dst=1.2.3.4:443",
    "action=AUDIT component=dns qname=foo.example.net destination_ip=9.9.9.9",
    "action=ALLOWED component=https https=example.org",
    "action=ALLOWED component=https https=example.org",
    "noise line, no action",
  ].join("\n");

  const { blocked, audited, allowed, totals } = collectDecisions(raw);

  assert.equal(blocked.length, 1);
  assert.equal(blocked[0].count, 2);
  assert.equal(audited.length, 1);
  assert.equal(allowed.length, 1);
  assert.deepEqual(totals, { BLOCKED: 2, AUDIT: 1, ALLOWED: 2 });
});

test("collectDecisions groups allowed hosts across destination IPs", () => {
  const raw = [
    "action=ALLOWED component=https https=example.org dst=1.1.1.1:443",
    "action=ALLOWED component=https https=example.org dst=2.2.2.2:443",
    "action=BLOCKED component=https https=blocked.test dst=1.1.1.1:443",
    "action=BLOCKED component=https https=blocked.test dst=2.2.2.2:443",
  ].join("\n");

  const { allowed, blocked } = collectDecisions(raw);

  assert.equal(allowed.length, 1);
  assert.equal(allowed[0].count, 2);
  // Blocked entries keep the destination: it is the detail needed to debug a denial.
  assert.equal(blocked.length, 2);
});

test("collectDecisions sorts each list by count", () => {
  const raw = [
    "action=BLOCKED component=https https=rare.test dst=1.1.1.1:443",
    "action=BLOCKED component=https https=common.test dst=2.2.2.2:443",
    "action=BLOCKED component=https https=common.test dst=2.2.2.2:443",
  ].join("\n");

  assert.deepEqual(
    collectDecisions(raw).blocked.map((d) => d.host),
    ["common.test", "rare.test"],
  );
});

test("escapeCell neutralises markdown-table-breaking characters", () => {
  assert.equal(escapeCell("a|b"), "a&#124;b");
  assert.equal(escapeCell("<script>"), "&lt;script&gt;");
  assert.equal(escapeCell("a&b"), "a&amp;b");
  assert.equal(escapeCell("line1\r\nline2"), "line1 line2");
  // Ampersand must be escaped first so the other entities are not double-encoded.
  assert.equal(escapeCell("&|"), "&amp;&#124;");
});

test("readManifest returns null when the file is missing or malformed", () => {
  assert.equal(readManifest(path.join(os.tmpdir(), "g0efilter-absent.json")), null);
  assert.equal(readManifest(writeManifest("{not json")), null);
});

test("readManifest keeps only string entries and defaults missing fields", () => {
  const file = writeManifest(JSON.stringify({ mode: "dns", baseDomains: ["a.test", 7, null] }));
  const m = readManifest(file);

  assert.equal(m.mode, "dns");
  assert.equal(m.image, "");
  assert.deepEqual(m.baseDomains, ["a.test"]);
  assert.deepEqual(m.inputDomains, []);
});

test("readManifest reads a manifest written by setup.sh, escapes included", () => {
  const file = writeManifest(
    '{"mode":"https","policy":"block","image":"i","baseDomains":["github.com"],' +
      '"inputDomains":["/^cache-[0-9]+\\\\.example\\\\.com$/"],"baseIPs":[],"inputIPs":[]}',
  );

  assert.deepEqual(readManifest(file).inputDomains, ["/^cache-[0-9]+\\.example\\.com$/"]);
});

test("buildSummary reports when no logs were captured", () => {
  const md = buildSummary("");
  assert.match(md, /## g0efilter egress report/);
  assert.match(md, /filter may have failed to start/);
});

test("buildSummary still lists the loaded allowlist when no logs were captured", () => {
  const md = buildSummary("", { manifest: MANIFEST });
  assert.match(md, /Loaded allowlist/);
  assert.match(md, /example\.org/);
});

test("buildSummary reports a clean run with only allowed decisions", () => {
  const md = buildSummary("action=ALLOWED component=https https=example.org");
  assert.match(md, /No connections were blocked or audited/);
  assert.match(md, /### Allowed/);
});

test("buildSummary falls back to the policy input when there is no manifest", () => {
  const prev = process.env["INPUT_EGRESS-POLICY"];
  process.env["INPUT_EGRESS-POLICY"] = "audit";
  try {
    assert.match(buildSummary("action=ALLOWED https=a.test"), /\*\*Egress policy:\*\* `audit`/);
  } finally {
    if (prev === undefined) delete process.env["INPUT_EGRESS-POLICY"];
    else process.env["INPUT_EGRESS-POLICY"] = prev;
  }
});

test("teardown removes the container and deletes each managed nft table", () => {
  const calls = [];
  teardown((cmd, args) => calls.push([cmd, args]));
  assert.deepEqual(calls, [
    ["docker", ["rm", "-f", "g0efilter"]],
    ["sudo", ["nft", "delete", "table", "ip", "g0efilter_v4"]],
    ["sudo", ["nft", "delete", "table", "ip", "g0efilter_nat_v4"]],
    ["sudo", ["nft", "delete", "table", "ip6", "g0efilter_v6"]],
    ["sudo", ["nft", "delete", "table", "ip6", "g0efilter_nat_v6"]],
    ["sudo", ["nft", "delete", "table", "ip", "g0efilter_bridge_v4"]],
    ["sudo", ["nft", "delete", "table", "ip", "g0efilter_bridge_nat_v4"]],
    ["sudo", ["nft", "delete", "table", "ip6", "g0efilter_bridge_v6"]],
    ["sudo", ["nft", "delete", "table", "ip6", "g0efilter_bridge_nat_v6"]],
  ]);
});

test("teardown swallows command failures without throwing", () => {
  assert.doesNotThrow(() =>
    teardown(() => {
      throw new Error("boom");
    }),
  );
});

test("maybeTeardown skips teardown under lockdown", () => {
  const calls = [];
  const ran = maybeTeardown(true, (cmd, args) => calls.push([cmd, args]));
  assert.equal(ran, false);
  assert.equal(calls.length, 0);
});

test("maybeTeardown runs teardown when not locked down", () => {
  const calls = [];
  const ran = maybeTeardown(false, (cmd, args) => calls.push([cmd, args]));
  assert.equal(ran, true);
  assert.ok(calls.length > 0);
});

test("buildSummary notes lockdown when no logs were captured", () => {
  const md = buildSummary("", { lockdown: true });
  assert.match(md, /Lockdown-runner mode/);
  assert.match(md, /Docker access was locked down/);
});

test("buildSummary renders the full report", () => {
  const raw = [
    "action=ALLOWED component=https https=example.org dst=1.1.1.1:443",
    "action=ALLOWED component=https https=github.com dst=1.1.1.2:443",
    "action=BLOCKED component=https https=evil.test dst=9.9.9.9:443",
    "action=AUDIT component=dns qname=watched.test destination_ip=8.8.8.8",
  ].join("\n");

  const md = buildSummary(raw, { manifest: MANIFEST });

  assert.match(md, /\*\*Mode:\*\* `https`/);
  assert.match(md, /\*\*Image:\*\* `docker\.io\/g0lab\/g0efilter:v1\.0\.0`/);

  assert.match(md, /\| Allowed \| 2 \| 2 \|/);
  assert.match(md, /\| Blocked \| 1 \| 1 \|/);
  assert.match(md, /\| Audited \| 1 \| 1 \|/);

  assert.match(md, /### Blocked \(1\)[\s\S]*evil\.test/);
  assert.match(md, /### Audited \(1\)[\s\S]*watched\.test/);
  assert.match(md, /2 hosts reached[\s\S]*example\.org/);

  assert.match(md, /\*\*Domains from this workflow \(1\)\*\*/);
  assert.match(md, /\*\*Baseline domains \(2\)\*\*/);
  assert.match(md, /\*\*IPs from this workflow \(1\)\*\*[\s\S]*10\.0\.0\.0\/8/);
  assert.doesNotMatch(md, /No connections were blocked or audited/);
});

test("buildSummary renders empty allowlist groups as none rather than omitting them", () => {
  const md = buildSummary("action=ALLOWED https=a.test", {
    manifest: { ...MANIFEST, inputDomains: [], inputIPs: [] },
  });

  assert.match(md, /\*\*Domains from this workflow \(0\)\*\*\n\n_none_/);
});

test("buildSummary renders hosts as code spans, escaping the table's own pipe", () => {
  // GitHub escapes the content of a code span, so angle brackets need no entity.
  const md = buildSummary("action=BLOCKED component=https https=a|b<c>");
  assert.match(md, /\| `a\\\|b<c>` \|/);
});

// A backslash already in the host would otherwise escape the escape, freeing the pipe.
test("buildSummary escapes a backslash before the pipe it protects", () => {
  const md = buildSummary("action=BLOCKED component=https https=a\\|b.test");
  const row = md.split("\n").find((line) => line.includes("a\\"));

  assert.match(row, /\| `a\\\\\\\|b\.test` \| https \|/);
  assert.equal(row.split(/(?<!\\)\|/).length - 1, 5);
});

test("buildSummary keeps wildcard hosts literal instead of italicising them", () => {
  const md = buildSummary("action=BLOCKED component=https https=*.example.com");
  assert.match(md, /\| `\*\.example\.com` \|/);
});

test("buildSummary shows a placeholder for missing fields", () => {
  const md = buildSummary("action=BLOCKED https=a.test");
  assert.match(md, /\| `a\.test` \| - \| - \| 1 \|/);
});

test("blockedSection folds ignored blocks into a collapsible", () => {
  const rows = [
    { component: "https", host: "evil.test", dest: "9.9.9.9:443", count: 3 },
    { component: "nflog", host: "", dest: "224.0.0.22", count: 4 },
    { component: "nflog", host: "", dest: "239.255.255.250:1900", count: 5 },
  ];

  const md = blockedSection(rows, compileIgnoreRules(["local"]));

  assert.match(md, /### Blocked \(1\)/);
  assert.match(md, /evil\.test/);
  assert.match(md, /<summary>2 destinations \(9 decisions\) matched notification-ignore<\/summary>/);
  assert.match(md, /224\.0\.0\.22/);
  assert.match(md, /239\.255\.255\.250:1900/);
});

test("blockedSection omits the collapsible when nothing is ignored", () => {
  const rows = [{ component: "https", host: "evil.test", dest: "9.9.9.9:443", count: 1 }];
  const md = blockedSection(rows, IGNORE_NOTHING);

  assert.match(md, /### Blocked \(1\)/);
  assert.doesNotMatch(md, /notification-ignore/);
});

test("blockedSection says so when every block was ignored", () => {
  const rows = [{ component: "nflog", host: "", dest: "224.0.0.22", count: 4 }];
  const md = blockedSection(rows, compileIgnoreRules(["local"]));

  assert.match(md, /### Blocked \(0\)/);
  assert.match(md, /Every block matched `notification-ignore`/);
  assert.match(md, /<summary>1 destination \(4 decisions\)/);
});

test("blockedSection renders nothing when there were no blocks", () => {
  assert.equal(blockedSection([], compileIgnoreRules(["local"])), "");
});

test("buildSummary keeps the overview counting every block, ignored or not", () => {
  const raw = [
    "action=BLOCKED component=https https=evil.test dst=9.9.9.9:443",
    "action=BLOCKED component=nflog dst=224.0.0.22",
    "action=BLOCKED component=nflog dst=10.42.3.0:51820",
  ].join("\n");

  const md = buildSummary(raw, { ignore: compileIgnoreRules(["local"]) });

  assert.match(md, /\| Blocked \| 3 \| 3 \|/);
  assert.match(md, /### Blocked \(1\)/);
  assert.match(md, /2 destinations \(2 decisions\) matched notification-ignore/);
});

test("buildSummary applies the local default when no ignore rules are passed", () => {
  const md = buildSummary("action=BLOCKED component=nflog dst=224.0.0.22");

  assert.match(md, /### Blocked \(0\)/);
  assert.match(md, /matched notification-ignore/);
});

test("blockedSection pluralises the ignored-group summary", () => {
  const one = blockedSection([{ component: "nflog", host: "", dest: "224.0.0.22", count: 1 }], () => true);
  assert.match(one, /<summary>1 destination \(1 decision\) matched/);

  const many = blockedSection(
    [
      { component: "nflog", host: "", dest: "224.0.0.22", count: 4 },
      { component: "nflog", host: "", dest: "239.255.255.250:1900", count: 5 },
    ],
    () => true,
  );
  assert.match(many, /<summary>2 destinations \(9 decisions\) matched/);
});

test("buildSummary orders the overview worst outcome first", () => {
  const md = buildSummary("action=ALLOWED component=https https=example.org");
  assert.match(md, /\| Blocked \| 0 \| 0 \|\n\| Audited \| 0 \| 0 \|\n\| Allowed \| 1 \| 1 \|/);
});

test("buildSummary leaves the blocked table intact when ignoring nothing", () => {
  const raw = [
    "action=BLOCKED component=https https=evil.test dst=9.9.9.9:443",
    "action=BLOCKED component=nflog dst=224.0.0.22",
  ].join("\n");

  const md = buildSummary(raw, { ignore: IGNORE_NOTHING });

  assert.match(md, /### Blocked \(2\)/);
  assert.doesNotMatch(md, /matched notification-ignore/);
});
