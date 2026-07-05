// Unit tests for post.js log parsing / summary rendering.
// Dependency-free: uses Node's built-in test runner (`node --test`).
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { parseLine, collectDecisions, escapeCell, buildSummary } = require("./post.js");

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

test("collectDecisions dedups repeats and tallies allowed separately", () => {
  const raw = [
    "action=BLOCKED component=https https=example.com dst=1.2.3.4:443",
    "action=BLOCKED component=https https=example.com dst=1.2.3.4:443",
    "action=AUDIT component=dns qname=foo.example.net destination_ip=9.9.9.9",
    "action=ALLOWED component=https https=example.org",
    "action=ALLOWED component=https https=example.org",
    "noise line, no action",
  ].join("\n");

  const { decisions, allowed } = collectDecisions(raw);
  assert.equal(allowed, 2);
  assert.equal(decisions.length, 2);

  const blocked = decisions.find((d) => d.action === "BLOCKED");
  assert.equal(blocked.count, 2);
  assert.equal(decisions.find((d) => d.action === "AUDIT").count, 1);
});

test("escapeCell neutralises markdown-table-breaking characters", () => {
  assert.equal(escapeCell("a|b"), "a&#124;b");
  assert.equal(escapeCell("<script>"), "&lt;script&gt;");
  assert.equal(escapeCell("a&b"), "a&amp;b");
  assert.equal(escapeCell("line1\r\nline2"), "line1 line2");
  // Ampersand must be escaped first so the other entities are not double-encoded.
  assert.equal(escapeCell("&|"), "&amp;&#124;");
});

test("buildSummary reports when no logs were captured", () => {
  const md = buildSummary("");
  assert.match(md, /## g0efilter egress report/);
  assert.match(md, /filter may have failed to start/);
});

test("buildSummary reports a clean run with only allowed decisions", () => {
  const md = buildSummary("action=ALLOWED component=https https=example.org");
  assert.match(md, /No blocked or audited connections \(1 allowed decisions logged\)/);
});

test("buildSummary renders a decision table and honours the policy env var", () => {
  const prev = process.env["INPUT_EGRESS-POLICY"];
  process.env["INPUT_EGRESS-POLICY"] = "audit";
  try {
    const raw = [
      "action=ALLOWED component=https https=example.org",
      "action=AUDIT component=https https=example.com dst=1.2.3.4:443",
    ].join("\n");
    const md = buildSummary(raw);
    assert.match(md, /Egress policy: `audit`/);
    assert.match(md, /\| Action \| Component \| Domain \/ Host \| Destination \| Count \|/);
    assert.match(md, /⚠️ AUDIT/);
    assert.match(md, /example\.com/);
  } finally {
    if (prev === undefined) delete process.env["INPUT_EGRESS-POLICY"];
    else process.env["INPUT_EGRESS-POLICY"] = prev;
  }
});
