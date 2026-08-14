// Unit tests for ignore.js, the job-summary port of agent/alerting/ignore.go.
// Dependency-free: uses Node's built-in test runner (`node --test`).
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const {
  parseAddr,
  parseIgnoreList,
  parseIgnoreRule,
  compileIgnoreRules,
  ignoreRulesFromEnv,
} = require("./ignore.js");

const entry = (over = {}) => ({ action: "BLOCKED", component: "", host: "", dest: "", ...over });

const matches = (pattern, over) => compileIgnoreRules([pattern])(entry(over));

test("parseAddr reads IPv4 and rejects malformed octets", () => {
  assert.deepEqual([...parseAddr("1.2.3.4")], [1, 2, 3, 4]);
  assert.equal(parseAddr("256.1.1.1"), null);
  // netip rejects leading zeros rather than reading them as octal.
  assert.equal(parseAddr("01.2.3.4"), null);
  assert.equal(parseAddr("1.2.3"), null);
});

test("parseAddr reads IPv6 in compressed, full, zoned and embedded-v4 forms", () => {
  assert.deepEqual([...parseAddr("::1")].slice(14), [0, 1]);
  assert.deepEqual([...parseAddr("::")], new Array(16).fill(0));
  assert.deepEqual([...parseAddr("ff02::16")].slice(0, 2), [0xff, 0x02]);
  assert.deepEqual([...parseAddr("fe80::1%eth0")].slice(0, 2), [0xfe, 0x80]);
  assert.deepEqual([...parseAddr("::ffff:1.2.3.4")].slice(10), [0xff, 0xff, 1, 2, 3, 4]);
  assert.deepEqual(
    [...parseAddr("2001:0db8:0000:0000:0000:0000:0000:0001")].slice(0, 4),
    [0x20, 0x01, 0x0d, 0xb8],
  );
});

test("parseAddr rejects malformed IPv6", () => {
  assert.equal(parseAddr("::1::2"), null);
  assert.equal(parseAddr(":1:2"), null);
  assert.equal(parseAddr("1:2:3:4:5:6:7"), null);
  assert.equal(parseAddr("fe80::gggg"), null);
  assert.equal(parseAddr("::1.2.3.4:5"), null);
  assert.equal(parseAddr(""), null);
});

test("domain rules match exactly, wildcards match subdomains only", () => {
  assert.ok(matches("example.com", { host: "example.com" }));
  assert.ok(matches("example.com", { host: "EXAMPLE.COM" }));
  assert.ok(!matches("example.com", { host: "sub.example.com" }));

  assert.ok(matches("*.example.com", { host: "sub.example.com" }));
  assert.ok(!matches("*.example.com", { host: "example.com" }));
});

test("address and CIDR rules read the destination field", () => {
  assert.ok(matches("10.0.0.0/8", { dest: "10.1.2.3:51820" }));
  assert.ok(!matches("10.0.0.0/8", { dest: "11.1.2.3:51820" }));
  assert.ok(matches("9.9.9.9", { dest: "9.9.9.9" }));
  assert.ok(matches("fd00::/8", { dest: "[fd00::1]:443" }));
  // A non-byte-aligned prefix still masks correctly.
  assert.ok(matches("192.168.4.0/22", { dest: "192.168.7.9:80" }));
  assert.ok(!matches("192.168.4.0/22", { dest: "192.168.8.9:80" }));
});

test("a v4 prefix does not contain a 4-in-6 address, matching netip", () => {
  assert.ok(!matches("10.0.0.0/8", { dest: "[::ffff:10.1.2.3]:443" }));
  assert.ok(matches("::ffff:0:0/96", { dest: "[::ffff:10.1.2.3]:443" }));
});

test("address classes cover the noise a runner produces", () => {
  assert.ok(matches("multicast", { dest: "224.0.0.22" }));
  assert.ok(matches("multicast", { dest: "239.255.255.250:1900" }));
  assert.ok(matches("multicast", { dest: "[ff02::16]:0" }));
  assert.ok(!matches("multicast", { dest: "1.2.3.4:443" }));

  assert.ok(matches("private", { dest: "10.42.3.0:51820" }));
  assert.ok(matches("private", { dest: "172.16.0.1:80" }));
  assert.ok(!matches("private", { dest: "172.32.0.1:80" }));
  assert.ok(matches("loopback", { dest: "127.0.0.1:53" }));
  assert.ok(matches("loopback", { dest: "[::1]:53" }));
  assert.ok(matches("link-local", { dest: "169.254.169.254:80" }));
  assert.ok(matches("link-local", { dest: "[fe80::1]:443" }));
  assert.ok(matches("unspecified", { dest: "0.0.0.0:0" }));
});

test("local covers every noisy class and public is its complement", () => {
  for (const dest of ["224.0.0.22", "10.42.3.0:51820", "127.0.0.1:53", "[ff02::2]:0", "0.0.0.0:0"]) {
    assert.ok(matches("local", { dest }), dest);
    assert.ok(!matches("public", { dest }), dest);
  }

  assert.ok(!matches("local", { dest: "95.111.222.228:443" }));
  assert.ok(matches("public", { dest: "95.111.222.228:443" }));
});

test("address classes report 4-in-6 addresses as their IPv4 form, matching netip", () => {
  assert.ok(matches("multicast", { dest: "[::ffff:224.0.0.1]:0" }));
  assert.ok(matches("private", { dest: "[::ffff:10.0.0.1]:443" }));
});

test("an address class needs an address, not a hostname", () => {
  assert.ok(!matches("multicast", { host: "example.com" }));
});

test("component rules match the reporting component", () => {
  assert.ok(matches("component:nflog", { component: "nflog", dest: "1.2.3.4:443" }));
  assert.ok(matches("component:NFLOG", { component: "nflog" }));
  assert.ok(!matches("component:nflog", { component: "dns" }));
});

test("ip-only matches blocks that carry no hostname", () => {
  assert.ok(matches("ip-only", { dest: "1.2.3.4:443" }));
  assert.ok(matches("ip-only", { host: "unknown destination", dest: "1.2.3.4:443" }));
  assert.ok(matches("ip-only", { host: "1.2.3.4:443", dest: "1.2.3.4:443" }));
  assert.ok(matches("ip-only", { host: "1.2.3.4", dest: "1.2.3.4:443" }));
  assert.ok(!matches("ip-only", { host: "example.com", dest: "1.2.3.4:443" }));
});

test("parseIgnoreRule drops empty and malformed patterns", () => {
  assert.equal(parseIgnoreRule(""), null);
  assert.equal(parseIgnoreRule("   "), null);
  assert.equal(parseIgnoreRule("component:"), null);
  assert.equal(parseIgnoreRule("10.0.0.0/64"), null);
  assert.equal(parseIgnoreRule("1.2.3.4:443"), null);
});

test("parseIgnoreList accepts the newline input and the comma-joined form", () => {
  assert.deepEqual(parseIgnoreList("local\n*.telemetry.example.com\n"), [
    "local",
    "*.telemetry.example.com",
  ]);
  assert.deepEqual(parseIgnoreList("local,ip-only"), ["local", "ip-only"]);
  assert.deepEqual(parseIgnoreList(""), []);
  assert.deepEqual(parseIgnoreList(undefined), []);
});

test("an empty rule set matches nothing", () => {
  assert.ok(!compileIgnoreRules([])(entry({ dest: "224.0.0.22" })));
});

test("any matching rule wins", () => {
  const ignore = compileIgnoreRules(["example.com", "multicast"]);
  assert.ok(ignore(entry({ host: "example.com" })));
  assert.ok(ignore(entry({ dest: "224.0.0.22" })));
  assert.ok(!ignore(entry({ host: "other.test", dest: "1.2.3.4:443" })));
});

test("ignoreRulesFromEnv defaults to local and honours the input", () => {
  assert.ok(ignoreRulesFromEnv({})(entry({ dest: "224.0.0.22" })));
  assert.ok(ignoreRulesFromEnv({ "INPUT_NOTIFICATION-IGNORE": "" })(entry({ dest: "224.0.0.22" })));
  assert.ok(!ignoreRulesFromEnv({ "INPUT_NOTIFICATION-IGNORE": "public" })(entry({ dest: "224.0.0.22" })));

  const custom = ignoreRulesFromEnv({ "INPUT_NOTIFICATION-IGNORE": "local\n*.telemetry.example.com" });
  assert.ok(custom(entry({ host: "a.telemetry.example.com", dest: "9.9.9.9:443" })));
});
