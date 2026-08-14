// Port of agent/alerting/ignore.go, which post.js cannot call into.
// Rules run against the entries parseLine produces: { component, host, dest }.
"use strict";

const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HEX_GROUP = /^[0-9a-f]{1,4}$/;

function parseV4(text) {
  const m = text.match(V4);
  if (!m) return null;

  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const octet = m[i + 1];
    // netip rejects leading zeros, which would otherwise read as octal.
    if (octet.length > 1 && octet[0] === "0") return null;

    const n = Number(octet);
    if (n > 255) return null;
    bytes[i] = n;
  }

  return bytes;
}

function expandGroups(part) {
  if (part === "") return [];

  const fields = part.split(":");
  const groups = [];

  for (let i = 0; i < fields.length; i++) {
    const field = fields[i];

    if (field.includes(".")) {
      const v4 = i === fields.length - 1 ? parseV4(field) : null;
      if (!v4) return null;

      groups.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      continue;
    }

    if (!HEX_GROUP.test(field)) return null;
    groups.push(parseInt(field, 16));
  }

  return groups;
}

function parseV6(text) {
  const zone = text.indexOf("%");
  const body = zone === -1 ? text : text.slice(0, zone);
  if (!body.includes(":")) return null;

  const halves = body.split("::");
  if (halves.length > 2) return null;

  const head = expandGroups(halves[0]);
  if (head === null) return null;

  let groups;
  if (halves.length === 1) {
    if (head.length !== 8) return null;
    groups = head;
  } else {
    const tail = expandGroups(halves[1]);
    if (tail === null || head.length + tail.length > 7) return null;

    groups = [...head, ...new Array(8 - head.length - tail.length).fill(0), ...tail];
  }

  const bytes = new Uint8Array(16);
  groups.forEach((g, i) => {
    bytes[2 * i] = g >> 8;
    bytes[2 * i + 1] = g & 0xff;
  });

  return bytes;
}

function parseAddr(text) {
  if (!text) return null;

  return parseV4(text) || parseV6(text);
}

function parseAddrPort(text) {
  if (!text) return null;

  if (text.startsWith("[")) {
    const end = text.indexOf("]:");

    return end === -1 ? null : parseAddr(text.slice(1, end));
  }

  const colon = text.lastIndexOf(":");

  return colon === -1 ? null : parseAddr(text.slice(0, colon));
}

// netip reads a 4-in-6 address's classes as its IPv4 form, yet no v4 prefix contains it.
function unmap(bytes) {
  if (bytes.length !== 16) return bytes;

  for (let i = 0; i < 10; i++) {
    if (bytes[i] !== 0) return bytes;
  }

  return bytes[10] === 0xff && bytes[11] === 0xff ? bytes.slice(12) : bytes;
}

const isMulticast = (b) => (b.length === 4 ? (b[0] & 0xf0) === 0xe0 : b[0] === 0xff);
const isLoopback = (b) => (b.length === 4 ? b[0] === 127 : b.every((v, i) => v === (i === 15 ? 1 : 0)));
const isUnspecified = (b) => b.every((v) => v === 0);

const isPrivate = (b) =>
  b.length === 4
    ? b[0] === 10 || (b[0] === 172 && (b[1] & 0xf0) === 16) || (b[0] === 192 && b[1] === 168)
    : (b[0] & 0xfe) === 0xfc;

const isLinkLocalUnicast = (b) =>
  b.length === 4 ? b[0] === 169 && b[1] === 254 : b[0] === 0xfe && (b[1] & 0xc0) === 0x80;

const isLinkLocalMulticast = (b) =>
  b.length === 4 ? b[0] === 224 && b[1] === 0 && b[2] === 0 : b[0] === 0xff && b[1] === 0x02;

const isLinkLocal = (b) => isLinkLocalUnicast(b) || isLinkLocalMulticast(b);

const isLocal = (b) =>
  isMulticast(b) || isLoopback(b) || isPrivate(b) || isUnspecified(b) || isLinkLocal(b);

const ADDR_CLASSES = {
  multicast: isMulticast,
  loopback: isLoopback,
  private: isPrivate,
  unspecified: isUnspecified,
  "link-local": isLinkLocal,
  local: isLocal,
  public: (b) => !isLocal(b),
};

// nflog reports an address, the domain-aware components a hostname.
function destinationAddr(entry) {
  for (const candidate of [entry.dest, entry.host]) {
    const addr = parseAddr(candidate) || parseAddrPort(candidate);
    if (addr) return addr;
  }

  return null;
}

function matchesPattern(host, pattern) {
  if (host === pattern) return true;

  // *.example.com matches sub.example.com but not example.com.
  return pattern.startsWith("*.") && host.endsWith(pattern.slice(1));
}

function isIPOnly(entry) {
  const host = entry.host;
  if (host === "" || host === "unknown destination" || host === entry.dest) return true;

  const colon = entry.dest.lastIndexOf(":");

  return colon !== -1 && host === entry.dest.slice(0, colon);
}

function parseIgnoreRule(pattern) {
  pattern = pattern.trim().toLowerCase();
  if (pattern === "") return null;

  if (pattern === "ip-only") return isIPOnly;

  const addrClass = ADDR_CLASSES[pattern];
  if (addrClass) {
    return (entry) => {
      const addr = destinationAddr(entry);

      return addr !== null && addrClass(unmap(addr));
    };
  }

  if (pattern.startsWith("component:")) {
    const component = pattern.slice("component:".length);

    return component === "" ? null : (entry) => entry.component.toLowerCase() === component;
  }

  const prefix = parsePrefix(pattern);
  if (prefix) {
    return (entry) => {
      const addr = destinationAddr(entry);

      return addr !== null && contains(prefix, addr);
    };
  }

  // A domain holds neither character: this is a malformed CIDR or a host:port.
  if (pattern.includes("/") || pattern.includes(":")) return null;

  return (entry) => matchesPattern(entry.host.toLowerCase(), pattern);
}

function parsePrefix(pattern) {
  const slash = pattern.lastIndexOf("/");
  if (slash === -1) {
    const addr = parseAddr(pattern);

    return addr ? { addr, bits: addr.length * 8 } : null;
  }

  const addr = parseAddr(pattern.slice(0, slash));
  const bits = Number(pattern.slice(slash + 1));
  if (!addr || !Number.isInteger(bits) || bits < 0 || bits > addr.length * 8) return null;

  return { addr, bits };
}

function contains(prefix, addr) {
  if (prefix.addr.length !== addr.length) return false;

  const whole = prefix.bits >> 3;
  for (let i = 0; i < whole; i++) {
    if (prefix.addr[i] !== addr[i]) return false;
  }

  const rest = prefix.bits & 7;
  if (rest === 0) return true;

  const mask = 0xff << (8 - rest);

  return (prefix.addr[whole] & mask) === (addr[whole] & mask);
}

// The input is newline-separated; setup.sh hands the agent the comma-joined form.
function parseIgnoreList(raw) {
  return String(raw || "")
    .split(/[\n,]/)
    .map((p) => p.trim())
    .filter(Boolean);
}

function compileIgnoreRules(patterns) {
  const rules = patterns.map(parseIgnoreRule).filter(Boolean);

  return (entry) => rules.some((rule) => rule(entry));
}

function ignoreRulesFromEnv(env = process.env) {
  const raw = env["INPUT_NOTIFICATION-IGNORE"];

  return compileIgnoreRules(parseIgnoreList(raw === undefined || raw === "" ? "local" : raw));
}

module.exports = {
  parseAddr,
  parseIgnoreList,
  parseIgnoreRule,
  compileIgnoreRules,
  ignoreRulesFromEnv,
};
