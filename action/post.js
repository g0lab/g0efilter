// Post step: summarise g0efilter decisions from the container logs into the
// job summary. Dependency-free on purpose: no npm install or dist build step.
//
// g0efilter logs in zerolog console format, e.g.:
//   2026-07-05T00:25:09Z WRN https.blocked action=BLOCKED component=https https=example.com dst=1.2.3.4:443 ...
"use strict";

const { execSync, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const { ignoreRulesFromEnv } = require("./ignore.js");

const ANSI = /\x1b\[[0-9;]*m/g;

function containerLogs() {
  try {
    return execSync("docker logs g0efilter 2>&1", {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch {
    return "";
  }
}

function manifestPath() {
  return (
    process.env.G0EFILTER_MANIFEST ||
    path.join(process.env.RUNNER_TEMP || "/tmp", "g0efilter", "policy-manifest.json")
  );
}

function strings(value) {
  return Array.isArray(value) ? value.filter((v) => typeof v === "string") : [];
}

// The manifest is written by setup.sh. Its absence is not an error: the filter may
// have failed before writing it, and the decision report still stands alone.
function readManifest(file = manifestPath()) {
  let raw;
  try {
    raw = fs.readFileSync(file, "utf8");
  } catch {
    return null;
  }

  try {
    const m = JSON.parse(raw);
    return {
      mode: String(m.mode || ""),
      policy: String(m.policy || ""),
      image: String(m.image || ""),
      baseDomains: strings(m.baseDomains),
      inputDomains: strings(m.inputDomains),
      baseIPs: strings(m.baseIPs),
      inputIPs: strings(m.inputIPs),
    };
  } catch {
    return null;
  }
}

function field(line, key) {
  const m = line.match(new RegExp(`(?:^|\\s)${key}=(\\S+)`));
  return m ? m[1] : "";
}

function parseLine(rawLine) {
  const line = rawLine.replace(ANSI, "");
  const m = line.match(/(?:^|\s)action=(BLOCKED|AUDIT|ALLOWED)(?:\s|$)/);
  if (!m) return null;

  return {
    action: m[1],
    component: field(line, "component"),
    host: field(line, "https") || field(line, "host") || field(line, "qname"),
    dest: field(line, "dst") || field(line, "destination_ip"),
  };
}

// Allowed traffic is grouped by host alone: one allowed domain fans out across many
// destination IPs, and listing each one buries the hosts an operator came to read.
function groupKey(entry) {
  return entry.action === "ALLOWED"
    ? [entry.action, entry.host].join("|")
    : [entry.action, entry.component, entry.host, entry.dest].join("|");
}

function collectDecisions(raw) {
  const groups = new Map();
  const totals = { BLOCKED: 0, AUDIT: 0, ALLOWED: 0 };

  for (const rawLine of raw.split("\n")) {
    const entry = parseLine(rawLine);
    if (!entry) continue;

    totals[entry.action]++;

    const key = groupKey(entry);
    const seen = groups.get(key);

    if (seen) {
      seen.count++;
    } else {
      groups.set(key, { ...entry, count: 1 });
    }
  }

  const of = (action) =>
    [...groups.values()]
      .filter((d) => d.action === action)
      .sort((a, b) => b.count - a.count || a.host.localeCompare(b.host));

  return {
    blocked: of("BLOCKED"),
    audited: of("AUDIT"),
    allowed: of("ALLOWED"),
    totals,
  };
}

function escapeCell(v) {
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/\|/g, "&#124;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/[\r\n]+/g, " ");
}

function cell(v) {
  const s = escapeCell(v).trim();
  return s === "" ? "-" : s;
}

// Hosts and addresses go in a code span: it keeps `*.example.com` and `a_b.test` from
// rendering as emphasis, and GitHub escapes the content. Entities would show verbatim
// there, so only the backtick and the table's own pipe need escaping.
function codeCell(v) {
  const s = String(v)
    .replace(/[\r\n]+/g, " ")
    .replace(/`/g, "'")
    .replace(/\|/g, "\\|")
    .trim();

  return s === "" ? "-" : `\`${s}\``;
}

function decisionTable(rows, { destination = true } = {}) {
  let md = destination
    ? "| Domain / Host | Component | Destination | Count |\n|---|---|---|---:|\n"
    : "| Domain / Host | Component | Count |\n|---|---|---:|\n";

  for (const d of rows) {
    md += destination
      ? `| ${codeCell(d.host)} | ${cell(d.component)} | ${codeCell(d.dest)} | ${d.count} |\n`
      : `| ${codeCell(d.host)} | ${cell(d.component)} | ${d.count} |\n`;
  }

  return md + "\n";
}

// GitHub strips CSS from job summaries, so the outcome colours come from GFM alerts:
// CAUTION renders red, WARNING amber, TIP green, NOTE blue.
function alert(kind, body) {
  return `> [!${kind}]\n> ${body}\n\n`;
}

function decisionCount(rows) {
  return rows.reduce((n, d) => n + d.count, 0);
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function collapsible(title, body) {
  return `<details>\n<summary>${title}</summary>\n\n${body}</details>\n\n`;
}

function bullets(title, values) {
  let md = `**${title} (${values.length})**\n\n`;
  if (values.length === 0) return md + "_none_\n\n";

  for (const v of values) md += `- \`${v.replace(/`/g, "'")}\`\n`;

  return md + "\n";
}

// Ordered as the sections below are, worst outcome first.
function overview({ blocked, audited, allowed, totals }) {
  return (
    "| Outcome | Unique hosts | Decisions |\n|---|---:|---:|\n" +
    `| Blocked | ${blocked.length} | ${totals.BLOCKED} |\n` +
    `| Audited | ${audited.length} | ${totals.AUDIT} |\n` +
    `| Allowed | ${allowed.length} | ${totals.ALLOWED} |\n\n`
  );
}

function policySection(manifest) {
  if (!manifest) return "";

  const domains = manifest.baseDomains.length + manifest.inputDomains.length;
  const ips = manifest.baseIPs.length + manifest.inputIPs.length;

  const body =
    bullets("Domains from this workflow", manifest.inputDomains) +
    bullets("Baseline domains", manifest.baseDomains) +
    bullets("IPs from this workflow", manifest.inputIPs) +
    bullets("Baseline IPs", manifest.baseIPs);

  return (
    "### Loaded allowlist\n\n" +
    collapsible(`${plural(domains, "domain")} and ${plural(ips, "IP")} allowed`, body)
  );
}

// Blocks matching notification-ignore are folded away rather than dropped: the
// summary stays a complete record, and the overview counts every decision.
function blockedSection(blocked, ignore) {
  if (blocked.length === 0) return "";

  const ignored = blocked.filter((d) => ignore(d));
  const alerting = blocked.filter((d) => !ignore(d));

  let md = `### Blocked (${alerting.length})\n\n`;

  if (alerting.length > 0) {
    md +=
      alert(
        "CAUTION",
        `Denied ${plural(alerting.length, "destination")} over ` +
          `${plural(decisionCount(alerting), "connection attempt")}.`,
      ) + decisionTable(alerting);
  } else {
    md += alert("NOTE", "Every block matched `notification-ignore`.");
  }

  if (ignored.length > 0) {
    md += collapsible(
      `${plural(ignored.length, "destination")} (${plural(decisionCount(ignored), "decision")})` +
        " matched notification-ignore",
      decisionTable(ignored),
    );
  }

  return md;
}

function auditedSection(audited) {
  if (audited.length === 0) return "";

  return (
    `### Audited (${audited.length})\n\n` +
    alert(
      "WARNING",
      `${plural(decisionCount(audited), "connection")} would have been blocked under ` +
        "`egress-policy: block`. They were reported only.",
    ) +
    decisionTable(audited)
  );
}

function allowedSection(allowed) {
  if (allowed.length === 0) return "";

  return (
    "### Allowed\n\n" +
    alert("TIP", `${plural(decisionCount(allowed), "connection")} reached an allowlisted host.`) +
    collapsible(`${plural(allowed.length, "host")} reached`, decisionTable(allowed, { destination: false }))
  );
}

function heading(manifest, lockdown) {
  let md = "## g0efilter egress report\n\n";

  if (manifest) {
    md +=
      `**Mode:** \`${manifest.mode}\` &nbsp; **Egress policy:** \`${manifest.policy}\`` +
      ` &nbsp; **Image:** \`${manifest.image}\`\n\n`;
  } else {
    md += `**Egress policy:** \`${process.env["INPUT_EGRESS-POLICY"] || "block"}\`\n\n`;
  }

  if (lockdown) {
    md += alert(
      "NOTE",
      "Lockdown-runner mode: teardown was skipped and later sudo/Docker access was disabled.",
    );
  }

  return md;
}

function buildSummary(raw, { lockdown = false, manifest = null, ignore = ignoreRulesFromEnv() } = {}) {
  const md = heading(manifest, lockdown);

  if (!raw.trim()) {
    return (
      md +
      // Under lockdown the missing logs are expected; otherwise the filter failed.
      alert(
        lockdown ? "NOTE" : "CAUTION",
        lockdown
          ? "No logs captured - Docker access was locked down after startup."
          : "No g0efilter logs found - the filter may have failed to start.",
      ) +
      policySection(manifest)
    );
  }

  const decisions = collectDecisions(raw);
  let report = md + overview(decisions);

  if (decisions.blocked.length === 0 && decisions.audited.length === 0) {
    report += alert("TIP", "No connections were blocked or audited.");
  }

  report +=
    blockedSection(decisions.blocked, ignore) +
    auditedSection(decisions.audited) +
    allowedSection(decisions.allowed);

  return report + policySection(manifest);
}

function run(cmd, args) {
  execFileSync(cmd, args, { stdio: "ignore" });
}

const TEARDOWN_TABLES = [
  ["ip", "g0efilter_v4"],
  ["ip", "g0efilter_nat_v4"],
  ["ip6", "g0efilter_v6"],
  ["ip6", "g0efilter_nat_v6"],
  ["ip", "g0efilter_bridge_v4"],
  ["ip", "g0efilter_bridge_nat_v4"],
  ["ip6", "g0efilter_bridge_v6"],
  ["ip6", "g0efilter_bridge_nat_v6"],
];

// Rules live in the host netns; a leftover container or ruleset would brick the
// runner's DNS/egress after the job. Best-effort - never fail the post step.
function teardown(exec = run) {
  try {
    exec("docker", ["rm", "-f", "g0efilter"]);
  } catch {}

  for (const table of TEARDOWN_TABLES) {
    try {
      exec("sudo", ["nft", "delete", "table", ...table]);
    } catch {} // table absent, or no sudo on self-hosted runners
  }
}

// Lockdown intentionally skips teardown: sudo/Docker were disabled after
// startup and the GitHub-hosted runner VM is discarded once the job ends.
function maybeTeardown(lockdown, exec = run) {
  if (lockdown) return false;
  teardown(exec);
  return true;
}

function main() {
  const lockdown = process.env["INPUT_LOCKDOWN-RUNNER"] === "true";
  const summary = buildSummary(containerLogs(), { lockdown, manifest: readManifest() });

  maybeTeardown(lockdown);

  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + "\n");
  } else {
    console.log(summary);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  parseLine,
  collectDecisions,
  escapeCell,
  blockedSection,
  buildSummary,
  readManifest,
  teardown,
  maybeTeardown,
};
