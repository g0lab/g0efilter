// Post step: summarise g0efilter decisions from the container logs into the
// job summary. Dependency-free on purpose: no npm install or dist build step.
//
// g0efilter logs in zerolog console format, e.g.:
//   2026-07-05T00:25:09Z WRN https.blocked action=BLOCKED component=https https=example.com dst=1.2.3.4:443 ...
"use strict";

const { execSync, execFileSync } = require("node:child_process");
const fs = require("node:fs");

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

function collectDecisions(raw) {
  const decisions = new Map();
  let allowed = 0;

  for (const rawLine of raw.split("\n")) {
    const entry = parseLine(rawLine);
    if (!entry) continue;

    if (entry.action === "ALLOWED") {
      allowed++;
      continue;
    }

    const key = [entry.action, entry.component, entry.host, entry.dest].join("|");
    const seen = decisions.get(key);

    if (seen) {
      seen.count++;
    } else {
      decisions.set(key, { ...entry, count: 1 });
    }
  }

  return { decisions: [...decisions.values()], allowed };
}

function escapeCell(v) {
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/\|/g, "&#124;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/[\r\n]+/g, " ");
}

function buildSummary(raw) {
  let md = "## g0efilter egress report\n\n";

  if (!raw.trim()) {
    return md + "No g0efilter logs found - the filter may have failed to start.\n";
  }

  const { decisions, allowed } = collectDecisions(raw);
  if (decisions.length === 0) {
    return md + `No blocked or audited connections (${allowed} allowed decisions logged).\n`;
  }

  const policy = process.env["INPUT_EGRESS-POLICY"] || "block";
  md += `Egress policy: \`${policy}\` - ${allowed} allowed decisions logged.\n\n`;
  md += "| Action | Component | Domain / Host | Destination | Count |\n";
  md += "|---|---|---|---|---|\n";

  decisions.sort((a, b) => b.count - a.count);
  for (const d of decisions) {
    const icon = d.action === "BLOCKED" ? "🚫 BLOCKED" : "⚠️ AUDIT";
    md += `| ${icon} | ${escapeCell(d.component)} | ${escapeCell(d.host)} | ${escapeCell(d.dest)} | ${d.count} |\n`;
  }

  return md;
}

// Rules live in the host netns; a leftover container or ruleset would brick the
// runner's DNS/egress after the job. Best-effort - never fail the post step.
function teardown() {
  try {
    execFileSync("docker", ["rm", "-f", "g0efilter"], { stdio: "ignore" });
  } catch {}

  for (const table of [
    ["ip", "g0efilter_v4"],
    ["ip", "g0efilter_nat_v4"],
    ["ip6", "g0efilter_v6"],
    ["ip6", "g0efilter_nat_v6"],
  ]) {
    try {
      execFileSync("sudo", ["nft", "delete", "table", ...table], { stdio: "ignore" });
    } catch {} // table absent, or no sudo on self-hosted runners
  }
}

function main() {
  const summary = buildSummary(containerLogs());

  teardown();

  if (process.env.GITHUB_STEP_SUMMARY) {
    fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + "\n");
  } else {
    console.log(summary);
  }
}

if (require.main === module) {
  main();
}

module.exports = { parseLine, collectDecisions, escapeCell, buildSummary };
