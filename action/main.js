// Maps the action inputs to plain env vars and runs setup.sh.
// Dependency-free on purpose: no npm install or dist build step.
"use strict";

const { spawnSync } = require("node:child_process");
const path = require("node:path");

const input = (name, fallback = "") => {
  const v = process.env[`INPUT_${name.toUpperCase()}`];
  return v === undefined || v === "" ? fallback : v;
};

const res = spawnSync("bash", [path.join(__dirname, "setup.sh")], {
  stdio: "inherit",
  env: {
    ...process.env,
    ALLOWED_DOMAINS: input("allowed-domains"),
    ALLOWED_IPS: input("allowed-ips"),
    EGRESS_POLICY: input("egress-policy", "block"),
    FILTER_MODE: input("mode", "https"),
    LOG_LEVEL: input("log-level", "INFO"),
    G0EFILTER_IMAGE: input("image"),
    LOCKDOWN_RUNNER: input("lockdown-runner", "false"),
  },
});

process.exit(res.status === null ? 1 : res.status);
