const { spawnSync } = require("node:child_process");

function curlOK(target, retry) {
  const args = [
    "--fail",
    "--silent",
    "--show-error",
    "--connect-timeout",
    "10",
    "--max-time",
    "20",
  ];

  if (retry) {
    args.push("--retry", "2", "--retry-delay", "2", "--retry-all-errors");
  }

  args.push(target, "-o", "/dev/null");

  return spawnSync("curl", args).status === 0;
}

const failures = [];

if (curlOK("https://api.github.com", true)) {
  console.log("OK: api.github.com reachable");
} else {
  failures.push("expected api.github.com to be reachable");
}

if (curlOK("https://example.com", false)) {
  failures.push("example.com should have been blocked");
} else {
  console.log("OK: example.com blocked");
}

if (process.env.INPUT_LOCKDOWN === "true") {
  // A hung probe means the command didn't succeed; timeout counts as denial.
  const probeOpts = { timeout: 15000 };

  // A later step must not be able to escalate past the filter.
  if (spawnSync("sudo", ["-n", "true"], probeOpts).status === 0) {
    failures.push("sudo should be denied under lockdown");
  } else {
    console.log("OK: sudo denied");
  }

  // Nor stop the filter container via the Docker socket.
  if (spawnSync("docker", ["stop", "g0efilter"], probeOpts).status === 0) {
    failures.push("docker access should be denied under lockdown (stopped g0efilter)");
  } else {
    console.log("OK: docker access denied");
  }
}

if (failures.length > 0) {
  for (const f of failures) {
    console.error(f);
  }
  process.exit(1);
}
