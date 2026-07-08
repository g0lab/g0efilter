const { spawnSync } = require("node:child_process");

const target = "https://example.com";

const result = spawnSync("curl", [
  "--fail",
  "--silent",
  "--show-error",
  "--connect-timeout",
  "10",
  "--max-time",
  "20",
  target,
  "-o",
  "/dev/null",
]);

if (result.status === 0) {
  console.error(`post step reached ${target}; a later action's post hook bypassed g0efilter`);
  process.exit(1);
}

console.log(`OK: post step to ${target} was filtered`);
