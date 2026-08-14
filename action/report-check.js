// Asserts the job summary that post.js renders from a live agent's logs. Run by the
// egress-report job in .github/workflows/action-test.yaml, with the g0efilter container
// still up. The unit tests parse hand-written log lines; this renders the real agent's
// output, so a drift in the log format cannot pass unnoticed.
//
// Not named *.test.js: it needs a running container, so scripts/test-action.sh must not
// pick it up as a unit test.
"use strict";

const { execSync } = require("node:child_process");
const path = require("node:path");

// Must match the notification-ignore input the workflow starts g0efilter with.
process.env["INPUT_NOTIFICATION-IGNORE"] = "local\nexample.com";

const { buildSummary } = require(path.resolve(__dirname, "post.js"));

function containerLogs() {
  return execSync("docker logs g0efilter 2>&1", {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
}

function problemsWith(md) {
  const blocked = (md.split("### Blocked")[1] || "").split("\n### ")[0];
  const [table, folded = ""] = blocked.split("<details>");

  const checks = [
    [md.includes("`api.github.com`"), "the allowed host is missing from the report"],
    [/\| Blocked \| [1-9]/.test(md), "the overview stopped counting the ignored block"],
    [folded.includes("example.com"), "the ignored block was not folded into the collapsible"],
    [!table.includes("example.com"), "the ignored block is still in the blocked table"],
  ];

  return checks.filter(([ok]) => !ok).map(([, problem]) => problem);
}

function main() {
  const md = buildSummary(containerLogs());
  const problems = problemsWith(md);

  console.log(md);

  if (problems.length > 0) {
    for (const problem of problems) console.error(`FAIL: ${problem}`);
    process.exit(1);
  }

  console.log("OK: the report folded the ignored block and kept the rest");
}

if (require.main === module) {
  main();
}

module.exports = { problemsWith };
