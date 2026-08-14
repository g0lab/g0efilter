// Unit tests for the assertions report-check.js makes against a live run, so a check
// that can no longer fail does not sit green in the workflow.
"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");

const { problemsWith } = require("./report-check.js");

const GOOD = [
  "## g0efilter egress report",
  "",
  "| Outcome | Unique hosts | Decisions |",
  "|---|---:|---:|",
  "| Blocked | 3 | 3 |",
  "| Audited | 0 | 0 |",
  "| Allowed | 1 | 1 |",
  "",
  "### Blocked (1)",
  "",
  "| Domain / Host | Component | Destination | Count |",
  "|---|---|---|---:|",
  "| - | nflog | `95.111.222.228:443` | 1 |",
  "",
  "<details>",
  "<summary>2 destinations (2 decisions) matched notification-ignore</summary>",
  "",
  "| `example.com` | https | `93.184.215.14:443` | 1 |",
  "| - | nflog | `224.0.0.22` | 1 |",
  "",
  "</details>",
  "",
  "### Allowed",
  "",
  "<details>",
  "<summary>1 host reached</summary>",
  "",
  "| `api.github.com` | https | 1 |",
  "",
  "</details>",
  "",
].join("\n");

test("a correct report raises no problems", () => {
  assert.deepEqual(problemsWith(GOOD), []);
});

// The rule silently ceasing to apply is the regression this job exists to catch: the
// row moves out of the collapsible and back into the table.
test("it catches an ignored block left in the blocked table", () => {
  const leaked = GOOD.replace("| `example.com` | https | `93.184.215.14:443` | 1 |\n", "").replace(
    "| - | nflog | `95.111.222.228:443` | 1 |",
    "| - | nflog | `95.111.222.228:443` | 1 |\n| `example.com` | https | `93.184.215.14:443` | 1 |",
  );

  assert.deepEqual(problemsWith(leaked), [
    "the ignored block was not folded into the collapsible",
    "the ignored block is still in the blocked table",
  ]);
});

test("it catches a report that parsed nothing", () => {
  assert.deepEqual(problemsWith("## g0efilter egress report\n\nNo g0efilter logs found.\n"), [
    "the allowed host is missing from the report",
    "the overview stopped counting the ignored block",
    "the ignored block was not folded into the collapsible",
  ]);
});

test("it catches an overview that stopped counting the folded blocks", () => {
  assert.deepEqual(problemsWith(GOOD.replace("| Blocked | 3 | 3 |", "| Blocked | 0 | 0 |")), [
    "the overview stopped counting the ignored block",
  ]);
});

test("it catches a missing allowed host", () => {
  assert.deepEqual(problemsWith(GOOD.replace("`api.github.com`", "`other.test`")), [
    "the allowed host is missing from the report",
  ]);
});
