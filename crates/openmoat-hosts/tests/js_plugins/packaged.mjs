// Loads the extension of pi's package (`plugins/pi/openmoat.js`, ADR-095) the
// way pi does and drives `tool_call` twice: with a stand-in `openmoat` on the
// search path, which records its arguments and denies, and with none there.
// Prints what happened as JSON for `packaged.rs`. The stand-in is a script
// run through its `#!` line, so this runs on Unix only.

import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { heartbeats, load } from "./common.mjs";

const [source] = process.argv.slice(2);
const dir = mkdtempSync(join(tmpdir(), "openmoat-pi-package-"));
const bin = join(dir, "found");
const empty = join(dir, "empty");
mkdirSync(bin);
mkdirSync(empty);
process.env.FAKE_DIR = dir;

const fake = `#!${process.execPath}
const fs = require("node:fs");
const argv = process.argv.slice(2);
if (argv.includes("--heartbeat")) {
  fs.appendFileSync(${JSON.stringify(join(dir, "heartbeats.jsonl"))}, JSON.stringify(argv) + "\\n");
  process.exit(0);
}
fs.writeFileSync(${JSON.stringify(join(dir, "args.json"))}, JSON.stringify(argv));
let input = "";
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  process.stdout.write('{"decision":"deny","reason":"moat: deny [x]"}');
  process.exitCode = 2;
});
`;
writeFileSync(join(bin, "openmoat"), fake);
chmodSync(join(bin, "openmoat"), 0o755);

async function handlers() {
  const factory = (await load(source)).default;
  const found = [];
  factory({ on: (event, handler) => event === "tool_call" && found.push(handler) });
  return found;
}

async function call(list) {
  const ctx = { cwd: dir, hasUI: false, ui: { confirm: async () => false } };
  const event = { type: "tool_call", toolName: "bash", toolCallId: "c1", input: { command: "ls" } };
  const result = await list[0](event, ctx);
  return result?.block ? `blocked: ${result.reason}` : "ran";
}

try {
  process.env.PATH = bin;
  const list = await handlers();
  const beats = await heartbeats(dir, 1);
  const denied = await call(list);
  const argv = JSON.parse(readFileSync(join(dir, "args.json"), "utf8"));
  process.env.PATH = empty;
  const missing = await call(list);
  console.log(JSON.stringify({ heartbeats: beats, argv, denied, missing }));
} finally {
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  } catch (error) {
    console.error(`left ${dir}: ${error.code ?? error}`);
  }
}
