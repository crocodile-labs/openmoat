// What the plugin harnesses share: a stand-in for `openmoat guard`, the
// plugin source made to run it, and a wait for the heartbeat.
//
// The stand-in is a Node script named `guard` in a scratch directory: a plugin
// runs `<MOAT> guard …` in that directory, and with MOAT set to this Node it
// runs that script, on every system. Each tool call's payload, arguments and
// working directory are written next to it; a heartbeat (`--heartbeat`) adds
// a line to `heartbeats.jsonl` and reads nothing. The answer is FAKE_MODE's.

import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const FAKE_GUARD = `
const fs = require("node:fs");
const path = require("node:path");
const out = process.env.FAKE_DIR;
const argv = process.argv.slice(2);
if (argv.includes("--heartbeat")) {
  fs.appendFileSync(path.join(out, "heartbeats.jsonl"), JSON.stringify(argv) + "\\n");
  process.exit(0);
}
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  fs.writeFileSync(path.join(out, "payload.json"), input);
  fs.writeFileSync(path.join(out, "args.json"), JSON.stringify(argv));
  fs.writeFileSync(path.join(out, "cwd.txt"), process.cwd());
  fs.appendFileSync(path.join(out, "calls.jsonl"), input + "\\n");
  const say = (text, code) => { process.stdout.write(text); process.exitCode = code; };
  const deny = '{"decision":"deny","reason":"moat: deny [secrets-paths] — secret material"}';
  switch (process.env.FAKE_MODE) {
    case "deny": return say(deny, 2);
    case "allow": return say('{"decision":"allow","reason":"moat: allow [dev-shell]"}', 0);
    case "defer": return say("", 0);
    case "ask": return say('{"decision":"ask","reason":"moat: ask [runs-later]"}', 0);
    case "crash": process.stderr.write("boom\\n"); process.exitCode = 1; return;
    case "garbage": return say("not json", 0);
    case "deny-exit-0": return say('{"decision":"deny","reason":"x"}', 0);
    case "allow-exit-3": return say('{"decision":"allow","reason":"x"}', 3);
    case "hang": setTimeout(() => {}, 10000); return;
    // The policy in miniature: a call that names the SSH key is denied.
    case "policy": return JSON.stringify(JSON.parse(input)).includes("id_rsa") ? say(deny, 2) : say("", 0);
  }
});
`;

/** A scratch directory holding the stand-in, which becomes the working directory. */
export function scratch(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  writeFileSync(join(dir, "guard"), FAKE_GUARD);
  process.env.FAKE_DIR = dir;
  // A heartbeat runs in the process's directory, so the stand-in is found.
  process.chdir(dir);
  return dir;
}

/**
 * The plugin at `source` written to `dir/name` running `moat`, with the guard's
 * timeout cut to one second. Fails when the lines it replaces are not there.
 */
export function plugin(source, dir, moat, name) {
  const original = readFileSync(source, "utf8");
  for (const line of ["const MOAT = __MOAT_BINARY__;", "const GUARD_TIMEOUT_MS = 45_000;"]) {
    if (!original.includes(line)) throw new Error(`the plugin has no \`${line}\`; update the harness`);
  }
  const text = original
    .replace("const MOAT = __MOAT_BINARY__;", `const MOAT = ${JSON.stringify(moat)};`)
    .replace("const GUARD_TIMEOUT_MS = 45_000;", "const GUARD_TIMEOUT_MS = 1_000;");
  const file = join(dir, name);
  writeFileSync(file, text);
  return file;
}

/** The module at `file`. */
export function load(file) {
  return import(pathToFileURL(file).href);
}

/** What the stand-in last received: the payload, its arguments, where it ran. */
export function lastCall(dir) {
  return {
    payload: JSON.parse(readFileSync(join(dir, "payload.json"), "utf8")),
    argv: JSON.parse(readFileSync(join(dir, "args.json"), "utf8")),
    cwd: readFileSync(join(dir, "cwd.txt"), "utf8"),
  };
}

/** Every payload the stand-in received, oldest first. */
export function calls(dir) {
  const file = join(dir, "calls.jsonl");
  if (!existsSync(file)) return [];
  return readFileSync(file, "utf8")
    .split("\n")
    .filter((line) => line !== "")
    .map((line) => JSON.parse(line));
}

/** Forget the calls received so far. */
export function forgetCalls(dir) {
  writeFileSync(join(dir, "calls.jsonl"), "");
}

/**
 * The heartbeats the stand-in received, after waiting up to `ms` for at least
 * `atLeast` of them: a plugin starts its heartbeat and does not wait for it.
 */
export async function heartbeats(dir, atLeast, ms = 5000) {
  const file = join(dir, "heartbeats.jsonl");
  const read = () =>
    existsSync(file)
      ? readFileSync(file, "utf8")
          .split("\n")
          .filter((line) => line !== "")
          .map((line) => JSON.parse(line))
      : [];
  const until = Date.now() + ms;
  while (read().length < atLeast && Date.now() < until) {
    await new Promise((done) => setTimeout(done, 25));
  }
  return read();
}
