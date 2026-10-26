// Loads OpenMoat's OpenCode plugin the way OpenCode 1 loads a legacy plugin
// module (its one export, a function called with the plugin input) and
// drives its hooks against a stand-in for `openmoat guard`, then prints what
// happened as JSON for `tests/opencode_plugin.rs`.
//
// The stand-in is a Node script named `guard` in the plugin's `directory`:
// the plugin runs `<MOAT> guard --host opencode` there, and with MOAT set to
// this Node it runs that script, on every system. Its answer is FAKE_MODE's.

import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [source] = process.argv.slice(2);
const dir = mkdtempSync(join(tmpdir(), "openmoat-opencode-plugin-"));

const FAKE_GUARD = `
const fs = require("node:fs");
const path = require("node:path");
const out = process.env.FAKE_DIR;
let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  fs.writeFileSync(path.join(out, "payload.json"), input);
  fs.writeFileSync(path.join(out, "args.json"), JSON.stringify(process.argv.slice(2)));
  fs.writeFileSync(path.join(out, "cwd.txt"), process.cwd());
  const say = (text, code) => { process.stdout.write(text); process.exitCode = code; };
  switch (process.env.FAKE_MODE) {
    case "deny": return say('{"decision":"deny","reason":"moat: deny [secrets-paths] — secret material"}', 2);
    case "allow": return say('{"decision":"allow","reason":"moat: allow [dev-shell]"}', 0);
    case "defer": return say("", 0);
    case "ask": return say('{"decision":"ask","reason":"moat: ask"}', 0);
    case "crash": process.stderr.write("boom\\n"); process.exitCode = 1; return;
    case "garbage": return say("not json", 0);
    case "deny-exit-0": return say('{"decision":"deny","reason":"x"}', 0);
    case "hang": setTimeout(() => {}, 10000); return;
  }
});
`;

function plugin(moat, name) {
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

async function load(file, input) {
  const module = await import(pathToFileURL(file).href);
  const exports = Object.values(module);
  if (exports.length !== 1 || typeof exports[0] !== "function") {
    throw new Error("not a legacy OpenCode plugin module");
  }
  return exports[0](input);
}

async function call(hooks, mode, tool, args, label = mode) {
  process.env.FAKE_MODE = mode;
  const output = { args };
  let outcome;
  try {
    await hooks["tool.execute.before"]({ tool, sessionID: "ses_1", callID: "call_1" }, output);
    outcome = "ran";
  } catch (error) {
    outcome = `threw: ${error.message}`;
  }
  let frozen = true;
  try {
    output.args.command = "changed";
    frozen = false;
  } catch {}
  try {
    if (output.args.nested) {
      output.args.nested.path = "/elsewhere";
      frozen = false;
    }
  } catch {}
  return { mode: label, outcome, frozen };
}

try {
  writeFileSync(join(dir, "guard"), FAKE_GUARD);
  process.env.FAKE_DIR = dir;
  const input = { directory: dir, worktree: dir, project: { id: "p" }, client: {}, $: undefined };
  const hooks = await load(plugin(process.execPath, "openmoat.mjs"), input);
  await hooks.config({ mcp: { github: { type: "remote", url: "https://example.invalid/mcp" } } });

  const results = [];
  results.push(await call(hooks, "deny", "bash", { command: "cat ~/.ssh/id_rsa", nested: { path: "/a" } }));
  const payload = JSON.parse(readFileSync(join(dir, "payload.json"), "utf8"));
  const argv = JSON.parse(readFileSync(join(dir, "args.json"), "utf8"));
  const ranIn = realpathSync(readFileSync(join(dir, "cwd.txt"), "utf8"));
  const cwdIsDirectory = ranIn === realpathSync(dir);
  for (const mode of ["allow", "defer", "ask", "crash", "garbage", "deny-exit-0", "hang"]) {
    results.push(await call(hooks, mode, "read", { filePath: "a" }));
  }

  const missing = await load(plugin(join(dir, "no-such-dir", "openmoat"), "missing.mjs"), input);
  results.push(await call(missing, "allow", "bash", { command: "ls" }, "missing-binary"));
  // No input at all and no call: still a block, never a crash of OpenCode.
  const bare = await load(plugin(join(dir, "no-such-dir", "openmoat"), "bare.mjs"), undefined);
  results.push(await call(bare, "allow", undefined, undefined, "no-input"));

  console.log(JSON.stringify({ payload, argv, cwdIsDirectory, dir, results }));
} finally {
  rmSync(dir, { recursive: true, force: true });
}
