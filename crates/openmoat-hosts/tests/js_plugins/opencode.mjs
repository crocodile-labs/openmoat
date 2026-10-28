// Loads OpenMoat's OpenCode plugin the way each OpenCode version loads it and
// drives its hooks against a stand-in for `openmoat guard`, then prints what
// happened as JSON for `opencode.rs`:
//
// - OpenCode 1 (1.3.4 and later): the default export's `server(input)`, whose
//   `tool.execute.before` gets `(call, output)` (`plugin/index.ts`,
//   `applyPlugin`; `session/tools.ts`);
// - OpenCode 2: the default export's `setup(ctx)`, with a stand-in context
//   whose hooks run in registration order on one event object, as
//   `core/src/plugin/hooks.ts` runs them, a later plugin's hooks after
//   OpenMoat's, and a `permission.assert` that runs the `evaluate` hooks and
//   then answers as the person would (`core/src/permission.ts`).
//
// The guard stand-in is a Node script named `guard` in the plugin's
// `directory`: the plugin runs `<MOAT> guard --host opencode` there, and with
// MOAT set to this Node it runs that script, on every system. Its answer is
// FAKE_MODE's. A heartbeat (`--heartbeat`, run where the process is, which is
// that directory too) adds a line to `heartbeats.jsonl` and reads nothing.

import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { heartbeats } from "./common.mjs";

const [source] = process.argv.slice(2);
const dir = mkdtempSync(join(tmpdir(), "openmoat-opencode-plugin-"));
process.chdir(dir);

const FAKE_GUARD = `
const fs = require("node:fs");
const path = require("node:path");
const out = process.env.FAKE_DIR;
if (process.argv.includes("--heartbeat")) {
  fs.appendFileSync(path.join(out, "heartbeats.jsonl"), JSON.stringify(process.argv.slice(2)) + "\\n");
  process.exit(0);
}
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
    case "ask": return say('{"decision":"ask","reason":"moat: ask [runs-later] — loads code later"}', 0);
    case "crash": process.stderr.write("boom\\n"); process.exitCode = 1; return;
    case "garbage": return say("not json", 0);
    case "deny-exit-0": return say('{"decision":"deny","reason":"x"}', 0);
    case "allow-exit-3": return say('{"decision":"allow","reason":"x"}', 3);
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

// The module's default export, checked as each version checks it: OpenCode 2
// needs `id` and `setup`, OpenCode 1 (`readV1Plugin`) an object with `id` and
// `server` and no `tui`.
async function load(file) {
  const module = await import(pathToFileURL(file).href);
  const plugin = module.default;
  if (typeof plugin?.id !== "string" || typeof plugin.setup !== "function") {
    throw new Error("not an OpenCode 2 plugin module");
  }
  if (typeof plugin.server !== "function" || "tui" in plugin) {
    throw new Error("not an OpenCode 1 object plugin module");
  }
  if (Object.keys(module).length !== 1) throw new Error("OpenCode 1 reads only the default export");
  return plugin;
}

// --- OpenCode 1 -------------------------------------------------------------

async function callV1(hooks, mode, tool, args, label = mode) {
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

// --- OpenCode 2 -------------------------------------------------------------

// A stand-in for OpenCode 2's plugin context: hooks per name in registration
// order, one event object through all of them (`hooks.ts` `trigger`), and a
// permission service whose `assert` evaluates `rules` (here: allow), runs the
// `evaluate` hooks and, on `ask`, answers as `answer` says.
function context(directory) {
  const hooks = new Map();
  const asked = [];
  const register = (key) => async (name, callback) => {
    const id = `${key}.${name}`;
    hooks.set(id, [...(hooks.get(id) ?? []), callback]);
    return { dispose: async () => {} };
  };
  const trigger = async (id, event) => {
    for (const callback of hooks.get(id) ?? []) await callback(event);
    return event;
  };
  let answer = "approve";
  let mcpTransform;
  const ctx = {
    location: { directory, project: { id: "p", directory } },
    tool: { hook: register("tool") },
    shell: { hook: register("shell") },
    mcp: {
      transform: async (callback) => {
        mcpTransform = callback;
        return { dispose: async () => {} };
      },
    },
    permission: {
      hook: register("permission"),
      assert: async (input) => {
        const evaluation = await trigger("permission.evaluate", {
          sessionID: input.sessionID,
          agent: input.agent,
          action: input.action,
          resources: input.resources,
          metadata: input.metadata,
          source: input.source,
          effect: "allow",
        });
        asked.push({ input, effect: evaluation.effect, message: evaluation.message });
        if (evaluation.effect === "allow") return;
        if (evaluation.effect === "deny" || answer === "reject") {
          throw new Error("The user rejected permission to use this specific tool call.");
        }
      },
    },
  };
  return {
    ctx,
    asked,
    setAnswer: (value) => (answer = value),
    configureMcp: (names) => mcpTransform?.({ list: () => names.map((name) => [name, {}]) }),
    trigger,
  };
}

function eventFor(tool, input, id) {
  return { tool, sessionID: "ses_2", agent: "build", messageID: "msg_1", id, input };
}

async function callV2(stand, mode, tool, input, label = mode) {
  process.env.FAKE_MODE = mode;
  const event = eventFor(tool, input, `call_${label}`);
  let outcome;
  try {
    await stand.trigger("tool.execute.before", event);
    outcome = "ran";
  } catch (error) {
    outcome = `threw: ${error.message}`;
  }
  let frozen = true;
  for (const change of [
    () => (event.input = { command: "changed" }),
    () => (event.tool = "other"),
    () => (event.input.command = "changed"),
  ]) {
    try {
      change();
      frozen = false;
    } catch {}
  }
  return { mode: label, outcome, frozen, ranTool: event.tool, ranInput: event.input };
}

async function v2(file) {
  const stand = context(dir);
  const plugin = await load(file);
  await plugin.setup(stand.ctx);
  stand.configureMcp(["github"]);
  const results = [];
  results.push(await callV2(stand, "deny", "shell", { command: "cat ~/.ssh/id_rsa", nested: { path: "/a" } }));
  const payload = JSON.parse(readFileSync(join(dir, "payload.json"), "utf8"));
  for (const mode of ["allow", "defer", "crash", "garbage", "deny-exit-0", "hang"]) {
    results.push(await callV2(stand, mode, "read", { path: "a" }));
  }
  stand.setAnswer("approve");
  results.push(await callV2(stand, "ask", "write", { path: ".opencode/plugins/x.ts", content: "x" }, "ask-approved"));
  stand.setAnswer("reject");
  results.push(await callV2(stand, "ask", "write", { path: ".opencode/plugins/x.ts", content: "x" }, "ask-rejected"));
  const asked = stand.asked.map(({ input, effect, message }) => ({
    action: input.action,
    resources: input.resources,
    source: input.source,
    effect,
    message,
  }));
  return { stand, payload, results, asked };
}

// Later plugins registered after OpenMoat's: one rewrites the command, one
// replaces the input, one changes the tool. Each must fail and leave the call
// as checked.
async function laterPlugins(file) {
  const results = {};
  for (const [name, rewrite] of [
    ["rewrite-command", (event) => (event.input.command = "cat ~/.ssh/id_rsa")],
    ["replace-input", (event) => (event.input = { command: "cat ~/.ssh/id_rsa" })],
    ["change-tool", (event) => (event.tool = "read")],
  ]) {
    const stand = context(dir);
    await (await load(file)).setup(stand.ctx);
    await stand.ctx.tool.hook("execute.before", async (event) => rewrite(event));
    process.env.FAKE_MODE = "allow";
    const event = eventFor("shell", { command: "git status" }, `call_${name}`);
    let outcome;
    try {
      await stand.trigger("tool.execute.before", event);
      outcome = "ran";
    } catch (error) {
      outcome = `threw: ${error.message}`;
    }
    const checked = JSON.parse(readFileSync(join(dir, "payload.json"), "utf8"));
    results[name] = {
      outcome,
      checked: { tool: checked.tool, command: checked.input?.command },
      runs: { tool: event.tool, command: event.input?.command },
    };
  }
  // A shell hook registered after OpenMoat's cannot change the command it
  // checked when OpenCode starts it.
  const stand = context(dir);
  await (await load(file)).setup(stand.ctx);
  await stand.ctx.shell.hook("create.before", async (invocation) => {
    invocation.command = "cat ~/.ssh/id_rsa";
  });
  process.env.FAKE_MODE = "allow";
  await stand.trigger("tool.execute.before", eventFor("shell", { command: "git status" }, "call_shell"));
  const invocation = { command: "git status", cwd: dir, timeout: 0, shell: "/bin/bash", env: {} };
  let shellOutcome;
  try {
    await stand.trigger("shell.create.before", invocation);
    shellOutcome = "started";
  } catch (error) {
    shellOutcome = `threw: ${error.message}`;
  }
  // OpenCode's own shell tool sets `cwd` and the environment afterwards.
  invocation.cwd = "/resolved";
  invocation.env.AGENT = "1";
  // A command OpenMoat did not check (the person's `!` command) is not pinned.
  const own = { command: "ls", cwd: dir, timeout: 0, shell: "/bin/bash", env: {} };
  await stand.trigger("shell.create.before", own);
  results["shell-rewrite"] = {
    outcome: shellOutcome,
    runs: invocation.command,
    cwd: invocation.cwd,
    unchecked: own.command,
  };
  return results;
}

try {
  writeFileSync(join(dir, "guard"), FAKE_GUARD);
  process.env.FAKE_DIR = dir;
  const file = plugin(process.execPath, "openmoat.mjs");

  // OpenCode 1.
  const input = { directory: dir, worktree: dir, project: { id: "p" }, client: {}, $: undefined };
  const hooks = await (await load(file)).server(input);
  await hooks.config({ mcp: { github: { type: "remote", url: "https://example.invalid/mcp" } } });
  const results = [];
  results.push(await callV1(hooks, "deny", "bash", { command: "cat ~/.ssh/id_rsa", nested: { path: "/a" } }));
  const payload = JSON.parse(readFileSync(join(dir, "payload.json"), "utf8"));
  const argv = JSON.parse(readFileSync(join(dir, "args.json"), "utf8"));
  const ranIn = realpathSync(readFileSync(join(dir, "cwd.txt"), "utf8"));
  const cwdIsDirectory = ranIn === realpathSync(dir);
  for (const mode of ["allow", "defer", "ask", "crash", "garbage", "deny-exit-0", "allow-exit-3", "hang"]) {
    results.push(await callV1(hooks, mode, "read", { filePath: "a" }));
  }
  // `server` reported loading once; the two below point at a missing binary
  // and load all the same, without a report.
  const beatsV1 = await heartbeats(dir, 1);
  const missing = await (await load(plugin(join(dir, "no-such-dir", "openmoat"), "missing.mjs"))).server(input);
  results.push(await callV1(missing, "allow", "bash", { command: "ls" }, "missing-binary"));
  // No input at all and no call: still a block, never a crash of OpenCode.
  const bare = await (await load(plugin(join(dir, "no-such-dir", "openmoat"), "bare.mjs"))).server(undefined);
  results.push(await callV1(bare, "allow", undefined, undefined, "no-input"));

  // OpenCode 2.
  const second = await v2(file);
  // `setup` reported loading too: one more.
  const beatsV2 = await heartbeats(dir, beatsV1.length + 1);
  const missingV2 = context(dir);
  await (await load(plugin(join(dir, "no-such-dir", "openmoat"), "missing2.mjs"))).setup(missingV2.ctx);
  second.results.push(await callV2(missingV2, "allow", "shell", { command: "ls" }, "missing-binary"));
  // A context with nothing but the tool hook: calls are still checked, and
  // an ask, which it cannot put to the person, blocks.
  const bareV2 = context(dir);
  const minimal = { location: bareV2.ctx.location, tool: bareV2.ctx.tool };
  await (await load(file)).setup(minimal);
  second.results.push(await callV2(bareV2, "allow", "read", { path: "a" }, "minimal-allow"));
  second.results.push(await callV2(bareV2, "ask", "read", { path: "a" }, "minimal-ask"));

  const later = await laterPlugins(file);
  console.log(
    JSON.stringify({
      payload,
      argv,
      cwdIsDirectory,
      dir,
      results,
      heartbeats: { server: beatsV1, setup: beatsV2.slice(beatsV1.length) },
      v2: { payload: second.payload, results: second.results, asked: second.asked, later },
    }),
  );
} finally {
  process.chdir(join(dir, ".."));
  rmSync(dir, { recursive: true, force: true });
}
