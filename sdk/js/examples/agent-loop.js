// An agent loop that checks every tool call with OpenMoat before it runs it.
//
// The "model" is a script of tool calls, so the example runs without a model
// or a network; replace `script` with your model's tool-use output. The tools
// are real: a POSIX shell, file reads and writes, and fetch. Each runs only
// after OpenMoat decided it may, and runs exactly the action decided.
//
//   node examples/agent-loop.js
//
// The rules the loop keeps (docs/SDK.md):
// - deny: the call does not run; the model is told why. No one is asked.
// - ask: the call runs only if a person approves this exact call.
// - defer: this product has no permission flow of its own, so it asks too.
// - allow: the call runs.
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

import { load, Session } from "../src/index.js";

/** A tool call as a model sends it, to the action OpenMoat decides. */
function actionOf(call) {
  switch (call.name) {
    case "shell":
      return { type: "shell", command: call.input.command };
    case "read_file":
      return { type: "fs_read", path: call.input.path };
    case "write_file":
      return { type: "fs_write", path: call.input.path };
    case "fetch":
      return { type: "fetch", url: call.input.url };
    default:
      // A tool OpenMoat has no shape for is still decided, never skipped.
      return { type: "unknown_tool", host: "agent-loop-example", tool: call.name };
  }
}

/** `path` through the real location of its deepest existing ancestor. */
function resolved(path) {
  const rest = [];
  let existing = path;
  while (!existsSync(existing)) {
    rest.unshift(basename(existing));
    const parent = dirname(existing);
    if (parent === existing) return null;
    existing = parent;
  }
  const real = join(realpathSync(existing), ...rest);
  return real === path ? null : real;
}

/** Run the decided action. `decision.action` is the frozen copy that was decided. */
async function run(decision, call, { home, project }) {
  const action = decision.action;
  switch (action.type) {
    case "shell": {
      // The shell sees the same home and directory the decision was made for.
      const r = spawnSync("/bin/sh", ["-c", action.command], {
        cwd: project,
        env: { ...process.env, HOME: home },
        encoding: "utf8",
      });
      return r.stdout + r.stderr;
    }
    case "fs_read":
      return readFileSync(action.path, "utf8");
    case "fs_write":
      writeFileSync(action.path, call.input.contents ?? "");
      return `wrote ${action.path}`;
    case "fetch":
      return await (await fetch(action.url)).text();
    default:
      return `no tool ${call.name}`;
  }
}

/**
 * An agent whose every tool call goes through `engine` first.
 * @param {{openmoat: import("../src/index.js").OpenMoat, home: string, project: string,
 *   approve: (call: object, reason: string) => Promise<boolean> | boolean}} options
 */
export function createAgent({ openmoat, home, project, approve }) {
  const engine = openmoat.compile({
    policy: openmoat.defaultPolicy,
    context: {
      home,
      cwd: project,
      project,
      real_home: realpathSync(home),
      real_project: realpathSync(project),
      case_insensitive_paths: process.platform === "darwin" || process.platform === "win32",
    },
  });
  const session = new Session();
  return {
    engine,
    /** Decide one call and run it only when the decision lets it. */
    async step(call) {
      const action = actionOf(call);
      const links = {};
      for (const path of engine.paths(action)) {
        const real = resolved(path);
        if (real) links[path] = real;
      }
      const facts = { links };
      const decision = engine.decide(action, { facts, session });
      let mayRun = decision.verdict === "allow";
      if (decision.verdict === "ask" || decision.verdict === "defer") {
        mayRun = await approve(call, decision.reason);
      }
      if (!mayRun) {
        return { ran: false, verdict: decision.verdict, reason: decision.reason };
      }
      const output = await run(decision, call, { home, project });
      session.record(engine, decision.action, facts);
      return { ran: true, verdict: decision.verdict, output };
    },
  };
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "openmoat-agent-loop-"));
  const home = join(dir, "home");
  const project = join(home, "app");
  mkdirSync(join(home, ".ssh"), { recursive: true });
  mkdirSync(project, { recursive: true });
  writeFileSync(join(home, ".ssh", "id_ed25519"), "not a real key\n");
  const agent = createAgent({
    openmoat: await load(),
    home,
    project,
    approve: () => false, // no person at this terminal: every ask is refused
  });
  const script = [
    { name: "shell", input: { command: "echo hello > greeting.txt && cat greeting.txt" } },
    { name: "shell", input: { command: "cat ~/.ssh/id_ed25519" } },
    { name: "write_file", input: { path: join(project, "NOTES.md"), contents: "checked\n" } },
    { name: "fetch", input: { url: "https://example.invalid/" } },
  ];
  for (const call of script) {
    console.log(JSON.stringify(call), "->", JSON.stringify(await agent.step(call)));
  }
  agent.engine.free();
  rmSync(dir, { recursive: true, force: true });
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
