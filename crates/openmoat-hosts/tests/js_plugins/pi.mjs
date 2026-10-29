// Loads OpenMoat's pi extension the way pi does (its default export, called
// with the extension API) and drives `tool_call` through a stand-in for pi's
// runner against the stand-in for `openmoat guard` (`common.mjs`), then
// prints what happened as JSON for `pi.rs`.
//
// The runner does what pi does (badlogic/pi-mono, packages/coding-agent):
// handlers run in the order their extensions loaded, each with the same
// event, and the first result that blocks ends the run
// (`emitToolCall`, `src/core/extensions/runner.ts` 1249–1267); a handler that
// throws blocks the call (`_beforeToolCall`, `src/core/agent-session.ts`
// 667–680).

import { rmSync } from "node:fs";
import { join } from "node:path";

import { heartbeats, lastCall, load, plugin, scratch } from "./common.mjs";

const [source] = process.argv.slice(2);
const dir = scratch("openmoat-pi-extension-");

async function extension(file) {
  const factory = (await load(file)).default;
  const handlers = [];
  factory({ on: (event, handler) => event === "tool_call" && handlers.push(handler) });
  return handlers;
}

// What the person answers in pi's dialog: FAKE_CONFIRM, and what was asked.
function context({ hasUI = true, signal } = {}) {
  const asked = [];
  return {
    asked,
    ctx: {
      cwd: dir,
      hasUI,
      signal,
      sessionManager: { getSessionId: () => "ses-1" },
      ui: {
        confirm: async (title, message) => {
          asked.push({ title, message });
          return process.env.FAKE_CONFIRM === "yes";
        },
      },
    },
  };
}

async function call(handlers, mode, label = mode, options = {}) {
  process.env.FAKE_MODE = mode;
  process.env.FAKE_CONFIRM = options.confirm ?? "no";
  const { asked, ctx } = context(options);
  const event = { type: "tool_call", toolName: "bash", toolCallId: "call-1", input: { command: "ls" } };
  let outcome;
  try {
    let result;
    for (const handler of handlers) {
      result = (await handler(event, ctx)) ?? result;
      if (result?.block) break;
    }
    outcome = result?.block ? `blocked: ${result.reason}` : "ran";
  } catch (error) {
    outcome = `threw: ${error.message}`;
  }
  return { mode: label, outcome, asked };
}

try {
  const handlers = await extension(plugin(source, dir, process.execPath, "openmoat.js"));
  const beats = await heartbeats(dir, 1);

  const results = [];
  results.push(await call(handlers, "deny"));
  const { payload, argv, cwd } = lastCall(dir);
  for (const mode of ["allow", "defer", "crash", "garbage", "deny-exit-0", "allow-exit-3", "hang"]) {
    results.push(await call(handlers, mode));
  }
  results.push(await call(handlers, "ask", "ask-approved", { confirm: "yes" }));
  results.push(await call(handlers, "ask", "ask-declined", { confirm: "no" }));
  results.push(await call(handlers, "ask", "ask-no-screen", { hasUI: false, confirm: "yes" }));
  const cancelled = new AbortController();
  setTimeout(() => cancelled.abort(), 200);
  results.push(await call(handlers, "hang", "cancelled", { signal: cancelled.signal }));

  const missing = await extension(plugin(source, dir, join(dir, "no-such-dir", "openmoat"), "missing.js"));
  results.push(await call(missing, "allow", "missing-binary"));

  console.log(JSON.stringify({ heartbeats: beats, payload, argv, cwd, dir, results }));
} finally {
  process.chdir(join(dir, ".."));
  // Windows keeps a folder busy while a stand-in guard the plugin just killed
  // exits; Node retries EBUSY, EPERM and ENOTEMPTY with these.
  rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
