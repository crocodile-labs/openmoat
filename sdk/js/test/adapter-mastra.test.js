// The Mastra adapter, run the way @mastra/core 1.83.0 wraps a tool with an
// agent's hooks (`Agent.wrapToolWithHooks`): `beforeToolCall` inside the
// tool's execute; `proceed: false` returns `output` instead of running it.
import { test } from "node:test";
import assert from "node:assert/strict";

import { describe } from "../src/adapters/guard.js";
import { openmoatHooks } from "../src/adapters/mastra.js";
import { scratchHome } from "./adapter-home.js";

const h = scratchHome();
test.after(() => h.done());

/** A stub of Mastra's hook wrapper. */
function wrap(toolName, tool, hooks) {
  return async (input, context) => {
    const before = await hooks.beforeToolCall?.({ toolName, input, context, metadata: {} });
    if (before?.proceed === false) return before.output;
    return tool.execute(input, context);
  };
}

test("an allowed call runs; a denied one returns OpenMoat's message as the result", async () => {
  const ran = [];
  const hooks = openmoatHooks({ ...h.options, tools: { shell: describe.shell() } });
  const run = wrap("shell", { execute: async ({ command }) => (ran.push(command), "ok") }, hooks);
  assert.equal(await run({ command: "ls" }, {}), "ok");
  const denied = await run({ command: `cat ${h.key}` }, {});
  assert.match(denied.error, /OpenMoat blocked this tool call \(secrets-paths\)/);
  assert.deepEqual(denied.openmoat, { verdict: "deny", rules: ["secrets-paths"] });
  assert.deepEqual(ran, ["ls"]);
});

test("an error deciding is a refusal, not a pass", async () => {
  let ran = false;
  const hooks = openmoatHooks({ ...h.options, tools: { shell: describe.shell() } });
  const run = wrap("shell", { execute: async () => (ran = true) }, hooks);
  const r = await run({ cmd: "ls" }, {});
  assert.match(r.error, /could not decide/);
  assert.equal(ran, false);
});
