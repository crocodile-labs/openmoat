// The LangChain.js adapter, run the way langchain 1.6.6's tool node runs a
// `wrapToolCall` middleware (agents/nodes/ToolNode.js): the base handler
// invokes `request.tool` when set, else the registered tool, and wraps a
// plain output in a ToolMessage; a middleware's throw ends the run.
import { test } from "node:test";
import assert from "node:assert/strict";

import { describe } from "../src/adapters/guard.js";
import { openmoatMiddleware } from "../src/adapters/langchain.js";
import { scratchHome } from "./adapter-home.js";

const h = scratchHome();
test.after(() => h.done());

/** A stub tool node with one registered tool and the middleware. */
function toolNode(registered, middleware) {
  const baseHandler = async (request) => {
    const tool = request.tool ?? registered;
    const output = await tool.invoke({ ...request.toolCall, type: "tool_call" });
    return { type: "tool", tool_call_id: request.toolCall.id, content: output };
  };
  return (toolCall) => middleware.wrapToolCall({ toolCall, tool: registered, state: {}, runtime: {} }, baseHandler);
}

test("an allowed call runs with the decided arguments; a denied one gets OpenMoat's message", async () => {
  const ran = [];
  const shell = { name: "shell", invoke: async (call) => (ran.push(call.args), "ok") };
  const config = openmoatMiddleware({ ...h.options, tools: { shell: describe.shell() } });
  assert.equal(config.name, "OpenMoat");
  const node = toolNode(shell, config);

  const args = { command: "ls" };
  const ok = await node({ name: "shell", args, id: "c1" });
  assert.deepEqual([ok.type, ok.content, ok.tool_call_id], ["tool", "ok", "c1"]);
  assert.notEqual(ran[0], args);
  assert.deepEqual(ran[0], args);

  const denied = await node({ name: "shell", args: { command: `cat ${h.key}` }, id: "c2" });
  assert.equal(denied.tool_call_id, "c2");
  assert.match(denied.content, /OpenMoat blocked this tool call \(secrets-paths\)/);
  assert.equal(ran.length, 1, "the denied command never ran");
});

test("a call the guard cannot decide gets the refusal, not the tool", async () => {
  let ran = false;
  const shell = { name: "shell", invoke: async () => (ran = true) };
  const node = toolNode(shell, openmoatMiddleware({ ...h.options, tools: { shell: describe.shell() } }));
  const r = await node({ name: "shell", args: {}, id: "c" });
  assert.match(r.content, /could not decide/);
  assert.equal(ran, false);
});
