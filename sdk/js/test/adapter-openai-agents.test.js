// The OpenAI Agents SDK adapter, run the way @openai/agents-core 0.22.0 runs
// tool input guardrails (utils/toolGuardrails.mjs): in order, the first
// `rejectContent` answers instead of the tool, `throwException` ends the run.
import { test } from "node:test";
import assert from "node:assert/strict";

import { describe } from "../src/adapters/guard.js";
import { openmoatGuardrail, withOpenMoat } from "../src/adapters/openai-agents.js";
import { scratchHome } from "./adapter-home.js";

const h = scratchHome();
test.after(() => h.done());

/** A stub runner: the tool's guardrails, then the tool, as the SDK does. */
async function runTool(tool, args) {
  const toolCall = { type: "function_call", callId: "call_1", name: tool.name, arguments: JSON.stringify(args) };
  for (const guardrail of tool.inputGuardrails ?? []) {
    const { behavior } = await guardrail.run({ context: {}, agent: {}, toolCall });
    if (behavior.type === "rejectContent") return { ran: false, output: behavior.message };
    if (behavior.type === "throwException") throw new Error(`Tool input guardrail triggered: ${guardrail.name}`);
  }
  return { ran: true, output: await tool.invoke({}, toolCall.arguments) };
}

function shellTool() {
  const ran = [];
  return {
    ran,
    tool: {
      type: "function",
      name: "run_shell",
      invoke: async (_ctx, json) => (ran.push(JSON.parse(json).command), "done"),
    },
  };
}
const options = { ...h.options, tools: { run_shell: describe.shell() } };

test("a guardrail lets an allowed call run and rejects a denied one with the message", async () => {
  const { tool, ran } = shellTool();
  const [guarded] = withOpenMoat([tool, { type: "hosted_tool", name: "web_search" }], options);
  assert.equal(guarded.inputGuardrails.length, 1);
  assert.deepEqual(await runTool(guarded, { command: "ls" }), { ran: true, output: "done" });
  const denied = await runTool(guarded, { command: `cat ${h.key}` });
  assert.equal(denied.ran, false);
  assert.match(denied.output, /secrets-paths/);
  assert.deepEqual(ran, ["ls"], "the denied command never ran");
});

test("hosted tools are left as they are; an existing guardrail is kept", () => {
  const mine = { type: "tool_input", name: "mine", run: async () => ({ behavior: { type: "allow" } }) };
  const hosted = { type: "hosted_tool", name: "web_search" };
  const [fn, kept] = withOpenMoat([{ type: "function", name: "f", inputGuardrails: [mine] }, hosted], options);
  assert.deepEqual(fn.inputGuardrails.map((g) => g.name), ["mine", "openmoat"]);
  assert.equal(kept, hosted);
});

test("block: \"throw\" ends the run; unreadable arguments never run", async () => {
  const { tool, ran } = shellTool();
  const throwing = { ...tool, inputGuardrails: [openmoatGuardrail({ ...options, block: "throw" })] };
  await assert.rejects(runTool(throwing, { command: `cat ${h.key}` }), /guardrail triggered: openmoat/);
  const g = openmoatGuardrail(options);
  const r = await g.run({ toolCall: { name: "run_shell", arguments: "{not json", callId: "c" } });
  assert.equal(r.behavior.type, "rejectContent");
  assert.deepEqual(ran, []);
});

test("the outcome's verdict, rules and time go to the trace", async () => {
  const g = openmoatGuardrail(options);
  const r = await g.run({ toolCall: { name: "run_shell", arguments: '{"command":"ls"}', callId: "c" } });
  assert.equal(r.outputInfo.verdict, "allow");
  assert.equal(typeof r.outputInfo.ms, "number");
});
