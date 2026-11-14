// The Vercel AI SDK adapter, executed the way ai 7.0.173 executes a tool
// (provider-utils `executeTool`): `execute` is called once; an async
// iterable streams, anything else is awaited; a throw is a `tool-error`.
import { test } from "node:test";
import assert from "node:assert/strict";

import { describe } from "../src/adapters/guard.js";
import { OpenMoatBlockedError, withOpenMoat } from "../src/adapters/ai-sdk.js";
import { scratchHome } from "./adapter-home.js";

const h = scratchHome();
test.after(() => h.done());

const isAsyncIterable = (v) => v != null && typeof v[Symbol.asyncIterator] === "function";

/** A stub of the SDK's tool execution: the final output, or the tool-error. */
async function execute(tool, input) {
  try {
    const result = tool.execute(input, { toolCallId: "call_1", messages: [] });
    if (isAsyncIterable(result)) {
      const parts = [];
      for await (const part of result) parts.push(part);
      return { type: "tool-result", output: parts.at(-1), parts };
    }
    return { type: "tool-result", output: await result };
  } catch (error) {
    return { type: "tool-error", error };
  }
}

const options = { ...h.options, tools: { run: describe.shell(), read: describe.read() } };

test("an allowed call runs with the decided copy; a denied one is a tool-error", async () => {
  const seen = [];
  const tools = withOpenMoat(
    {
      run: { description: "shell", execute: async (input) => (seen.push(input), "ok") },
      client: { description: "runs in the browser" },
    },
    options,
  );
  assert.equal(tools.client.execute, undefined, "a tool without execute is left alone");
  const input = { command: "ls" };
  assert.deepEqual(await execute(tools.run, input), { type: "tool-result", output: "ok" });
  assert.notEqual(seen[0], input, "the tool gets the decided copy, not the model's object");
  assert.deepEqual(seen[0], input);

  const denied = await execute(tools.run, { command: `cat ${h.key}` });
  assert.equal(denied.type, "tool-error");
  assert.ok(denied.error instanceof OpenMoatBlockedError);
  assert.match(denied.error.message, /secrets-paths/);
  assert.equal(denied.error.outcome.verdict, "deny");
  assert.equal(seen.length, 1);
});

test("a streaming tool still streams, and is checked before its first part", async () => {
  let started = 0;
  const tools = withOpenMoat(
    {
      read: {
        async *execute({ path }) {
          started += 1;
          yield `reading ${path}`;
          yield "done";
        },
      },
    },
    options,
  );
  const ok = await execute(tools.read, { path: `${h.project}/a.txt` });
  assert.deepEqual(ok.parts, [`reading ${h.project}/a.txt`, "done"]);
  const denied = await execute(tools.read, { path: h.key });
  assert.equal(denied.type, "tool-error");
  assert.equal(started, 1);
});

test("an input the guard cannot copy or read fails closed", async () => {
  let ran = false;
  const tools = withOpenMoat({ run: { execute: async () => (ran = true) } }, options);
  assert.equal((await execute(tools.run, { command: () => "ls" })).type, "tool-error");
  assert.equal((await execute(tools.run, { cmd: "ls" })).type, "tool-error");
  assert.equal(ran, false);
});
