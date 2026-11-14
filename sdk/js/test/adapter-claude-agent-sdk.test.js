// The Claude Agent SDK adapter, called as the SDK calls a `PreToolUse`
// callback (input, toolUseID, { signal }); no SDK, no model.
import { test } from "node:test";
import assert from "node:assert/strict";

import { claudeToolAction, openmoatHooks } from "../src/adapters/claude-agent-sdk.js";
import { scratchHome } from "./adapter-home.js";

const h = scratchHome();
test.after(() => h.done());

/** What the SDK passes a `PreToolUse` callback. */
function pre(tool_name, tool_input, extra = {}) {
  return {
    hook_event_name: "PreToolUse",
    session_id: "s",
    transcript_path: "/dev/null",
    cwd: h.project,
    tool_name,
    tool_input,
    tool_use_id: "toolu_1",
    ...extra,
  };
}
const signal = new AbortController().signal;

test("the matcher blocks on failure and covers every tool", () => {
  const { PreToolUse } = openmoatHooks(h.options);
  assert.equal(PreToolUse.length, 1);
  assert.equal(PreToolUse[0].onFailure, "block");
  assert.equal(PreToolUse[0].matcher, undefined);
});

test("allowed and deferred calls get no opinion; a denied call is denied with the reason", async () => {
  const [callback] = openmoatHooks(h.options).PreToolUse[0].hooks;
  assert.deepEqual(await callback(pre("Bash", { command: "ls" }), "toolu_1", { signal }), {});
  assert.deepEqual(await callback(pre("Bash", { command: "git push" }), "toolu_2", { signal }), {});
  const denied = await callback(pre("Read", { file_path: h.key }), "toolu_3", { signal });
  assert.equal(denied.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(denied.hookSpecificOutput.permissionDecision, "deny");
  assert.match(denied.hookSpecificOutput.permissionDecisionReason, /secrets-paths.*secret material/);
  // Other events are not this hook's.
  assert.deepEqual(await callback({ hook_event_name: "Stop" }, undefined, { signal }), {});
});

test("a malformed input is denied, never passed", async () => {
  const [callback] = openmoatHooks(h.options).PreToolUse[0].hooks;
  const r = await callback(pre("Read", { path: "x" }), "t", { signal });
  assert.equal(r.hookSpecificOutput.permissionDecision, "deny");
  assert.match(r.hookSpecificOutput.permissionDecisionReason, /no string "file_path"/);
});

test("review is denied by default, or handed to the app's prompt with review: \"ask\"", async () => {
  const unchecked = { tools: { Odd: () => ({ type: "unchecked", action: { type: "shell", command: "ls" }, reason: "t" }) } };
  const [strict] = openmoatHooks({ ...h.options, ...unchecked }).PreToolUse[0].hooks;
  assert.equal((await strict(pre("Odd", {}), "t", { signal })).hookSpecificOutput.permissionDecision, "deny");

  const [ask] = openmoatHooks({ ...h.options, ...unchecked, review: "ask" }).PreToolUse[0].hooks;
  const asked = await ask(pre("Odd", {}), "t", { signal });
  assert.equal(asked.hookSpecificOutput.permissionDecision, "ask");
  // A mode that answers prompts without a person never gets an "ask".
  for (const mode of ["bypassPermissions", "dontAsk"]) {
    const r = await ask(pre("Odd", {}, { permission_mode: mode }), "t", { signal });
    assert.equal(r.hookSpecificOutput.permissionDecision, "deny", mode);
  }
  // A deny stays a deny under "ask".
  const key = await ask(pre("Read", { file_path: h.key }), "t", { signal });
  assert.equal(key.hookSpecificOutput.permissionDecision, "deny");
});

test("Claude's tools map to the actions openmoat-hosts gives them", () => {
  const cwd = "/w";
  const cases = [
    ["Bash", { command: "ls" }, { type: "shell", command: "ls" }],
    ["Monitor", { command: "tail -f x" }, { type: "shell", command: "tail -f x" }],
    ["PowerShell", { command: "dir" }, { type: "foreign_shell", shell: "PowerShell", command: "dir" }],
    ["Read", { file_path: "/a" }, { type: "fs_read", path: "/a" }],
    ["LSP", { filePath: "/a" }, { type: "fs_read", path: "/a" }],
    ["Write", { file_path: "/a", content: "" }, { type: "fs_write", path: "/a" }],
    ["Edit", { file_path: "/a" }, { type: "fs_write", path: "/a" }],
    ["MultiEdit", { file_path: "/a", edits: [] }, { type: "fs_write", path: "/a" }],
    ["NotebookEdit", { notebook_path: "/n.ipynb" }, { type: "fs_write", path: "/n.ipynb" }],
    ["WebFetch", { url: "https://x.test/", prompt: "p" }, { type: "fetch", url: "https://x.test/" }],
    ["WebSearch", { query: "q" }, { type: "web_search", query: "q" }],
    ["Grep", { pattern: "x" }, { type: "fs_read", path: "/w" }],
    ["Grep", { pattern: "x", path: "/src" }, { type: "fs_read", path: "/src" }],
    ["Glob", { pattern: "**/*.rs" }, { type: "fs_read", path: "/w" }],
    ["Glob", { pattern: "/home/me/.ssh/*" }, { type: "fs_read", path: "/home/me/.ssh" }],
    ["mcp__fs__read", { p: "~/.aws/credentials" }, { type: "mcp_tool", name: "mcp__fs__read", value_reads: ["~/.aws/credentials"] }],
    ["Agent", { prompt: "hi" }, { type: "unknown_tool", host: "claude-agent-sdk", tool: "Agent" }],
    ["SendFile", { path: "/home/me/.ssh/id_rsa" }, { type: "unknown_tool", host: "claude-agent-sdk", tool: "SendFile", reads: ["/home/me/.ssh/id_rsa"] }],
  ];
  for (const [tool, input, action] of cases) {
    assert.deepEqual(claudeToolAction(tool, input, cwd), action, tool);
  }
  assert.throws(() => claudeToolAction("Grep", { pattern: "x" }, undefined));
});
