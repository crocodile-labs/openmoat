// OpenMoat as a `PreToolUse` hook callback of the Claude Agent SDK
// (@anthropic-ai/claude-agent-sdk; types checked against 0.3.325).
//
//   query({ prompt, options: { hooks: openmoatHooks() } })
//
// A blocked call returns `permissionDecision: "deny"` with OpenMoat's message
// as `permissionDecisionReason`, which Claude receives as the tool result. An
// allowed or deferred call returns `{}`: no opinion, so the app's own
// permission settings and `canUseTool` still apply. The matcher sets
// `onFailure: "block"` (TypeScript Agent SDK 0.3.317+), so a callback that
// fails or times out blocks the call instead of letting it through.
//
// Tool inputs are read with the field names `openmoat-hosts` reads for Claude
// Code (crates/openmoat-hosts/src/wire/pre_tool_use.rs); a tool not listed is
// an unknown tool whose path-like strings are checked as reads.

import { createGuard, field, pathsIn, unknownTool } from "./guard.js";

const HOST = "claude-agent-sdk";

/** Permission modes that put no question to a person (`openmoat-hosts`'
 * Claude Code spec, `prompt_free_modes`): an "ask" there is never a review. */
const PROMPT_FREE_MODES = ["bypassPermissions", "dontAsk"];

const GLOB_CHARS = /[*?[{]/;

/**
 * The directory a `Glob` call reads: the fixed part of an absolute pattern,
 * else its `path`, else the session's directory.
 * @param {any} input
 * @param {string | undefined} cwd
 */
function globRoot(input, cwd) {
  const pattern = typeof input?.pattern === "string" ? input.pattern : "";
  if (/^(\/|~|[A-Za-z]:[\\/])/.test(pattern)) {
    const fixed = pattern.split(GLOB_CHARS)[0];
    const cut = Math.max(fixed.lastIndexOf("/"), fixed.lastIndexOf("\\"));
    return cut > 0 ? fixed.slice(0, cut) : fixed.slice(0, 1) || "/";
  }
  return typeof input?.path === "string" ? input.path : field({ cwd }, "cwd");
}

/**
 * The action one Claude Agent SDK tool call is decided as.
 * @param {string} tool
 * @param {unknown} input
 * @param {string} [cwd]
 * @returns {import("../index").Action}
 */
export function claudeToolAction(tool, input, cwd) {
  const i = /** @type {any} */ (input);
  switch (tool) {
    case "Bash":
    case "Monitor":
      return typeof i?.command === "string"
        ? { type: "shell", command: i.command }
        : unknownTool(HOST, tool, input);
    case "PowerShell":
      return { type: "foreign_shell", shell: tool, command: field(input, "command") };
    case "Read":
      return { type: "fs_read", path: field(input, "file_path") };
    case "LSP":
      return { type: "fs_read", path: field(input, "filePath") };
    case "Edit":
    case "Write":
    case "MultiEdit":
      return { type: "fs_write", path: field(input, "file_path") };
    case "NotebookEdit":
      return { type: "fs_write", path: field(input, "notebook_path") };
    case "WebFetch":
      return { type: "fetch", url: field(input, "url") };
    case "WebSearch":
      return { type: "web_search", query: field(input, "query") };
    case "Grep":
      return {
        type: "fs_read",
        path: typeof i?.path === "string" ? i.path : field({ cwd }, "cwd"),
      };
    case "Glob":
      return { type: "fs_read", path: globRoot(input, cwd) };
    default:
      break;
  }
  if (tool.startsWith("mcp__")) {
    const { paths, unchecked } = pathsIn(input);
    return {
      type: "mcp_tool",
      name: tool,
      ...(paths.length ? { value_reads: paths } : {}),
      ...(unchecked ? { unchecked } : {}),
    };
  }
  return unknownTool(HOST, tool, input);
}

/** @param {string} message */
const deny = (message) => ({
  hookSpecificOutput: {
    hookEventName: /** @type {const} */ ("PreToolUse"),
    permissionDecision: /** @type {const} */ ("deny"),
    permissionDecisionReason: message,
  },
});

/**
 * The `PreToolUse` callback.
 * @param {import("./claude-agent-sdk").ClaudeOptions} [options]
 */
export function openmoatPreToolUse(options = {}) {
  const asks = options.review === "ask";
  const guard =
    options.guard ??
    createGuard({ ...options, review: asks ? undefined : options.review, host: HOST });
  /** @type {import("./claude-agent-sdk").HookCallback} */
  const callback = async (input, toolUseID) => {
    if (input?.hook_event_name !== "PreToolUse") return {};
    const call = { tool: input.tool_name, input: input.tool_input, id: toolUseID, cwd: input.cwd };
    let action;
    try {
      action = options.tools?.[call.tool]?.(call.input) ?? claudeToolAction(call.tool, call.input, call.cwd);
    } catch (error) {
      const why = error instanceof Error ? error.message : String(error);
      return deny(`OpenMoat could not decide this tool call (${why}), so it did not run.`);
    }
    const outcome = await guard.check({ ...call, action });
    if (outcome.run) return {};
    // `review: "ask"` hands a review to the app's own prompt (`canUseTool`),
    // unless the session's mode answers prompts without a person.
    if (asks && outcome.verdict === "review" && !outcome.error) {
      if (!PROMPT_FREE_MODES.includes(input.permission_mode ?? "")) {
        try {
          await guard.record({ ...call, action }, outcome);
        } catch (error) {
          const why = error instanceof Error ? error.message : String(error);
          return deny(`OpenMoat could not record this tool call (${why}), so it did not run.`);
        }
        return {
          hookSpecificOutput: {
            hookEventName: /** @type {const} */ ("PreToolUse"),
            permissionDecision: /** @type {const} */ ("ask"),
            permissionDecisionReason: `OpenMoat: ${outcome.reason}`,
          },
        };
      }
    }
    return deny(outcome.message);
  };
  return { hooks: [callback], onFailure: /** @type {const} */ ("block"), ...(options.timeout ? { timeout: options.timeout } : {}) };
}

/**
 * `options.hooks` for `query()`: OpenMoat on every tool call.
 * @param {import("./claude-agent-sdk").ClaudeOptions} [options]
 */
export function openmoatHooks(options = {}) {
  return { PreToolUse: [openmoatPreToolUse(options)] };
}
