// OpenMoat for OpenClaw. `moat init` writes this file with the path of the
// `moat` binary in place of __MOAT_BINARY__, adds it to `plugins.load.paths`
// and pins it; do not edit the installed copy.
//
// Before each tool call runs, OpenClaw's `before_tool_call` hook hands the call
// to `moat guard --host openclaw` on stdin. A deny blocks the call, an ask
// becomes OpenClaw's own approval request, and allow or no answer (defer) lets
// OpenClaw decide as it would without OpenMoat. Any other outcome blocks the
// call: moat missing, a crash, an exit code other than 0 or 2, an answer that
// cannot be read, or no answer within GUARD_TIMEOUT_MS. No dependencies.

import { spawn } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

const MOAT = __MOAT_BINARY__;
// Above `moat guard`'s own 30 s budget, below the hook timeout `moat init` sets.
const GUARD_TIMEOUT_MS = 45_000;
const MAX_OUTPUT = 1 << 20;

function block(why) {
  return { block: true, blockReason: `OpenMoat blocked this call: ${why}` };
}

function home(env) {
  return env.OPENCLAW_HOME?.trim() || homedir();
}

function expand(path, env) {
  return path.startsWith("~") ? join(home(env), path.slice(1)) : path;
}

// Where the Gateway reads its configuration (docs.openclaw.ai/help/environment).
function configPath(env) {
  const explicit = env.OPENCLAW_CONFIG_PATH?.trim();
  if (explicit) return expand(explicit, env);
  const state = env.OPENCLAW_STATE_DIR?.trim();
  return join(state ? expand(state, env) : join(home(env), ".openclaw"), "openclaw.json");
}

// The agent's workspace, where OpenClaw's file tools resolve relative paths.
function workspace(api, ctx) {
  try {
    const dir = api.runtime?.agent?.resolveAgentWorkspaceDir?.(api.config, ctx.agentId);
    return typeof dir === "string" && dir !== "" ? dir : undefined;
  } catch {
    return undefined;
  }
}

function answer(code, stdout, stderr) {
  const text = stdout.trim();
  if (code === 0 && text === "") return undefined;
  let reply;
  try {
    reply = JSON.parse(text);
  } catch {
    const first = stderr.trim().split("\n")[0] || "no readable answer";
    return block(`moat guard exited ${code}: ${first}`);
  }
  const reason = typeof reply?.reason === "string" ? reply.reason : "moat: no reason given";
  if (code === 0 && reply?.decision === "allow") return undefined;
  if (code === 0 && reply?.decision === "ask") {
    return {
      requireApproval: {
        title: "OpenMoat: approve this call?",
        description: reason,
        severity: "warning",
        allowedDecisions: ["allow-once", "deny"],
      },
    };
  }
  if (code === 2 && reply?.decision === "deny") return { block: true, blockReason: reason };
  return block(`moat guard exited ${code} with an answer it should not give: ${text}`);
}

function guard(payload, cwd, signal) {
  return new Promise((resolve) => {
    let settled = false;
    let child;
    let timer;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener?.("abort", onAbort);
      resolve(result);
    };
    const stop = (why) => {
      child?.kill("SIGKILL");
      finish(block(why));
    };
    const onAbort = () => stop("the tool call was cancelled");
    try {
      child = spawn(MOAT, ["guard", "--host", "openclaw"], {
        cwd,
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (error) {
      finish(block(`moat could not start: ${error?.message ?? error}`));
      return;
    }
    timer = setTimeout(() => stop("moat guard did not answer in time"), GUARD_TIMEOUT_MS);
    signal?.addEventListener?.("abort", onAbort, { once: true });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.length > MAX_OUTPUT) stop("moat guard's answer is too long");
    });
    child.stderr.on("data", (chunk) => {
      if (stderr.length < MAX_OUTPUT) stderr += chunk;
    });
    child.on("error", (error) => finish(block(`moat could not run: ${error?.message ?? error}`)));
    child.on("close", (code) => finish(answer(code, stdout, stderr)));
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(payload));
  });
}

export default {
  id: "openmoat",
  name: "OpenMoat",
  description: "Checks every tool call with `moat guard` before it runs.",
  register(api) {
    api.on(
      "before_tool_call",
      async (event, ctx) => {
        try {
          const cwd = workspace(api, ctx ?? {});
          const payload = {
            hook_event_name: "before_tool_call",
            toolName: event.toolName,
            params: event.params ?? {},
            toolCallId: event.toolCallId ?? ctx?.toolCallId,
            runId: event.runId ?? ctx?.runId,
            toolKind: event.toolKind ?? ctx?.toolKind,
            sessionId: ctx?.sessionId,
            sessionKey: ctx?.sessionKey,
            agentId: ctx?.agentId,
            cwd,
            configPath: configPath(process.env),
            platform: process.platform,
          };
          return await guard(payload, cwd, ctx?.abortSignal);
        } catch (error) {
          return block(`the OpenMoat plugin failed: ${error?.message ?? error}`);
        }
      },
      { priority: 10_000 },
    );
  },
};
