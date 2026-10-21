// OpenMoat for pi. `openmoat init` writes this file to `extensions/` in pi's
// agent directory (`~/.pi/agent`, or `PI_CODING_AGENT_DIR`) with the path of
// the `openmoat` binary in place of __MOAT_BINARY__, and pins it; do not edit
// the installed copy.
//
// Before each tool call runs, pi's `tool_call` event hands the call to
// `openmoat guard --host pi` on stdin. A deny blocks the call, an ask is put to
// the person in pi's own dialog, and allow or no answer (defer) lets the call
// run as it would without OpenMoat. Any other outcome blocks the call:
// `openmoat` missing, a crash, an exit code other than 0 or 2, an answer that
// cannot be read, or no answer within GUARD_TIMEOUT_MS. pi blocks the call
// when this handler throws. No dependencies.

import { spawn } from "node:child_process";

const MOAT = __MOAT_BINARY__;
// Above `openmoat guard`'s own 30 s budget; the wait for a person's answer to
// an ask comes after it and has no limit.
const GUARD_TIMEOUT_MS = 45_000;
const MAX_OUTPUT = 1 << 20;

function block(why) {
  return { block: true, reason: `OpenMoat blocked this call: ${why}` };
}

async function answer(code, stdout, stderr, ctx) {
  const text = stdout.trim();
  if (code === 0 && text === "") return undefined;
  let reply;
  try {
    reply = JSON.parse(text);
  } catch {
    const first = stderr.trim().split("\n")[0] || "no readable answer";
    return block(`openmoat guard exited ${code}: ${first}`);
  }
  const reason = typeof reply?.reason === "string" ? reply.reason : "moat: no reason given";
  if (code === 0 && reply?.decision === "allow") return undefined;
  if (code === 0 && reply?.decision === "ask") {
    // The guard answers an ask only where pi has a screen (`hasUI`).
    if (!ctx.hasUI) return block(reason);
    const approved = await ctx.ui.confirm("OpenMoat: approve this call?", reason, {
      signal: ctx.signal,
    });
    return approved === true ? undefined : { block: true, reason: `not approved: ${reason}` };
  }
  if (code === 2 && reply?.decision === "deny") return { block: true, reason };
  return block(`openmoat guard exited ${code} with an answer it should not give: ${text}`);
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
      finish({ code: null, stdout: "", stderr: why });
    };
    const onAbort = () => stop("the tool call was cancelled");
    try {
      child = spawn(MOAT, ["guard", "--host", "pi"], {
        cwd,
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (error) {
      finish({ code: null, stdout: "", stderr: `openmoat could not start: ${error?.message ?? error}` });
      return;
    }
    timer = setTimeout(() => stop("openmoat guard did not answer in time"), GUARD_TIMEOUT_MS);
    signal?.addEventListener?.("abort", onAbort, { once: true });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
      if (stdout.length > MAX_OUTPUT) stop("openmoat guard's answer is too long");
    });
    child.stderr.on("data", (chunk) => {
      if (stderr.length < MAX_OUTPUT) stderr += chunk;
    });
    child.on("error", (error) =>
      finish({ code: null, stdout: "", stderr: `openmoat could not run: ${error?.message ?? error}` }),
    );
    child.on("close", (code) => finish({ code, stdout, stderr }));
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(payload));
  });
}

function sessionId(ctx) {
  try {
    const id = ctx.sessionManager?.getSessionId?.();
    return typeof id === "string" && id !== "" ? id : undefined;
  } catch {
    return undefined;
  }
}

export default function openmoat(pi) {
  pi.on("tool_call", async (event, ctx) => {
    try {
      const cwd = typeof ctx?.cwd === "string" && ctx.cwd !== "" ? ctx.cwd : undefined;
      const payload = {
        hook_event_name: "tool_call",
        toolName: event.toolName,
        input: event.input ?? {},
        toolCallId: event.toolCallId,
        parentToolCallId: event.parentToolCallId,
        sessionId: sessionId(ctx),
        cwd,
        hasUI: ctx?.hasUI === true,
        platform: process.platform,
      };
      const run = await guard(payload, cwd, ctx?.signal);
      if (run.code === null) return block(run.stderr);
      return await answer(run.code, run.stdout, run.stderr, ctx);
    } catch (error) {
      return block(`the OpenMoat extension failed: ${error?.message ?? error}`);
    }
  });
}
