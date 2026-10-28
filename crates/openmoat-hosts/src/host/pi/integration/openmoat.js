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
//
// When pi loads the extension, it runs `openmoat guard --heartbeat --host pi`,
// which records that it loaded, so `openmoat status` and `openmoat doctor` can
// tell an extension that never loaded.
// @ts-check

import { spawn } from "node:child_process";

/**
 * The call as pi hands it to a `tool_call` handler.
 * @typedef {object} ToolCall
 * @property {string} toolName
 * @property {Record<string, unknown>} [input]
 * @property {string} [toolCallId]
 * @property {string} [parentToolCallId]
 */

/**
 * The part of pi's extension context this extension uses.
 * @typedef {object} Context
 * @property {string} [cwd]
 * @property {boolean} [hasUI]
 * @property {AbortSignal} [signal]
 * @property {{ getSessionId?: () => unknown }} [sessionManager]
 * @property {{ confirm: (title: string, message: string, options?: { signal?: AbortSignal }) => Promise<boolean> }} ui
 */

/**
 * What a `tool_call` handler returns to block the call.
 * @typedef {{ block: true, reason: string }} Block
 */

/**
 * The part of pi's extension API this extension uses.
 * @typedef {object} ExtensionApi
 * @property {(
 *   event: "tool_call",
 *   handler: (event: ToolCall, ctx: Context) => Promise<Block | undefined>,
 * ) => void} on
 */

/**
 * How the guard ended: its exit code (`null` when it did not run to the
 * end) and what it wrote.
 * @typedef {{ code: number | null, stdout: string, stderr: string }} Run
 */

/** @type {string} */
const MOAT = __MOAT_BINARY__;
// Above `openmoat guard`'s own 30 s budget; the wait for a person's answer to
// an ask comes after it and has no limit.
const GUARD_TIMEOUT_MS = 45_000;
const MAX_OUTPUT = 1 << 20;

/**
 * @param {string} why
 * @returns {Block}
 */
function block(why) {
  return { block: true, reason: `OpenMoat blocked this call: ${why}` };
}

/**
 * @param {unknown} error
 * @returns {string}
 */
function message(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * `value[key]` when `value` is an object.
 * @param {unknown} value
 * @param {string} key
 * @returns {unknown}
 */
function field(value, key) {
  return value !== null && typeof value === "object"
    ? /** @type {Record<string, unknown>} */ (value)[key]
    : undefined;
}

/**
 * What the guard's exit code and output mean for pi, after asking the person
 * where the guard asks.
 * @param {number} code
 * @param {string} stdout
 * @param {string} stderr
 * @param {Context} ctx
 * @returns {Promise<Block | undefined>}
 */
async function answer(code, stdout, stderr, ctx) {
  const text = stdout.trim();
  if (code === 0 && text === "") return undefined;
  /** @type {unknown} */
  let reply;
  try {
    reply = JSON.parse(text);
  } catch {
    const first = stderr.trim().split("\n")[0] || "no readable answer";
    return block(`openmoat guard exited ${code}: ${first}`);
  }
  const given = field(reply, "reason");
  const reason = typeof given === "string" ? given : "moat: no reason given";
  const decision = field(reply, "decision");
  if (code === 0 && decision === "allow") return undefined;
  if (code === 0 && decision === "ask") {
    // The guard answers an ask only where pi has a screen (`hasUI`).
    if (!ctx.hasUI) return block(reason);
    const approved = await ctx.ui.confirm("OpenMoat: approve this call?", reason, {
      signal: ctx.signal,
    });
    return approved === true ? undefined : { block: true, reason: `not approved: ${reason}` };
  }
  if (code === 2 && decision === "deny") return { block: true, reason };
  return block(`openmoat guard exited ${code} with an answer it should not give: ${text}`);
}

/**
 * Run the guard on `payload` in `cwd`.
 * @param {Record<string, unknown>} payload
 * @param {string | undefined} cwd
 * @param {AbortSignal | undefined} signal
 * @returns {Promise<Run>}
 */
function guard(payload, cwd, signal) {
  return new Promise((done) => {
    let settled = false;
    /** @type {import("node:child_process").ChildProcessWithoutNullStreams | undefined} */
    let child;
    /** @type {ReturnType<typeof setTimeout> | undefined} */
    let timer;
    /** @param {Run} result */
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener?.("abort", onAbort);
      done(result);
    };
    /** @param {string} why */
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
      finish({ code: null, stdout: "", stderr: `openmoat could not start: ${message(error)}` });
      return;
    }
    timer = setTimeout(() => stop("openmoat guard did not answer in time"), GUARD_TIMEOUT_MS);
    signal?.addEventListener?.("abort", onAbort, { once: true });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (/** @type {string} */ chunk) => {
      stdout += chunk;
      if (stdout.length > MAX_OUTPUT) stop("openmoat guard's answer is too long");
    });
    child.stderr.on("data", (/** @type {string} */ chunk) => {
      if (stderr.length < MAX_OUTPUT) stderr += chunk;
    });
    child.on("error", (error) =>
      finish({ code: null, stdout: "", stderr: `openmoat could not run: ${message(error)}` }),
    );
    child.on("close", (code) => finish({ code, stdout, stderr }));
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(payload));
  });
}

// Tells `openmoat` that pi loaded this extension. It never waits and never
// fails the load: a heartbeat that cannot run only leaves `openmoat status`
// saying the extension has not reported.
function heartbeat() {
  try {
    const child = spawn(MOAT, ["guard", "--heartbeat", "--host", "pi"], {
      stdio: "ignore",
      windowsHide: true,
    });
    child.on("error", () => {});
    child.unref();
  } catch {
    // Nothing to do: see above.
  }
}

/**
 * @param {Context | undefined} ctx
 * @returns {string | undefined}
 */
function sessionId(ctx) {
  try {
    const id = ctx?.sessionManager?.getSessionId?.();
    return typeof id === "string" && id !== "" ? id : undefined;
  } catch {
    return undefined;
  }
}

/** @param {ExtensionApi} pi */
export default function openmoat(pi) {
  heartbeat();
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
      return block(`the OpenMoat extension failed: ${message(error)}`);
    }
  });
}
