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
//
// OpenClaw runs the `before_tool_call` handlers one after another, highest
// priority first; each sees the call as it came, not as an earlier handler
// changed it, and the `params` of the last handler that returns some are what
// runs (`runBeforeToolCall` in OpenClaw's `src/plugins/hooks.ts`). So the
// plugin registers twice: first, to decide on the call, and last, to hand back
// the parameters it decided on, which undoes a change by any plugin in
// between. A block by any handler is final, and once a handler asks for
// approval OpenClaw keeps that handler's parameters, so after OpenMoat's own
// ask no later plugin can change the call either.
//
// When OpenClaw loads it to run (`registrationMode` "full"), the plugin also
// runs `moat guard --heartbeat --host openclaw`, which records that it loaded,
// so `moat status` and `moat doctor` can tell a plugin that never loaded.
// @ts-check

import { spawn } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

/**
 * The call as OpenClaw hands it to each `before_tool_call` handler.
 * @typedef {object} ToolCall
 * @property {string} toolName
 * @property {Record<string, unknown>} [params]
 * @property {string} [toolCallId]
 * @property {string} [runId]
 * @property {string} [toolKind]
 */

/**
 * What OpenClaw tells a handler about the run the call belongs to.
 * @typedef {object} ToolContext
 * @property {string} [agentId]
 * @property {string} [sessionId]
 * @property {string} [sessionKey]
 * @property {string} [toolCallId]
 * @property {string} [runId]
 * @property {string} [toolKind]
 * @property {AbortSignal} [abortSignal]
 */

/**
 * What a handler may return: a block, a request for the person's approval,
 * the parameters to run, or nothing.
 * @typedef {object} HookResult
 * @property {true} [block]
 * @property {string} [blockReason]
 * @property {Record<string, unknown>} [params]
 * @property {{
 *   title: string,
 *   description: string,
 *   severity: "info" | "warning" | "critical",
 *   allowedDecisions: Array<"allow-once" | "allow-always" | "deny">,
 * }} [requireApproval]
 */

/**
 * The part of OpenClaw's plugin API this plugin uses.
 * @typedef {object} PluginApi
 * @property {string} [registrationMode]
 * @property {unknown} [config]
 * @property {{ agent?: { resolveAgentWorkspaceDir?: (config: unknown, agentId?: string) => unknown } }} [runtime]
 * @property {(
 *   hook: "before_tool_call",
 *   handler: (event: ToolCall, ctx?: ToolContext) => Promise<HookResult | undefined> | HookResult | undefined,
 *   options: { priority: number },
 * ) => void} on
 */

/** @typedef {Record<string, string | undefined>} Environment */

/** @type {string} */
const MOAT = "openmoat";
// The state directory the guard decides with, from its command line and never
// from the environment the host gives this plugin (ADR-071).
/** @type {string} */
const MOAT_HOME = "";
// What follows the host in the guard's arguments: the state directory `init`
// wrote, or, in the package of OpenClaw's own channel (`plugins/openclaw`,
// where both are empty and `openmoat` is found on the search path),
// `--plugin`: the guard finds its state directory and gives no decision where
// `init`'s own copy of this plugin decides (ADR-099).
const WHERE = MOAT_HOME === "" ? ["--plugin"] : ["--home", MOAT_HOME];
// What the call is blocked with when there is no `openmoat` to run.
const NOT_INSTALLED =
  "OpenMoat is not installed: install it with `brew install crocodile-labs/tap/openmoat` (other ways: https://github.com/crocodile-labs/openmoat/blob/main/docs/INSTALL.md), then run `openmoat init`";
// What the call is blocked with when the policy lock names no program to run.
const LOCK_UNUSABLE =
  "the policy lock (`~/.moat/policy.lock`) names no `openmoat` this package can run: reinstall OpenMoat, then run `openmoat init`";

/**
 * Whether `path` is a file.
 * @param {string} path
 * @returns {boolean}
 */
function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * The program to run. `init`'s copy runs the binary `init` wrote in. The
 * package runs the one the policy lock pins (`binary` in
 * `~/.moat/policy.lock`, the absolute path `openmoat init` recorded); with no
 * lock yet, one in a folder OpenMoat's installers use, then `openmoat` on the
 * search path, which the agent's environment decides and so comes last, where
 * the guard denies every call until `openmoat init` writes the lock (ADR-099).
 * Throws when the lock names no program this can run.
 * @returns {string}
 */
function program() {
  if (MOAT_HOME !== "") return MOAT;
  const home = homedir();
  /** @type {string | undefined} */
  let text;
  try {
    text = readFileSync(join(home, ".moat", "policy.lock"), "utf8");
  } catch (error) {
    if (field(error, "code") !== "ENOENT") throw new Error(LOCK_UNUSABLE);
  }
  if (text !== undefined) {
    /** @type {unknown} */
    let binary;
    try {
      binary = field(JSON.parse(text), "binary");
    } catch {
      binary = undefined;
    }
    if (typeof binary !== "string" || !isAbsolute(binary) || !isFile(binary)) {
      throw new Error(LOCK_UNUSABLE);
    }
    return binary;
  }
  const dirs = [join(home, ".cargo", "bin"), "/opt/homebrew/bin", "/usr/local/bin", "/home/linuxbrew/.linuxbrew/bin"];
  for (const dir of dirs) {
    const found = join(dir, MOAT);
    if (isFile(found)) return found;
  }
  return MOAT;
}
// Above `moat guard`'s own 30 s budget, below the hook timeout `moat init` sets.
const GUARD_TIMEOUT_MS = 45_000;
const MAX_OUTPUT = 1 << 20;
// OpenClaw takes any number as a priority and sorts the handlers by it; these
// are the largest and smallest whose differences stay exact.
const FIRST = Number.MAX_SAFE_INTEGER;
const LAST = Number.MIN_SAFE_INTEGER;

/**
 * @param {string} why
 * @returns {HookResult}
 */
function block(why) {
  return { block: true, blockReason: `OpenMoat blocked this call: ${why}` };
}

/**
 * @param {unknown} error
 * @returns {string}
 */
function message(error) {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Why `openmoat` could not run: not installed, or `error`.
 * @param {unknown} error
 * @returns {string}
 */
function couldNotRun(error) {
  if (field(error, "code") === "ENOENT") return `moat could not run: ${NOT_INSTALLED}`;
  return `moat could not run: ${message(error)}`;
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
 * A variable as OpenClaw reads it: trimmed; blank, `undefined` and `null` are unset.
 * @param {Environment} env
 * @param {string} name
 * @returns {string | undefined}
 */
function variable(env, name) {
  const value = env[name]?.trim();
  return value && value !== "undefined" && value !== "null" ? value : undefined;
}

/**
 * `~` (alone or before a separator) as `base`, and the path made absolute.
 * @param {string} path
 * @param {string} base
 * @returns {string}
 */
function expand(path, base) {
  const tilde = path === "~" || path.startsWith("~/") || path.startsWith("~\\");
  return resolve(tilde ? join(base, path.slice(1)) : path);
}

/**
 * @param {Environment} env
 * @returns {string}
 */
function home(env) {
  const explicit = variable(env, "OPENCLAW_HOME");
  return explicit ? expand(explicit, homedir()) : homedir();
}

/**
 * Where the Gateway keeps its state and reads its configuration
 * (docs.openclaw.ai/help/environment), as `moat init` finds them.
 * @param {Environment} env
 * @returns {string}
 */
function stateDir(env) {
  const explicit = variable(env, "OPENCLAW_STATE_DIR");
  return explicit ? expand(explicit, home(env)) : join(home(env), ".openclaw");
}

/**
 * @param {Environment} env
 * @returns {string}
 */
function configPath(env) {
  const explicit = variable(env, "OPENCLAW_CONFIG_PATH");
  return explicit ? expand(explicit, home(env)) : join(stateDir(env), "openclaw.json");
}

/**
 * The agent's workspace, where OpenClaw's file tools resolve relative paths.
 * @param {PluginApi} api
 * @param {ToolContext} ctx
 * @returns {string | undefined}
 */
function workspace(api, ctx) {
  try {
    const dir = api.runtime?.agent?.resolveAgentWorkspaceDir?.(api.config, ctx.agentId);
    return typeof dir === "string" && dir !== "" ? dir : undefined;
  } catch {
    return undefined;
  }
}

/**
 * What the guard's exit code and output mean for OpenClaw.
 * @param {number | null} code
 * @param {string} stdout
 * @param {string} stderr
 * @returns {HookResult | undefined}
 */
function answer(code, stdout, stderr) {
  const text = stdout.trim();
  if (code === 0 && text === "") return undefined;
  /** @type {unknown} */
  let reply;
  try {
    reply = JSON.parse(text);
  } catch {
    const first = stderr.trim().split("\n")[0] || "no readable answer";
    return block(`moat guard exited ${code}: ${first}`);
  }
  const given = field(reply, "reason");
  const reason = typeof given === "string" ? given : "moat: no reason given";
  const decision = field(reply, "decision");
  if (code === 0 && decision === "allow") return undefined;
  if (code === 0 && decision === "ask") {
    return {
      requireApproval: {
        title: "OpenMoat: approve this call?",
        description: reason,
        severity: "warning",
        allowedDecisions: ["allow-once", "deny"],
      },
    };
  }
  if (code === 2 && decision === "deny") return { block: true, blockReason: reason };
  return block(`moat guard exited ${code} with an answer it should not give: ${text}`);
}

/**
 * The guard's answer to `payload`, run in `cwd`.
 * @param {Record<string, unknown>} payload
 * @param {string | undefined} cwd
 * @param {AbortSignal | undefined} signal
 * @returns {Promise<HookResult | undefined>}
 */
function guard(payload, cwd, signal) {
  return new Promise((done) => {
    let settled = false;
    /** @type {import("node:child_process").ChildProcessWithoutNullStreams | undefined} */
    let child;
    /** @type {ReturnType<typeof setTimeout> | undefined} */
    let timer;
    /** @param {HookResult | undefined} result */
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
      finish(block(why));
    };
    const onAbort = () => stop("the tool call was cancelled");
    try {
      child = spawn(program(), ["guard", "--host", "openclaw", ...WHERE], {
        cwd,
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (error) {
      finish(block(couldNotRun(error)));
      return;
    }
    timer = setTimeout(() => stop("moat guard did not answer in time"), GUARD_TIMEOUT_MS);
    signal?.addEventListener?.("abort", onAbort, { once: true });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (/** @type {string} */ chunk) => {
      stdout += chunk;
      if (stdout.length > MAX_OUTPUT) stop("moat guard's answer is too long");
    });
    child.stderr.on("data", (/** @type {string} */ chunk) => {
      if (stderr.length < MAX_OUTPUT) stderr += chunk;
    });
    child.on("error", (error) => finish(block(couldNotRun(error))));
    child.on("close", (code) => finish(answer(code, stdout, stderr)));
    child.stdin.on("error", () => {});
    child.stdin.end(JSON.stringify(payload));
  });
}

// Tells `moat` that OpenClaw loaded this plugin. It never waits and never
// fails the load: a heartbeat that cannot run only leaves `moat status`
// saying the plugin has not reported.
function heartbeat() {
  try {
    const child = spawn(program(), ["guard", "--heartbeat", "--host", "openclaw", ...WHERE], {
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
 * Decides on the call as it came, before any other plugin's handler.
 * @param {PluginApi} api
 * @param {ToolCall} event
 * @param {ToolContext | undefined} ctx
 * @returns {Promise<HookResult | undefined>}
 */
async function check(api, event, ctx) {
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
      stateDir: stateDir(process.env),
      platform: process.platform,
    };
    return await guard(payload, cwd, ctx?.abortSignal);
  } catch (error) {
    return block(`the OpenMoat plugin failed: ${message(error)}`);
  }
}

/**
 * Runs after every other plugin's handler and hands back the parameters
 * `check` decided on: OpenClaw gives every handler the call as it came.
 * @param {ToolCall} event
 * @returns {HookResult}
 */
function keep(event) {
  return { params: event.params ?? {} };
}

export default {
  id: "openmoat-clawhub",
  name: "OpenMoat",
  description: "Checks every tool call with `moat guard` before it runs.",
  /** @param {PluginApi} api */
  register(api) {
    if (api.registrationMode === undefined || api.registrationMode === "full") heartbeat();
    api.on("before_tool_call", (event, ctx) => check(api, event, ctx), { priority: FIRST });
    api.on("before_tool_call", keep, { priority: LAST });
  },
};
