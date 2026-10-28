// OpenMoat for OpenCode. `openmoat init` writes this file to `plugins/` in
// OpenCode's configuration directory (`~/.config/opencode`,
// `$XDG_CONFIG_HOME/opencode`, or `OPENCODE_CONFIG_DIR`) with the path of the
// `openmoat` binary in place of __MOAT_BINARY__, and pins it; do not edit the
// installed copy. One file serves both plugin APIs (ADR-040): OpenCode 1
// (`opencode-ai`, 1.3.4 and later) calls `server`, OpenCode 2 (`@opencode/cli`)
// calls `setup`; each ignores the other.
//
// Before each tool call runs, OpenCode's hook (`tool.execute.before` in
// OpenCode 1, `execute.before` in OpenCode 2) hands the call to `openmoat guard
// --host opencode` on stdin. A deny blocks the call with OpenMoat's reason,
// which the model sees; allow or no answer (defer) lets the call run as it
// would without OpenMoat, and OpenCode's own permission rules still apply. An
// ask is put to the person through OpenCode 2's permission prompt; OpenCode 1
// gives plugins no way to ask, so there the guard answers an ask with a deny
// that says how to approve it. Any other outcome blocks the call: `openmoat`
// missing, a crash, an exit code other than 0 or 2, an answer that cannot be
// read, or no answer within GUARD_TIMEOUT_MS. OpenCode blocks the call when
// this hook throws, and it waits for the hook without a limit of its own. No
// dependencies.
//
// The call OpenMoat checked is the call that runs. OpenCode hands one object
// to every later plugin and then to the tool, so a plugin loaded after this
// one could otherwise change a call after it was checked. OpenCode 1: the
// arguments are frozen before the guard runs, and a later change throws.
// OpenCode 2: the tool's name and a frozen copy of its input replace the
// event's own, and a later plugin that assigns either throws; the command and
// shell of the agent's shell call are pinned the same way when OpenCode
// starts it. Either throw blocks the call.
//
// When OpenCode loads the plugin for a project (`server` or `setup`), it runs
// `openmoat guard --heartbeat --host opencode`, which records that it loaded,
// so `openmoat status` and `openmoat doctor` can tell a plugin that never
// loaded (ADR-042).
// @ts-check

import { spawn } from "node:child_process";

/**
 * What OpenCode 1 hands `server` when it loads the plugin for a project.
 * @typedef {object} PluginInput
 * @property {unknown} [directory]
 * @property {unknown} [worktree]
 */

/**
 * The call as OpenCode 1 hands it to `tool.execute.before`.
 * @typedef {object} ToolCall
 * @property {string} [tool]
 * @property {string} [sessionID]
 * @property {string} [callID]
 */

/**
 * The call as OpenCode 2 hands it to `execute.before`.
 * @typedef {object} ToolEvent
 * @property {string} [tool]
 * @property {unknown} [input]
 * @property {string} [id]
 * @property {string} [sessionID]
 * @property {string} [agent]
 * @property {string} [messageID]
 */

/**
 * What OpenCode 2 asks its `evaluate` permission hook about.
 * @typedef {object} Evaluation
 * @property {string} [action]
 * @property {{ type?: string, id?: string }} [source]
 * @property {string} [effect]
 * @property {string} [message]
 */

/**
 * A shell OpenCode 2 is about to start.
 * @typedef {object} ShellInvocation
 * @property {string} [command]
 * @property {string} [shell]
 */

/**
 * The part of OpenCode 2's plugin context this plugin uses.
 * @typedef {object} PluginContext
 * @property {{ directory?: unknown, project?: { directory?: unknown } }} [location]
 * @property {{ hook: (name: "execute.before", handler: (event: ToolEvent) => Promise<void>) => Promise<void> }} tool
 * @property {{
 *   assert?: (request: Record<string, unknown>) => Promise<void>,
 *   hook: (name: "evaluate", handler: (evaluation: Evaluation) => void) => Promise<void>,
 * }} permission
 * @property {{ transform: (fn: (servers: { list: () => Array<[string, unknown]> }) => void) => Promise<void> }} mcp
 * @property {{ hook: (name: "create.before", handler: (invocation: ShellInvocation) => void) => Promise<void> }} shell
 */

/**
 * How the guard ended: its exit code (`null` when it did not run to the
 * end) and what it wrote.
 * @typedef {{ code: number | null, stdout: string, stderr: string }} Run
 */

/**
 * What the guard's answer means: run the call, ask about it, or the Error
 * that blocks it.
 * @typedef {{ run: true } | { ask: string } | { error: Error }} Answer
 */

/** @type {string} */
const MOAT = __MOAT_BINARY__;
// Above `openmoat guard`'s own 30 s budget.
const GUARD_TIMEOUT_MS = 45_000;
const MAX_OUTPUT = 1 << 20;
// The permission action OpenMoat's asks carry in OpenCode 2's prompt.
const ASK_ACTION = "openmoat";
// How many checked shell commands wait for OpenCode to start them.
const MAX_CHECKED_SHELLS = 64;
const HOW_TO_APPROVE =
  "run `openmoat` to approve it, or `openmoat allow --last` (this session) or " +
  "`openmoat allow --last --always`, then retry";

/**
 * @param {string} why
 * @returns {Error}
 */
function blocked(why) {
  return new Error(`OpenMoat blocked this call: ${why}`);
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
 * What the guard's exit code and output mean: `{ run: true }` to let the call
 * run, `{ ask: reason }` when `asks` and the guard asks, else `{ error }`,
 * the Error that blocks it.
 * @param {number} code
 * @param {string} stdout
 * @param {string} stderr
 * @param {boolean} asks
 * @returns {Answer}
 */
function answer(code, stdout, stderr, asks) {
  const text = stdout.trim();
  if (code === 0 && text === "") return { run: true };
  /** @type {unknown} */
  let reply;
  try {
    reply = JSON.parse(text);
  } catch {
    const first = stderr.trim().split("\n")[0] || "no readable answer";
    return { error: blocked(`openmoat guard exited ${code}: ${first}`) };
  }
  const given = field(reply, "reason");
  const reason = typeof given === "string" ? given : "moat: no reason given";
  const decision = field(reply, "decision");
  if (code === 0 && decision === "allow") return { run: true };
  if (asks && code === 0 && decision === "ask") return { ask: reason };
  if (code === 2 && decision === "deny") return { error: new Error(reason) };
  return { error: blocked(`openmoat guard exited ${code} with an answer it should not give: ${text}`) };
}

/**
 * Run the guard on `payload` in `cwd`.
 * @param {Record<string, unknown>} payload
 * @param {string | undefined} cwd
 * @returns {Promise<Run>}
 */
function guard(payload, cwd) {
  return new Promise((resolve) => {
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
      resolve(result);
    };
    /** @param {string} why */
    const stop = (why) => {
      child?.kill("SIGKILL");
      finish({ code: null, stdout: "", stderr: why });
    };
    try {
      child = spawn(MOAT, ["guard", "--host", "opencode"], {
        cwd,
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch (error) {
      finish({ code: null, stdout: "", stderr: `openmoat could not start: ${message(error)}` });
      return;
    }
    timer = setTimeout(() => stop("openmoat guard did not answer in time"), GUARD_TIMEOUT_MS);
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

// Tells `openmoat` that OpenCode loaded this plugin. It never waits and never
// fails the load: a heartbeat that cannot run only leaves `openmoat status`
// saying the plugin has not reported.
function heartbeat() {
  try {
    const child = spawn(MOAT, ["guard", "--heartbeat", "--host", "opencode"], {
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
 * `value` and everything in it made read-only.
 * @template T
 * @param {T} value
 * @returns {T}
 */
function freeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Reflect.ownKeys(value)) {
    freeze(/** @type {Record<PropertyKey, unknown>} */ (value)[key]);
  }
  return value;
}

/**
 * `object[key]` from now on always `value`; assigning it throws, which
 * blocks the call whatever mode the assigning plugin's code runs in.
 * @param {object} object
 * @param {string} key
 * @param {unknown} value
 */
function pin(object, key, value) {
  Object.defineProperty(object, key, {
    get: () => value,
    set: () => {
      throw blocked(`another plugin tried to change \`${key}\` after OpenMoat checked the call`);
    },
    enumerable: true,
    configurable: false,
  });
}

/**
 * @param {unknown} value
 * @returns {string | undefined}
 */
function text(value) {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/**
 * Runs the guard on `payload` in `directory` and turns any failure into the
 * Error that blocks the call.
 * @param {Record<string, unknown>} payload
 * @param {string | undefined} directory
 * @param {boolean} asks
 * @returns {Promise<Answer>}
 */
async function check(payload, directory, asks) {
  let run;
  try {
    run = await guard(payload, directory);
  } catch (error) {
    return { error: blocked(`the OpenMoat plugin failed: ${message(error)}`) };
  }
  if (run.code === null) return { error: blocked(run.stderr) };
  return answer(run.code, run.stdout, run.stderr, asks);
}

/**
 * OpenCode 1 (`tool.execute.before`): `input` is the `PluginInput` of the
 * instance that loaded the plugin.
 * @param {PluginInput | undefined} input
 */
async function server(input) {
  heartbeat();
  const directory = text(input?.directory);
  const worktree = text(input?.worktree);
  // The names of the MCP servers in OpenCode's merged configuration, from
  // its `config` hook: OpenCode names a server's tools `<server>_<tool>`, so
  // the guard needs them to tell an MCP tool from a plugin's.
  /** @type {string[]} */
  let mcpServers = [];
  return {
    /** @param {unknown} config */
    config: async (config) => {
      const mcp = field(config, "mcp");
      mcpServers = mcp && typeof mcp === "object" ? Object.keys(mcp) : [];
    },
    /**
     * @param {ToolCall | undefined} call
     * @param {{ args?: unknown } | undefined} output
     */
    "tool.execute.before": async (call, output) => {
      let payload;
      try {
        const args = freeze(output?.args ?? {});
        payload = {
          hook_event_name: "tool.execute.before",
          tool: call?.tool,
          sessionID: call?.sessionID,
          callID: call?.callID,
          args,
          directory,
          worktree,
          mcpServers,
          platform: process.platform,
        };
      } catch (error) {
        throw blocked(`the OpenMoat plugin failed: ${message(error)}`);
      }
      const result = await check(payload, directory, false);
      if ("error" in result) throw result.error;
    },
  };
}

/**
 * OpenCode 2 (`execute.before`): `ctx` is the plugin context of the instance
 * that loaded it. The tool hook is registered first: if anything after it
 * cannot be set up, OpenMoat still checks every call (and blocks the asks it
 * cannot put to the person).
 * @param {PluginContext} ctx
 */
async function setup(ctx) {
  heartbeat();
  const directory = text(ctx?.location?.directory);
  const worktree = text(ctx?.location?.project?.directory) ?? directory;
  /** @type {string[]} */
  let mcpServers = [];
  // The reason of each call OpenMoat is asking about, by the call's id.
  /** @type {Map<string | undefined, string>} */
  const asking = new Map();
  // Shell commands checked and not yet started, oldest first.
  /** @type {string[]} */
  const checkedShells = [];
  let canAsk = false;

  await ctx.tool.hook("execute.before", async (event) => {
    let payload;
    let tool;
    /** @type {unknown} */
    let input;
    try {
      tool = event?.tool;
      input = freeze(structuredClone(event?.input ?? {}));
      pin(event, "tool", tool);
      pin(event, "input", input);
      payload = {
        hook_event_name: "execute.before",
        tool,
        sessionID: event?.sessionID,
        agent: event?.agent,
        messageID: event?.messageID,
        callID: event?.id,
        input,
        directory,
        worktree,
        mcpServers,
        platform: process.platform,
      };
    } catch (error) {
      throw blocked(`the OpenMoat plugin failed: ${message(error)}`);
    }
    const result = await check(payload, directory, true);
    if ("error" in result) throw result.error;
    if ("ask" in result) await ask(event, result.ask);
    const command = field(input, "command");
    if (tool === "shell" && typeof command === "string") {
      checkedShells.push(command);
      if (checkedShells.length > MAX_CHECKED_SHELLS) checkedShells.shift();
    }
  });

  /**
   * Puts OpenMoat's ask to the person: OpenCode evaluates the session's
   * rules for the action, the `evaluate` hook below makes it an ask whatever
   * they say, and OpenCode prompts and waits. A deny rule, a rejection or no
   * way to ask rejects, which blocks the call.
   * @param {ToolEvent} event
   * @param {string} reason
   */
  async function ask(event, reason) {
    const assert = ctx?.permission?.assert;
    if (!canAsk || typeof assert !== "function") {
      throw blocked(`this needs your approval and OpenCode could not ask: ${HOW_TO_APPROVE}`);
    }
    asking.set(event.id, reason);
    try {
      await assert.call(ctx.permission, {
        sessionID: event.sessionID,
        agent: event.agent,
        action: ASK_ACTION,
        resources: [String(event.tool)],
        metadata: { reason },
        source: { type: "tool", messageID: event.messageID, id: event.id },
      });
    } finally {
      asking.delete(event.id);
    }
  }

  // Each of these only adds to what the tool hook does: it never throws, so
  // OpenCode never disables the plugin for it.
  try {
    await ctx.permission.hook("evaluate", (evaluation) => {
      try {
        const id = evaluation?.source?.type === "tool" ? evaluation.source.id : undefined;
        if (evaluation?.action !== ASK_ACTION || !asking.has(id)) return;
        evaluation.effect = "ask";
        evaluation.message = asking.get(id);
      } catch {}
    });
    canAsk = true;
  } catch {}
  try {
    await ctx.mcp.transform((servers) => {
      try {
        mcpServers = servers.list().map(([name]) => name);
      } catch {}
    });
  } catch {}
  try {
    // The shell OpenCode is about to start for a command OpenMoat checked:
    // its command and shell can no longer change.
    await ctx.shell.hook("create.before", (invocation) => {
      try {
        const command = invocation?.command;
        if (command === undefined) return;
        const at = checkedShells.indexOf(command);
        if (at === -1) return;
        checkedShells.splice(at, 1);
        pin(invocation, "command", invocation.command);
        pin(invocation, "shell", invocation.shell);
      } catch {}
    });
  } catch {}
}

export default { id: "openmoat", server, setup };
