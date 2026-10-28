// OpenMoat for OpenCode. `openmoat init` writes this file to `plugins/` in
// OpenCode's configuration directory (`~/.config/opencode`,
// `$XDG_CONFIG_HOME/opencode`, or `OPENCODE_CONFIG_DIR`) with the path of the
// `openmoat` binary in place of __MOAT_BINARY__, and pins it; do not edit the
// installed copy. One file serves both plugin APIs (ADR-039): OpenCode 1
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

import { spawn } from "node:child_process";

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

function blocked(why) {
  return new Error(`OpenMoat blocked this call: ${why}`);
}

// What the guard's exit code and output mean: `{ run: true }` to let the call
// run, `{ ask: reason }` when `asks` and the guard asks, else `{ error }`,
// the Error that blocks it.
function answer(code, stdout, stderr, asks) {
  const text = stdout.trim();
  if (code === 0 && text === "") return { run: true };
  let reply;
  try {
    reply = JSON.parse(text);
  } catch {
    const first = stderr.trim().split("\n")[0] || "no readable answer";
    return { error: blocked(`openmoat guard exited ${code}: ${first}`) };
  }
  const reason = typeof reply?.reason === "string" ? reply.reason : "moat: no reason given";
  if (code === 0 && reply?.decision === "allow") return { run: true };
  if (asks && code === 0 && reply?.decision === "ask") return { ask: reason };
  if (code === 2 && reply?.decision === "deny") return { error: new Error(reason) };
  return { error: blocked(`openmoat guard exited ${code} with an answer it should not give: ${text}`) };
}

function guard(payload, cwd) {
  return new Promise((resolve) => {
    let settled = false;
    let child;
    let timer;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(result);
    };
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
      finish({ code: null, stdout: "", stderr: `openmoat could not start: ${error?.message ?? error}` });
      return;
    }
    timer = setTimeout(() => stop("openmoat guard did not answer in time"), GUARD_TIMEOUT_MS);
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

// `value` and everything in it made read-only.
function freeze(value) {
  if (value === null || typeof value !== "object" || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const key of Reflect.ownKeys(value)) freeze(value[key]);
  return value;
}

// `object[key]` from now on always `value`; assigning it throws, which
// blocks the call whatever mode the assigning plugin's code runs in.
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

function text(value) {
  return typeof value === "string" && value !== "" ? value : undefined;
}

// Runs the guard on `payload` in `directory` and turns any failure into the
// Error that blocks the call.
async function check(payload, directory, asks) {
  let run;
  try {
    run = await guard(payload, directory);
  } catch (error) {
    return { error: blocked(`the OpenMoat plugin failed: ${error?.message ?? error}`) };
  }
  if (run.code === null) return { error: blocked(run.stderr) };
  return answer(run.code, run.stdout, run.stderr, asks);
}

// OpenCode 1 (`tool.execute.before`): `input` is the `PluginInput` of the
// instance that loaded the plugin.
async function server(input) {
  const directory = text(input?.directory);
  const worktree = text(input?.worktree);
  // The names of the MCP servers in OpenCode's merged configuration, from
  // its `config` hook: OpenCode names a server's tools `<server>_<tool>`, so
  // the guard needs them to tell an MCP tool from a plugin's.
  let mcpServers = [];
  return {
    config: async (config) => {
      const mcp = config?.mcp;
      mcpServers = mcp && typeof mcp === "object" ? Object.keys(mcp) : [];
    },
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
        throw blocked(`the OpenMoat plugin failed: ${error?.message ?? error}`);
      }
      const result = await check(payload, directory, false);
      if (result.error) throw result.error;
    },
  };
}

// OpenCode 2 (`execute.before`): `ctx` is the plugin context of the instance
// that loaded it. The tool hook is registered first: if anything after it
// cannot be set up, OpenMoat still checks every call (and blocks the asks it
// cannot put to the person).
async function setup(ctx) {
  const directory = text(ctx?.location?.directory);
  const worktree = text(ctx?.location?.project?.directory) ?? directory;
  let mcpServers = [];
  // The reason of each call OpenMoat is asking about, by the call's id.
  const asking = new Map();
  // Shell commands checked and not yet started, oldest first.
  const checkedShells = [];
  let canAsk = false;

  await ctx.tool.hook("execute.before", async (event) => {
    let payload;
    let tool;
    try {
      tool = event?.tool;
      const input = freeze(structuredClone(event?.input ?? {}));
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
      throw blocked(`the OpenMoat plugin failed: ${error?.message ?? error}`);
    }
    const result = await check(payload, directory, true);
    if (result.error) throw result.error;
    if (result.ask !== undefined) await ask(event, result.ask);
    if (tool === "shell" && typeof payload.input?.command === "string") {
      checkedShells.push(payload.input.command);
      if (checkedShells.length > MAX_CHECKED_SHELLS) checkedShells.shift();
    }
  });

  // Puts OpenMoat's ask to the person: OpenCode evaluates the session's
  // rules for the action, the `evaluate` hook below makes it an ask whatever
  // they say, and OpenCode prompts and waits. A deny rule, a rejection or no
  // way to ask rejects, which blocks the call.
  async function ask(event, reason) {
    if (!canAsk || typeof ctx?.permission?.assert !== "function") {
      throw blocked(`this needs your approval and OpenCode could not ask: ${HOW_TO_APPROVE}`);
    }
    asking.set(event.id, reason);
    try {
      await ctx.permission.assert({
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
        const at = checkedShells.indexOf(invocation?.command);
        if (at === -1) return;
        checkedShells.splice(at, 1);
        pin(invocation, "command", invocation.command);
        pin(invocation, "shell", invocation.shell);
      } catch {}
    });
  } catch {}
}

export default { id: "openmoat", server, setup };
