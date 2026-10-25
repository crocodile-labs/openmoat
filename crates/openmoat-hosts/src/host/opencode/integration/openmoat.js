// OpenMoat for OpenCode. `openmoat init` writes this file to `plugins/` in
// OpenCode's configuration directory (`~/.config/opencode`, or
// `$XDG_CONFIG_HOME/opencode`) with the path of the `openmoat` binary in place
// of __MOAT_BINARY__, and pins it; do not edit the installed copy. It is an
// OpenCode 1 plugin (`opencode-ai`); OpenCode 2 does not load it.
//
// Before each tool call runs, OpenCode's `tool.execute.before` hook hands the
// call to `openmoat guard --host opencode` on stdin. A deny blocks the call
// with OpenMoat's reason, which the model sees; allow or no answer (defer)
// lets the call run as it would without OpenMoat, and OpenCode's own
// permission rules still apply. OpenCode 1 gives plugins no way to ask the
// person, so the guard answers an ask with a deny that says how to approve it.
// Any other outcome blocks the call: `openmoat` missing, a crash, an exit code
// other than 0 or 2, an answer that cannot be read, or no answer within
// GUARD_TIMEOUT_MS. OpenCode blocks the call when this hook throws, and it
// waits for the hook without a limit of its own. No dependencies.
//
// The arguments OpenMoat checked are frozen before the guard runs: OpenCode
// hands the same object to every later plugin and then to the tool, so a
// plugin loaded after this one could otherwise change a call after it was
// checked. A later change then throws, which blocks the call.

import { spawn } from "node:child_process";

const MOAT = __MOAT_BINARY__;
// Above `openmoat guard`'s own 30 s budget.
const GUARD_TIMEOUT_MS = 45_000;
const MAX_OUTPUT = 1 << 20;

function blocked(why) {
  return new Error(`OpenMoat blocked this call: ${why}`);
}

// What the guard's exit code and output mean: `undefined` to let the call
// run, else the Error that blocks it.
function answer(code, stdout, stderr) {
  const text = stdout.trim();
  if (code === 0 && text === "") return undefined;
  let reply;
  try {
    reply = JSON.parse(text);
  } catch {
    const first = stderr.trim().split("\n")[0] || "no readable answer";
    return blocked(`openmoat guard exited ${code}: ${first}`);
  }
  const reason = typeof reply?.reason === "string" ? reply.reason : "moat: no reason given";
  if (code === 0 && reply?.decision === "allow") return undefined;
  if (code === 2 && reply?.decision === "deny") return new Error(reason);
  return blocked(`openmoat guard exited ${code} with an answer it should not give: ${text}`);
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

function text(value) {
  return typeof value === "string" && value !== "" ? value : undefined;
}

export default async function openmoat(input) {
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
      let run;
      try {
        const args = freeze(output?.args ?? {});
        const payload = {
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
        run = await guard(payload, directory);
      } catch (error) {
        throw blocked(`the OpenMoat plugin failed: ${error?.message ?? error}`);
      }
      if (run.code === null) throw blocked(run.stderr);
      const error = answer(run.code, run.stdout, run.stderr);
      if (error) throw error;
    },
  };
}
