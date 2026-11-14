// What every framework adapter shares (docs/SDK.md "Framework adapters"): one
// engine per working directory, one session, the verdict handling of
// docs/SDK.md "Handling a verdict", and the time each decision took.
//
// The adapters decide; the framework enforces. Each adapter only lets a call
// through when `check` says `run: true`, and turns every other outcome into the
// framework's way of not running a tool and telling the model why.
//
// Errors never let a call through: a call OpenMoat holds no decision for does
// not run (`check` never throws; it answers `run: false`).

import { load, OpenMoatError, Session } from "../index.js";

/** How far `pathsIn` searches a tool's input before it gives up. */
const SCAN = { depth: 32, strings: 1024 };

/** A string that starts at a filesystem root, a drive or `~`: the look of a path. */
const PATH_LIKE = /^(\/|~(\/|$)|[A-Za-z]:[\\/])/;

/** Milliseconds, from a clock that only goes forward where there is one. */
const now = () => globalThis.performance?.now() ?? Date.now();

/**
 * The string under `key` in `input`; an error when there is none, so a call
 * without the field the tool needs is never decided as an empty one.
 * @param {unknown} input
 * @param {string} key
 */
export function field(input, key) {
  const value = /** @type {any} */ (input)?.[key];
  if (typeof value !== "string") {
    throw new OpenMoatError(`the tool's input has no string "${key}"`);
  }
  return value;
}

/** Describe a tool by the input field that holds what it touches. */
export const describe = {
  /** @param {string} [key] */
  shell: (key = "command") => (/** @type {unknown} */ input) => ({ type: "shell", command: field(input, key) }),
  /** @param {string} [key] */
  read: (key = "path") => (/** @type {unknown} */ input) => ({ type: "fs_read", path: field(input, key) }),
  /** @param {string} [key] */
  write: (key = "path") => (/** @type {unknown} */ input) => ({ type: "fs_write", path: field(input, key) }),
  /** @param {string} [key] */
  fetch: (key = "url") => (/** @type {unknown} */ input) => ({ type: "fetch", url: field(input, key) }),
  /** @param {string} [key] */
  net: (key = "url") => (/** @type {unknown} */ input) => ({ type: "net", url: field(input, key) }),
  /** @param {string} [key] */
  search: (key = "query") => (/** @type {unknown} */ input) => ({ type: "web_search", query: field(input, key) }),
};

/**
 * Every string in `input` that looks like a path (starts at a root, a drive or
 * `~`), and why the search stopped early when it did.
 * @param {unknown} input
 * @returns {{paths: string[], unchecked?: string}}
 */
export function pathsIn(input) {
  /** @type {string[]} */
  const paths = [];
  let strings = 0;
  /** @type {Array<[unknown, number]>} */
  const stack = [[input, 0]];
  while (stack.length > 0) {
    const [value, depth] = /** @type {[unknown, number]} */ (stack.pop());
    if (typeof value === "string") {
      strings += 1;
      if (strings > SCAN.strings) {
        return { paths, unchecked: `the input holds more than ${SCAN.strings} strings` };
      }
      if (PATH_LIKE.test(value) && !paths.includes(value)) paths.push(value);
    } else if (value && typeof value === "object") {
      if (depth >= SCAN.depth) {
        return { paths, unchecked: `the input nests deeper than ${SCAN.depth} levels` };
      }
      for (const inner of Object.values(value)) stack.push([inner, depth + 1]);
    }
  }
  return { paths };
}

/**
 * A tool OpenMoat has no description for: decided as an unknown tool of
 * `host`, with every path its input names checked as a read, so a secret path
 * is denied whatever the tool is called.
 * @param {string} host
 * @param {string} tool
 * @param {unknown} input
 * @returns {import("../index").Action}
 */
export function unknownTool(host, tool, input) {
  const { paths, unchecked } = pathsIn(input);
  /** @type {import("../index").Action} */
  const action = { type: "unknown_tool", host, tool, ...(paths.length ? { reads: paths } : {}) };
  return unchecked ? { type: "unchecked", action, reason: unchecked } : action;
}

/** @param {string} path */
const slash = (path) => path.replaceAll("\\", "/");

/**
 * The context of this process, for `cwd`: the home directory, the working
 * directory as the project unless it is the home directory, one of its
 * ancestors or a root, their real locations, and the platform's file-name case.
 * @param {string} [cwd]
 * @returns {Promise<import("../index").Context>}
 */
export async function nodeContext(cwd) {
  const [{ homedir }, { realpathSync }] = await Promise.all([import("node:os"), import("node:fs")]);
  const home = slash(homedir());
  const dir = slash(cwd ?? process.cwd());
  /** @param {string} path */
  const real = (path) => {
    try {
      return slash(realpathSync(path));
    } catch {
      return path;
    }
  };
  /** @type {import("../index").Context} */
  const context = {
    home,
    cwd: dir,
    case_insensitive_paths: process.platform === "darwin" || process.platform === "win32",
  };
  if (real(home) !== home) context.real_home = real(home);
  const trimmed = dir.replace(/\/+$/, "");
  const isRoot = /^([A-Za-z]:)?$/.test(trimmed);
  if (!isRoot && dir !== home && !`${home}/`.startsWith(`${trimmed}/`)) {
    context.project = dir;
    if (real(dir) !== dir) context.real_project = real(dir);
  }
  return context;
}

/**
 * Facts from this machine's disk: each path an action reads or writes that
 * leads somewhere else through a link, so it is also checked where it leads.
 * @returns {Promise<(engine: import("../index").Engine, action: import("../index").Action) => import("../index").Facts>}
 */
export async function nodeFacts() {
  const { existsSync, realpathSync } = await import("node:fs");
  const { basename, dirname, join } = await import("node:path");
  /** @param {string} path */
  const resolved = (path) => {
    const rest = [];
    let existing = path;
    while (!existsSync(existing)) {
      rest.unshift(basename(existing));
      const parent = dirname(existing);
      if (parent === existing) return null;
      existing = parent;
    }
    const real = slash(join(realpathSync(existing), ...rest));
    return real === path ? null : real;
  };
  return (engine, action) => {
    /** @type {Record<string, string>} */
    const links = {};
    for (const path of engine.paths(action)) {
      const real = resolved(path);
      if (real) links[path] = real;
    }
    return { links };
  };
}

/** @param {readonly string[]} rules */
const named = (rules) => (rules.length ? ` (${rules.join(", ")})` : "");

/**
 * A guard over one policy: decides each tool call, asks a reviewer when one is
 * configured, records what it lets through, and times every decision.
 * @param {import("./guard").GuardOptions} [options]
 * @returns {import("./guard").Guard}
 */
export function createGuard(options = {}) {
  const host = options.host ?? "sdk";
  const session = options.session ?? new Session();
  const stats = { calls: 0, ran: 0, blocked: 0, errors: 0, totalMs: 0, maxMs: 0 };
  /** @type {Promise<{openmoat: import("../index").OpenMoat, facts: Function}> | undefined} */
  let loaded;
  /** @type {Map<string, import("../index").Engine>} */
  const engines = new Map();

  // Loading and compiling are pure, so a failure is not retried: every later
  // call is refused the same way.
  const setup = () =>
    (loaded ??= (async () => {
      const openmoat = await (options.openmoat ?? load());
      const facts =
        options.facts === false ? () => ({}) : (options.facts ?? (await nodeFacts()));
      return { openmoat, facts };
    })());

  /** @param {string | undefined} cwd */
  async function engineFor(cwd) {
    const { openmoat, facts } = await setup();
    const key = options.context ? "" : (cwd ?? "");
    let engine = engines.get(key);
    if (!engine) {
      const context = options.context ?? (await nodeContext(cwd));
      engine = openmoat.compile({
        policy: options.policy ?? openmoat.defaultPolicy,
        context,
        repository: options.repository,
      });
      engines.set(key, engine);
    }
    return { engine, facts };
  }

  /** @param {import("./guard").ToolCall} call */
  function actionOf(call) {
    if (call.action) return call.action;
    const describeTool = options.tools?.[call.tool];
    return describeTool ? describeTool(call.input) : unknownTool(host, call.tool, call.input);
  }

  /**
   * @param {import("./guard").ToolCall} call
   * @param {import("../index").Decision} decision
   * @returns {Promise<{run: boolean, message: string, approved?: boolean}>}
   */
  async function settle(call, decision) {
    const { verdict, rules, reason } = decision;
    const held = `OpenMoat holds this tool call for a person's review${named(rules)}: ${reason}.`;
    const asksPerson =
      verdict === "review" || (verdict === "defer" && options.defer === "review");
    if (verdict === "allow" || (verdict === "defer" && options.defer !== "review")) {
      return { run: true, message: "" };
    }
    if (asksPerson) {
      if (!options.review) {
        return { run: false, message: `${held} No person can approve it here, so it did not run.` };
      }
      const approved = (await options.review({ ...call, decision })) === true;
      return approved
        ? { run: true, message: "", approved }
        : { run: false, message: `${held} A person did not approve it, so it did not run.`, approved };
    }
    // `deny`, and any verdict this version does not know.
    return {
      run: false,
      message: `OpenMoat blocked this tool call${named(rules)}: ${reason}. It did not run.`,
    };
  }

  /** @param {import("./guard").ToolCall} call */
  async function check(call) {
    const started = now();
    /** @type {import("./guard").Outcome} */
    let outcome;
    try {
      const { engine, facts } = await engineFor(call.cwd);
      const action = actionOf(call);
      const observed = await facts(engine, action);
      const deciding = now();
      const decision = engine.decide(action, { facts: observed, session });
      const decideMs = now() - deciding;
      const settled = await settle(call, decision);
      // Recorded when let through, before it runs: taint only ever tightens,
      // so a call that then fails or is refused makes later calls stricter,
      // never looser.
      if (settled.run) session.record(engine, decision.action, observed);
      outcome = {
        ...settled,
        verdict: decision.verdict,
        rules: decision.rules,
        reason: decision.reason,
        action: decision.action,
        facts: observed,
        decision,
        decideMs,
        ms: 0,
      };
    } catch (error) {
      const why = error instanceof Error ? error.message : String(error);
      outcome = {
        run: false,
        verdict: "deny",
        rules: [],
        reason: why,
        message: `OpenMoat could not decide this tool call (${why}), so it did not run.`,
        error,
        decideMs: 0,
        ms: 0,
      };
      stats.errors += 1;
    }
    outcome.ms = now() - started;
    stats.calls += 1;
    stats[outcome.run ? "ran" : "blocked"] += 1;
    stats.totalMs += outcome.ms;
    stats.maxMs = Math.max(stats.maxMs, outcome.ms);
    try {
      options.onDecision?.({ host, tool: call.tool, id: call.id, ...outcome });
    } catch {
      // An observer that fails never changes what was decided.
    }
    return outcome;
  }

  return {
    host,
    stats,
    session,
    check,
    /**
     * Record a call `check` held that the framework's own approval may still
     * run (Claude Agent SDK `review: "ask"`), so a run it gets is not missed.
     * @param {import("./guard").ToolCall} call
     * @param {import("./guard").Outcome} outcome
     */
    async record(call, outcome) {
      if (!outcome.action) return;
      const { engine } = await engineFor(call.cwd);
      session.record(engine, outcome.action, outcome.facts);
    },
    ready: async () => {
      await engineFor(undefined);
    },
    free() {
      for (const engine of engines.values()) engine.free();
      engines.clear();
    },
  };
}
