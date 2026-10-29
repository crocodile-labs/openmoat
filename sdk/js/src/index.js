// OpenMoat's policy decisions for JavaScript: the Rust engine compiled to
// WebAssembly (crates/openmoat-wasm), behind a typed API. docs/SDK.md, ADR-046.
//
// Types are in index.d.ts.
//
// The module imports nothing, so it cannot reach a network, a clock or a file.
// This file reads the module from disk only when `load()` is given no bytes.
// No telemetry: nothing here sends anything anywhere.
//
// The SDK decides; enforcement is the caller's. A call it denies must not run,
// and an `ask` must not run until a person approves that exact call.

/** The request protocol version this wrapper speaks (`ABI_VERSION` in Rust). */
const ABI = 1;

/** Characters JSON may hold raw but a YAML 1.2 stream may not (the module
 * reads JSON with the core's YAML 1.2 reader); `JSON.stringify` already
 * escapes C0 controls. Keep in step with `not_yaml_printable` in json.rs. */
const NOT_YAML_PRINTABLE = /[\u007f-\u009f﻿￾￿]/g;

/** An input OpenMoat cannot use, or a module that can no longer answer.
 * Whatever the cause, the call in hand has no decision: do not run it. */
export class OpenMoatError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = "OpenMoatError";
  }
}

/** @param {unknown} value */
function deepFreeze(value) {
  if (value && typeof value === "object") {
    for (const inner of Object.values(value)) deepFreeze(inner);
    Object.freeze(value);
  }
  return value;
}

/** One instance of the module, and the request/response exchange with it. */
class Module {
  /** @param {WebAssembly.Instance} instance */
  constructor(instance) {
    const e = /** @type {any} */ (instance.exports);
    /** @type {WebAssembly.Memory} */
    this.memory = e.memory;
    /** @type {(len: number) => number} */
    this.input = e.openmoat_input;
    /** @type {() => number} */
    this.call = e.openmoat_call;
    /** @type {() => number} */
    this.output = e.openmoat_output;
    /** @type {string | null} */
    this.broken = null;
    this.encoder = new TextEncoder();
    this.decoder = new TextDecoder("utf-8", { fatal: true });
  }

  /**
   * Send one request; the `ok` value of the answer.
   * @param {object} request
   * @returns {any}
   */
  request(request) {
    if (this.broken) throw new OpenMoatError(this.broken);
    const text = JSON.stringify(request).replace(
      NOT_YAML_PRINTABLE,
      (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
    );
    const bytes = this.encoder.encode(text);
    let answer;
    try {
      const at = this.input(bytes.length);
      if (at === 0) throw new OpenMoatError("request too large");
      // Views are taken after each call: the module's memory may have grown.
      new Uint8Array(this.memory.buffer, at, bytes.length).set(bytes);
      const len = this.call();
      const out = new Uint8Array(this.memory.buffer, this.output(), len);
      answer = JSON.parse(this.decoder.decode(out));
    } catch (error) {
      if (error instanceof OpenMoatError) throw error;
      // A trap leaves the module's state unknown: it never decides again.
      this.broken = `the OpenMoat module failed and was disabled: ${error}`;
      throw new OpenMoatError(this.broken);
    }
    if (typeof answer.error === "string") throw new OpenMoatError(answer.error);
    return answer.ok;
  }
}

/** One agent session's history, as far as later decisions need it. Record each
 * call after it ran; pass the session to `Engine.decide`. */
export class Session {
  /** @param {string} [saved] what `save()` returned, to continue a session */
  constructor(saved) {
    if (saved !== undefined && typeof saved !== "string") {
      throw new OpenMoatError("a saved session is the string save() returned");
    }
    /** @type {string | undefined} The module's opaque state; empty when fresh. */
    this.state = saved || undefined;
  }

  /**
   * Note that `action` ran, as `engine` decided it with `facts`. Record only
   * calls that really ran.
   * @param {Engine} engine
   * @param {import("./index").Action} action
   * @param {import("./index").Facts} [facts]
   */
  record(engine, action, facts) {
    this.state = engine.module.request({
      op: "record",
      engine: engine.handle(),
      action,
      facts,
      session: this.state,
    }).session;
  }

  /** The session as opaque text, for `new Session(saved)` in another process. */
  save() {
    return this.state ?? "";
  }
}

const released = new FinalizationRegistry(
  /** @param {{module: Module, handle: number}} held */
  ({ module, handle }) => {
    if (!module.broken) module.request({ op: "release", engine: handle });
  },
);

/** A policy compiled for one context. Keep it: compiling dominates the cost. */
export class Engine {
  /**
   * @param {Module} module
   * @param {number} handle
   */
  constructor(module, handle) {
    this.module = module;
    /** @type {number | null} */
    this.id = handle;
    released.register(this, { module, handle }, this);
  }

  /** @returns {number} */
  handle() {
    if (this.id === null) throw new OpenMoatError("this engine was freed");
    return this.id;
  }

  /**
   * Decide `action`. The result carries `action`: a frozen copy of exactly
   * what was decided. Run that, never a value rebuilt from it afterwards.
   * @param {import("./index").Action} action
   * @param {{facts?: import("./index").Facts, session?: Session}} [options]
   * @returns {import("./index").Decision}
   */
  decide(action, options = {}) {
    const decided = deepFreeze(JSON.parse(JSON.stringify(action)));
    const d = this.module.request({
      op: "decide",
      engine: this.handle(),
      action: decided,
      facts: options.facts,
      session: options.session?.state,
    });
    return deepFreeze({
      verdict: d.verdict,
      rules: d.rules,
      reasons: d.reasons,
      reason: d.reasons.join("; "),
      context: d.context,
      action: decided,
    });
  }

  /**
   * The absolute paths `action` reads or writes, to resolve and report as
   * `facts.links` before deciding.
   * @param {import("./index").Action} action
   * @returns {string[]}
   */
  paths(action) {
    return this.module.request({ op: "paths", engine: this.handle(), action }).paths;
  }

  /** Release the compiled policy now rather than when collected. */
  free() {
    if (this.id === null) return;
    released.unregister(this);
    const handle = this.id;
    this.id = null;
    if (!this.module.broken) this.module.request({ op: "release", engine: handle });
  }

  [Symbol.dispose]() {
    this.free();
  }
}

/** A loaded module: compile policies into engines. */
export class OpenMoat {
  /** @param {Module} module */
  constructor(module) {
    this.module = module;
    const info = module.request({ op: "info" });
    if (info.abi !== ABI) {
      throw new OpenMoatError(`module speaks protocol ${info.abi}; this wrapper speaks ${ABI}`);
    }
    /** The OpenMoat release the module was built from. */
    this.version = /** @type {string} */ (info.version);
    /** The policy schema version (`version:` in a policy) it reads. */
    this.policySchemaVersion = /** @type {number} */ (info.policy_schema_version);
    /** The shipped default policy, as YAML. */
    this.defaultPolicy = /** @type {string} */ (module.request({ op: "default_policy" }).policy);
  }

  /**
   * Compile `policy` (YAML text) for `context`, with a repository policy
   * merged in when `repository` is given.
   * @param {{policy: string, context: import("./index").Context,
   *   repository?: {policy: string, trusted?: boolean}}} options
   * @returns {Engine}
   */
  compile({ policy, context, repository }) {
    const { engine } = this.module.request({ op: "compile", policy, context, repository });
    return new Engine(this.module, engine);
  }
}

/**
 * Load the module. With no `wasm`, it is read from `dist/openmoat.wasm` beside
 * this package (Node); in a browser or bundler, pass the bytes or a compiled
 * `WebAssembly.Module`.
 * @param {{wasm?: BufferSource | WebAssembly.Module}} [options]
 * @returns {Promise<OpenMoat>}
 */
export async function load(options = {}) {
  let wasm = options.wasm;
  if (wasm === undefined) {
    const { readFile } = await import("node:fs/promises");
    wasm = await readFile(new URL("../dist/openmoat.wasm", import.meta.url));
  }
  const compiled = wasm instanceof WebAssembly.Module ? wasm : await WebAssembly.compile(wasm);
  if (WebAssembly.Module.imports(compiled).length !== 0) {
    throw new OpenMoatError("not OpenMoat's module: it imports from its host");
  }
  const instance = await WebAssembly.instantiate(compiled, {});
  return new OpenMoat(new Module(instance));
}
