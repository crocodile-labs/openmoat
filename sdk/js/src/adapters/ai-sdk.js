// OpenMoat around the `execute` of each tool of a Vercel AI SDK tool set
// (`ai`; types checked against ai 7.0.173, @ai-sdk/provider-utils 5.0.81).
//
//   generateText({ model, tools: withOpenMoat({ readFile, runShell }, { tools: {...} }) })
//
// A blocked call throws `OpenMoatBlockedError` from `execute` before the tool
// runs; the AI SDK turns a throwing `execute` into a `tool-error` part, which
// the model receives with OpenMoat's message on the next step. A tool runs
// with the copy of its input that was decided, never the model's object.
//
// Only tools with an `execute` are wrapped: a tool the client runs (no
// `execute`) or the provider runs is never seen. For a person's approval,
// pass `review`, or keep the SDK's own `toolApproval` for `defer`.

import { createGuard } from "./guard.js";

const HOST = "ai-sdk";

/** The error a blocked call's `execute` throws; `outcome` says why. */
export class OpenMoatBlockedError extends Error {
  /** @param {import("./guard").Outcome} outcome */
  constructor(outcome) {
    super(outcome.message);
    this.name = "OpenMoatBlockedError";
    this.outcome = outcome;
  }
}

/** @param {unknown} fn */
const isAsyncGenerator = (fn) =>
  Object.prototype.toString.call(fn) === "[object AsyncGeneratorFunction]";

/**
 * `tools` with every `execute` checked by OpenMoat first.
 * @template {Record<string, any>} T
 * @param {T} tools
 * @param {import("./ai-sdk").AiSdkOptions} [options]
 * @returns {T}
 */
export function withOpenMoat(tools, options = {}) {
  const guard = options.guard ?? createGuard({ ...options, host: HOST });
  /** @type {Record<string, any>} */
  const wrapped = {};
  for (const [name, tool] of Object.entries(tools)) {
    if (typeof tool?.execute !== "function") {
      wrapped[name] = tool;
      continue;
    }
    const execute = tool.execute;
    /** @param {unknown} input @param {{toolCallId?: string}} [execOptions] */
    const decide = async (input, execOptions) => {
      const decided = structuredClone(input);
      const outcome = await guard.check({ tool: name, input: decided, id: execOptions?.toolCallId });
      if (!outcome.run) throw new OpenMoatBlockedError(outcome);
      return decided;
    };
    // The SDK streams preliminary results only from an `execute` that returns
    // an async iterable at once, so a streaming tool stays a generator.
    wrapped[name] = {
      ...tool,
      execute: isAsyncGenerator(execute)
        ? async function* (/** @type {unknown} */ input, /** @type {any} */ execOptions) {
            yield* execute.call(tool, await decide(input, execOptions), execOptions);
          }
        : async (/** @type {unknown} */ input, /** @type {any} */ execOptions) =>
            execute.call(tool, await decide(input, execOptions), execOptions),
    };
  }
  return /** @type {T} */ (wrapped);
}
