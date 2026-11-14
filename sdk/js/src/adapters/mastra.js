// OpenMoat as the `beforeToolCall` hook of a Mastra agent (@mastra/core;
// types checked against 1.83.0).
//
//   new Agent({ ..., hooks: openmoatHooks({ tools: {...} }) })
//
// A blocked call returns `{ proceed: false, output }`: the tool does not run,
// and `output`, `{ error: <OpenMoat's message>, openmoat: {...} }`, is the
// tool result the model receives. A hook that throws fails the call too
// (Mastra calls the hook inside the tool's `execute`).
//
// Hooks passed to one `generate`/`stream` call are merged over the agent's,
// so a run that sets its own `beforeToolCall` replaces OpenMoat's for that
// run: add `openmoatHooks()` there too. `requireApproval` still applies to
// calls OpenMoat lets through.

import { createGuard } from "./guard.js";

const HOST = "mastra";

/**
 * `hooks` for a Mastra `Agent` (or one run).
 * @param {import("./mastra").MastraOptions} [options]
 */
export function openmoatHooks(options = {}) {
  const guard = options.guard ?? createGuard({ ...options, host: HOST });
  return {
    /** @param {{toolName: string, input: unknown}} context */
    async beforeToolCall({ toolName, input }) {
      const outcome = await guard.check({ tool: toolName, input });
      if (outcome.run) return undefined;
      return {
        proceed: /** @type {const} */ (false),
        output: {
          error: outcome.message,
          openmoat: { verdict: outcome.verdict, rules: outcome.rules },
        },
      };
    },
  };
}
