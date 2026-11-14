// OpenMoat as a `wrapToolCall` middleware of a LangChain.js v1 agent
// (`langchain`; types checked against langchain 1.6.6, @langchain/core 1.4.1).
//
//   import { createAgent, createMiddleware } from "langchain";
//   createAgent({ ..., middleware: [createMiddleware(openmoatMiddleware({ tools: {...} }))] })
//
// `createMiddleware` stays the app's own import, so this package needs no
// LangChain at run time. A blocked call never reaches the tool: the handler
// is given a stand-in tool that returns OpenMoat's message, which the agent's
// tool node wraps in the `ToolMessage` the model receives (the documented way
// a middleware supplies a tool, `ToolCallRequest.tool`). An allowed call runs
// with the copy of its arguments that was decided.
//
// An error inside a middleware ends the agent's run unless the tool node's
// `handleToolErrors` is `true`; either way the tool does not run.

import { createGuard } from "./guard.js";

const HOST = "langchain";

/**
 * The middleware's config, for the app's `createMiddleware`.
 * @param {import("./langchain").LangChainOptions} [options]
 */
export function openmoatMiddleware(options = {}) {
  const guard = options.guard ?? createGuard({ ...options, host: HOST });
  return {
    name: "OpenMoat",
    /**
     * @param {any} request
     * @param {(request: any) => any} handler
     */
    async wrapToolCall(request, handler) {
      const call = request.toolCall;
      const args = structuredClone(call.args ?? {});
      const outcome = await guard.check({ tool: call.name, input: args, id: call.id });
      if (outcome.run) {
        return handler({ ...request, toolCall: { ...call, args } });
      }
      const message = outcome.message;
      const blocked = {
        name: call.name,
        description: "OpenMoat blocked this call",
        invoke: async () => message,
      };
      return handler({ ...request, tool: blocked });
    },
  };
}
