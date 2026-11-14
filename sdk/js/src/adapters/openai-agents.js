// OpenMoat as a tool input guardrail of the OpenAI Agents SDK for JavaScript
// (@openai/agents; types checked against @openai/agents-core 0.22.0).
//
//   tool({ ..., inputGuardrails: [openmoatGuardrail()] })
//   new MCPServerStdio({ ..., toolInputGuardrails: [openmoatGuardrail()] })
//   new Agent({ tools: withOpenMoat([readFile, runShell], { tools: {...} }) })
//
// A blocked call answers `rejectContent`: the tool does not run and the model
// receives OpenMoat's message as the call's output. With `block: "throw"` it
// answers `throwException` instead, which ends the run with
// `ToolInputGuardrailTripwireTriggered`.
//
// Tool input guardrails run only for function tools and local MCP servers'
// tools. Hosted tools, `ShellTool`, `ApplyPatchTool`, `ComputerTool` and
// handoffs never reach them; `withOpenMoat` leaves those tools as they are.

import { createGuard } from "./guard.js";

const HOST = "openai-agents";

/**
 * A tool input guardrail.
 * @param {import("./openai-agents").OpenAIOptions} [options]
 */
export function openmoatGuardrail(options = {}) {
  const guard = options.guard ?? createGuard({ ...options, host: HOST });
  return {
    type: /** @type {const} */ ("tool_input"),
    name: "openmoat",
    /** @param {{toolCall: {name: string, arguments: string, callId?: string}}} data */
    async run({ toolCall }) {
      let input;
      try {
        input = JSON.parse(toolCall.arguments || "{}");
      } catch {
        input = undefined;
      }
      const outcome =
        input === undefined
          ? await guard.check({
              tool: toolCall.name,
              input: toolCall.arguments,
              id: toolCall.callId,
              action: { type: "unchecked", action: { type: "unknown_tool", host: HOST, tool: toolCall.name }, reason: "its arguments are not JSON" },
            })
          : await guard.check({ tool: toolCall.name, input, id: toolCall.callId });
      const outputInfo = { verdict: outcome.verdict, rules: outcome.rules, ms: outcome.ms };
      if (outcome.run) return { outputInfo, behavior: { type: /** @type {const} */ ("allow") } };
      return options.block === "throw"
        ? { outputInfo: { ...outputInfo, message: outcome.message }, behavior: { type: /** @type {const} */ ("throwException") } }
        : { outputInfo, behavior: { type: /** @type {const} */ ("rejectContent"), message: outcome.message } };
    },
  };
}

/**
 * `tools` with OpenMoat's guardrail added to every function tool.
 * @template {{type: string}} T
 * @param {T[]} tools
 * @param {import("./openai-agents").OpenAIOptions} [options]
 * @returns {T[]}
 */
export function withOpenMoat(tools, options = {}) {
  const guardrail = openmoatGuardrail(options);
  return tools.map((tool) =>
    tool.type === "function"
      ? { ...tool, inputGuardrails: [.../** @type {any} */ (tool).inputGuardrails ?? [], guardrail] }
      : tool,
  );
}
