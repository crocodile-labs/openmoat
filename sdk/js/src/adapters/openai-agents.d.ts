// Types of @openmoat/sdk/openai-agents. Structural: assignable to
// `ToolInputGuardrailDefinition` of @openai/agents-core (checked against
// 0.22.0) without importing it.
import type { Guard, GuardOptions } from "./guard";

type GuardrailAnswer =
  | { type: "allow" }
  | { type: "rejectContent"; message: string }
  | { type: "throwException" };

export interface OpenMoatToolGuardrail {
  type: "tool_input";
  name: string;
  run(data: {
    toolCall: { name: string; arguments: string; callId?: string };
  }): Promise<{ outputInfo?: unknown; behavior: GuardrailAnswer }>;
}

export interface OpenAIOptions extends Omit<GuardOptions, "host"> {
  /** `"reject"` (default): the model gets the message. `"throw"`: the run ends. */
  block?: "reject" | "throw";
  guard?: Guard;
}

export function openmoatGuardrail(options?: OpenAIOptions): OpenMoatToolGuardrail;
export function withOpenMoat<T extends { type: string }>(tools: T[], options?: OpenAIOptions): T[];
