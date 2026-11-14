// Types of @openmoat/sdk/mastra. Structural: assignable to `ToolHooks` of
// @mastra/core (checked against 1.83.0) without importing it.
import type { Guard, GuardOptions } from "./guard";

export interface MastraOptions extends Omit<GuardOptions, "host"> {
  guard?: Guard;
}

export interface OpenMoatToolHooks {
  beforeToolCall(context: { toolName: string; input: unknown }): Promise<
    | undefined
    | {
        proceed: false;
        output: { error: string; openmoat: { verdict: string; rules: readonly string[] } };
      }
  >;
}

export function openmoatHooks(options?: MastraOptions): OpenMoatToolHooks;
