// Types of @openmoat/sdk/ai-sdk. `withOpenMoat` returns the tool set it is
// given, typed as it was (checked against ai 7.0.173).
import type { Guard, GuardOptions, Outcome } from "./guard";

export interface AiSdkOptions extends Omit<GuardOptions, "host"> {
  guard?: Guard;
}

export class OpenMoatBlockedError extends Error {
  readonly outcome: Outcome;
}

export function withOpenMoat<T extends Record<string, any>>(tools: T, options?: AiSdkOptions): T;
