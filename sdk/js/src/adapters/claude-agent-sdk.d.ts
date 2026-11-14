// Types of @openmoat/sdk/claude-agent-sdk. Structural: assignable to the
// Claude Agent SDK's `HookCallbackMatcher` and `Options["hooks"]` (checked
// against @anthropic-ai/claude-agent-sdk 0.3.325) without importing it.
import type { Action } from "../index";
import type { Describe, Guard, GuardOptions } from "./guard";

/** The fields of a hook input this adapter reads. */
export interface ClaudeHookInput {
  hook_event_name: string;
  tool_name?: string;
  tool_input?: unknown;
  cwd?: string;
  permission_mode?: string;
}

export interface ClaudeHookOutput {
  hookSpecificOutput?: {
    hookEventName: "PreToolUse";
    permissionDecision: "deny" | "ask";
    permissionDecisionReason: string;
  };
}

export type HookCallback = (
  input: ClaudeHookInput,
  toolUseID: string | undefined,
  options: { signal: AbortSignal },
) => Promise<ClaudeHookOutput>;

export interface OpenMoatMatcher {
  hooks: HookCallback[];
  onFailure: "block";
  timeout?: number;
}

export interface ClaudeOptions extends Omit<GuardOptions, "host" | "review"> {
  /** A person's approval for `review`; or `"ask"` to return `permissionDecision: "ask"`,
   * which the app's `canUseTool` answers (never in `bypassPermissions` or `dontAsk`). */
  review?: GuardOptions["review"] | "ask";
  /** Override how a tool's input becomes an action. */
  tools?: Record<string, Describe>;
  /** Seconds the SDK waits for the callback; default the SDK's 600. */
  timeout?: number;
  /** Share one guard (its session and stats) between adapters. */
  guard?: Guard;
}

export function claudeToolAction(tool: string, input: unknown, cwd?: string): Action;
export function openmoatPreToolUse(options?: ClaudeOptions): OpenMoatMatcher;
export function openmoatHooks(options?: ClaudeOptions): { PreToolUse: OpenMoatMatcher[] };
