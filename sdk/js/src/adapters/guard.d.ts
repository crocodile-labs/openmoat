// Types of @openmoat/sdk/guard: what every framework adapter shares
// (docs/SDK.md "Framework adapters").
import type { Action, Context, Decision, Engine, Facts, OpenMoat, Session, Verdict } from "../index";

/** One tool call as a framework hands it over, before it runs. */
export interface ToolCall {
  /** The tool's name as the model called it. */
  tool: string;
  /** The tool's input, as the framework parsed it. */
  input: unknown;
  /** The framework's id for this call, for `onDecision`. */
  id?: string;
  /** The directory the call runs in, when the framework says (Claude Agent SDK). */
  cwd?: string;
  /** The action to decide, when the adapter already knows it. */
  action?: Action;
}

/** What the guard made of one call. `run: false` means the tool must not run. */
export interface Outcome {
  run: boolean;
  verdict: Verdict;
  rules: readonly string[];
  reason: string;
  /** What the model is told when the call does not run; empty when it runs. */
  message: string;
  action?: Readonly<Action>;
  /** The facts the decision was made with. */
  facts?: Facts;
  decision?: Decision;
  /** `true` or `false` when a reviewer answered. */
  approved?: boolean;
  /** Why no decision was made; the call did not run. */
  error?: unknown;
  /** Milliseconds the engine took to decide. */
  decideMs: number;
  /** Milliseconds the whole check took, a reviewer's wait included. */
  ms: number;
}

export interface DecisionEvent extends Outcome {
  host: string;
  tool: string;
  id?: string;
}

/** A reviewer: `true` only when a person approved this exact call. */
export type Reviewer = (call: ToolCall & { decision: Decision }) => boolean | Promise<boolean>;

/** Input of one tool → the action OpenMoat decides for it. Throw when it cannot say. */
export type Describe = (input: unknown) => Action;

export interface GuardOptions {
  /** The name unknown tools are decided under (`unknown_tool`'s `host`). */
  host?: string;
  /** A loaded module; default `load()`. */
  openmoat?: OpenMoat | Promise<OpenMoat>;
  /** Policy YAML; default the shipped default policy. */
  policy?: string;
  repository?: { policy: string; trusted?: boolean };
  /** Default: this process's home and working directory (`nodeContext`). Needed outside Node. */
  context?: Context;
  /** How each tool's input becomes an action; tools not named are unknown tools whose path-like strings are checked as reads. */
  tools?: Record<string, Describe>;
  /** Default: links resolved on this disk (`nodeFacts`); `false` for none (outside Node). */
  facts?: false | ((engine: Engine, action: Action) => Facts | Promise<Facts>);
  /** Asked for `review` (and `defer` with `defer: "review"`). Without one, those calls do not run. */
  review?: Reviewer;
  /** `"allow"` (default): a `defer` goes to the framework's own approval flow, if it has one. `"review"`: treated as `review`. */
  defer?: "allow" | "review";
  /** Called after every check, with the outcome and its timing. Its errors are ignored. */
  onDecision?: (event: DecisionEvent) => void;
  /** Continue an earlier session. */
  session?: Session;
}

export interface Guard {
  readonly host: string;
  /** Calls checked, let through, blocked, failed; total and slowest milliseconds. */
  readonly stats: {
    calls: number;
    ran: number;
    blocked: number;
    errors: number;
    totalMs: number;
    maxMs: number;
  };
  readonly session: Session;
  /** Decide one call. Never throws: an error is `run: false`. */
  check(call: ToolCall): Promise<Outcome>;
  /** Record a held call the framework's own approval may still run. */
  record(call: ToolCall, outcome: Outcome): Promise<void>;
  /** Load and compile now rather than on the first call; rejects if that fails. */
  ready(): Promise<void>;
  free(): void;
}

export function createGuard(options?: GuardOptions): Guard;
export function field(input: unknown, key: string): string;
export const describe: {
  shell(key?: string): Describe;
  read(key?: string): Describe;
  write(key?: string): Describe;
  fetch(key?: string): Describe;
  net(key?: string): Describe;
  search(key?: string): Describe;
};
export function pathsIn(input: unknown): { paths: string[]; unchecked?: string };
export function unknownTool(host: string, tool: string, input: unknown): Action;
export function nodeContext(cwd?: string): Promise<Context>;
export function nodeFacts(): Promise<(engine: Engine, action: Action) => Facts>;
