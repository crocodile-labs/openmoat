// Types of @openmoat/sdk (docs/SDK.md, ADR-046). The shapes are the JSON forms
// of the Rust crate openmoat-sdk; an unknown field is an error, never ignored.

/** `allow < defer < ask < deny`.
 * - `deny`: the call must not run; no approval can lift it.
 * - `ask`: it runs only after a person approves this exact call.
 * - `defer`: your own permission flow decides; OpenMoat neither objects nor vouches.
 * - `allow`: it may run. */
export type Verdict = "allow" | "defer" | "ask" | "deny";

/** Arguments of an MCP or unknown tool call that name files, hosts or commands,
 * so the usual rules apply to them too. */
export interface Touches {
  reads?: string[];
  writes?: string[];
  /** URLs or hosts. */
  hosts?: string[];
  commands?: string[];
}

/** One tool call, before it runs. Paths are absolute or relative to `context.cwd`. */
export type Action =
  | { type: "shell"; command: string }
  | { type: "foreign_shell"; shell: string; command: string }
  | { type: "fs_read"; path: string }
  | { type: "fs_write"; path: string }
  | { type: "read_files"; paths: string[] }
  | { type: "patch"; writes: string[] }
  | { type: "net"; url: string }
  | { type: "fetch"; url: string }
  | { type: "web_search"; query: string }
  /** `opens`: the one URL a call that only opens or reads a page names (a browser's
   * `navigate`), decided like a fetch; a call that sends more names it in `hosts`. */
  | ({ type: "mcp_tool"; name: string; opens?: string[]; unchecked?: string } & Touches)
  | ({ type: "unknown_tool"; host: string; tool: string } & Touches)
  | { type: "unchecked"; action: Action; reason: string };

/** Where the agent runs. Absolute, slash-separated paths. */
export interface Context {
  home: string;
  cwd: string;
  /** The trusted project root, for `${project}`; never the home directory or a root. */
  project?: string;
  real_home?: string;
  real_project?: string;
  /** Default directory → where an environment variable moved it. */
  moved_dirs?: Record<string, string>;
  case_insensitive_paths?: boolean;
}

/** What the caller observed on its filesystem, for the checks that need it. */
export interface Facts {
  /** Program name → absolute path it resolves to on the search path the call uses. */
  programs?: Record<string, string>;
  /** Program name → path recorded at setup; anywhere else is a deny. */
  pinned?: Record<string, string>;
  /** Symlink path → target. */
  links?: Record<string, string>;
  /** Files that exist, for glob operands. */
  files?: string[];
}

export interface Decision {
  readonly verdict: Verdict;
  /** Rule ids that produced `verdict` (`secrets-paths`, `default.net`, `unparseable`). */
  readonly rules: readonly string[];
  readonly reasons: readonly string[];
  /** `reasons` joined with "; ". */
  readonly reason: string;
  /** Weaker matches that did not decide. */
  readonly context: readonly string[];
  /** A frozen copy of exactly the action decided: run this one. */
  readonly action: Readonly<Action>;
}

export class OpenMoatError extends Error {}

export class Session {
  constructor(saved?: string);
  record(engine: Engine, action: Action, facts?: Facts): void;
  save(): string;
}

export class Engine {
  decide(action: Action, options?: { facts?: Facts; session?: Session }): Decision;
  paths(action: Action): string[];
  free(): void;
  [Symbol.dispose](): void;
}

export class OpenMoat {
  readonly version: string;
  readonly policySchemaVersion: number;
  readonly defaultPolicy: string;
  compile(options: {
    policy: string;
    context: Context;
    repository?: { policy: string; trusted?: boolean };
  }): Engine;
}

export function load(options?: { wasm?: BufferSource | WebAssembly.Module }): Promise<OpenMoat>;
