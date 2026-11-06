# ADR-063: Injected input for more agents, and safe normalised links

Status: proposed · Date: 2026-11-06 · Builds on ADR-020, ADR-029, ADR-057 and ADR-058

## Context

ADR-057 links a later call to what untrusted output said. A fetched page, an issue read
with `gh` or an MCP result names a host, a path or a command, and a call that uses it
needs review (`injected-input`). It has two limits, both listed in ADR-057 "Limits":

- **Only Claude Code.** The check needs the call's output. Only Claude Code's
  `PostToolUse` (and the Continue CLI, which runs Claude Code's hooks) is installed. Every
  other host's HOST.md says "OpenMoat does not install … so it never sees what a call
  returned; only session taint applies". Ten of the twelve hosts are without it.
- **Exact matches only.** A planted host spelled another way (a subdomain of it, a numeric
  IPv4 form, a trailing dot, upper case) or a command re-quoted or re-ordered is not
  linked.

Prompt injection is the most common way an agent is turned (OWASP ASI01, "agent goal
hijack"). On the agents OpenMoat cannot sandbox (hook-only, THREAT_MODEL §5), this link is
one of the few checks that looks at *what* came in rather than *that* something came in.

What the repository shows today about each host's after-call event:

| Host | After-call event | In the repo | Install today | Blocking? (from HOST.md, else unverified) |
|---|---|---|---|---|
| Claude Code | `PostToolUse` (`tool_response`) | fixtures `post-tool-use-{bash,mcp,webfetch}.json`, parser | installed (ADR-057) | no; 60 s |
| Continue CLI | Claude Code's `PostToolUse` | via Claude Code | inherits | as Claude Code |
| Cline | `PostToolUse` (`hookName: "tool_result"`, `tool_result`) | fixture `cline/fixtures/tool_result.json`; parser returns `WrongEvent` | not installed | unverified |
| Codex | `PostToolUse` | named in ADR-057 only, no fixture | not installed | unverified |
| Gemini CLI | `AfterTool` | named in ADR-057 only, no fixture | not installed | unverified |
| GitHub Copilot CLI | `postToolUse` | named in ADR-057 only, no fixture | not installed | unverified |
| Cursor | `afterShellExecution`, `afterMCPExecution` | named in ADR-057 only, no fixture | not installed | unverified |
| goose | `PostToolUse` (plugin `hooks.json`) | named in HOST.md only, no fixture | not installed | unverified |
| Hermes Agent | `post_tool_call` | named in HOST.md only, no fixture | not installed | unverified |
| OpenCode | `tool.execute.after` (plugin) | named in HOST.md only, no fixture | plugin does not handle it | unverified |
| pi | `tool_result` (extension) | named in HOST.md only, no fixture | extension does not handle it | unverified |
| OpenClaw | `after_tool_call` (plugin) | named in HOST.md only, no fixture | plugin does not handle it | unverified |

Two sources see results without any host event:

- **The MCP gateway** (ADR-045, ADR-058) already reads every result of a wrapped server to
  hashed *pieces* for `mcp-cross-server`, whatever the agent.
- **`openmoat run`'s proxy** sees which hosts a session reached, and response bodies only
  inside a terminated tunnel (ADR-043). It does not read bodies otherwise.

## Decision

What this adds is tracking, not a new enforcement point: an after-call hook cannot stop
the call that produced the output, and on some hosts it cannot hold the agent at all. It
records which hosts, paths and commands untrusted output named, so that a *later* call
that uses one needs review at the pre-call hook, which is where OpenMoat already decides.
Where a host's after-call event is missing, broken or skipped, that later call is decided
exactly as today (session taint still applies).

1. **One event, every host that has one.** Each host adapter maps its after-call payload to
   the existing `HookEvent::PostToolUse { output }`: every string of the host's result
   field, joined by newlines, cut at `MAX_INJECTED_SCAN_BYTES` (1 MiB). Nothing else in the
   guard changes: `post_tool_use::answer` already checks the lock, places the request,
   decides whether the source is untrusted (`output_source`, ADR-057 §1) and keeps keyed
   fingerprints (ADR-057 §3). The one new code per host is its parser and its install
   entry.
   - Command hooks (Cline, Codex, Gemini CLI, Copilot CLI, Cursor, goose, Hermes Agent):
     an after-call entry beside the existing pre-call one, matched to the tools whose
     output can be untrusted (shell, fetch, search, MCP) where the host has matchers.
   - Plugin hosts (OpenCode, pi, OpenClaw): the plugin handles the after event, filters to
     the same tools in JavaScript before it starts a process, and writes the payload to
     `openmoat guard --host <id>`'s stdin, never its arguments (no output in `ps`).
2. **Never block, never lose the call's record.** An after-call hook runs after the call.
   Its answer is empty whatever happens. A failure is written to stderr where the host
   shows it (as ADR-057 §5) and the session keeps its taint, which the pre-call row already
   set. Where a host blocks on an after-call hook, the entry's timeout is the host's
   minimum. A host whose after-call hook would hold the agent's turn for the process start
   is listed in its HOST.md with the measured cost (the `guard latency` CI job gains a
   `post-tool-use` case).
3. **The gateway feeds the same table.** For a wrapped server, the gateway already reads
   each result. It also computes ADR-057's tokens (`injected_tokens`) for it and stores the
   fingerprints under the hook decision's host and session, source named
   `MCP server <name>`. That covers MCP output for every agent, the hook-only ones
   included, without any host event. ADR-058's `mcp_flow` table is unchanged.
4. **Links beyond exact, only where the rewrite is the same request.** Each normalisation
   is applied both when a token is kept and when a call is checked, inside
   `openmoat-core` (pure, no new dependency):
   - **Hosts:** lower case, trailing dot removed, IPv4 numeric forms read the way the URL
     Standard reads them (already done for `net` atoms), IPv6 compressed. A kept URL host
     also links a call to any of its subdomains. A call checks its host and each parent
     domain down to two labels, one probe each. A parent that is on the policy's allow list
     or is the source call's own host is skipped, so `docs.github.com` named by a page on
     `github.com` links nothing new.
   - **Commands:** the classifier's canonical form, which ADR-057 already compares, plus the
     same command after removing leading `VAR=value` assignments and a wrapping `sh -c`,
     `bash -c`, `env`, `sudo` or `nohup`. Flags are not re-ordered and words are not
     dropped: `rm -rf x` and `rm -r -f x` stay different, as in POLICY.md §3.1.
   - **Paths:** unchanged (absolute and `~/` only; project paths dropped).
   - **Not done:** edit distance, substring, case-folded paths on case-sensitive systems,
     DNS resolution, any model. Each one turns docs into links.
5. **Verdict and rule unchanged.** `review`, rule `injected-input`, the reason naming the
   token kind and its source. A host that cannot prompt turns it into a deny with the
   `openmoat allow --last` hint, as every review. What the policy allows on its own stays
   allowed.
6. **Bounds unchanged.** 1 MiB per output, 256 tokens per output, 4096 fingerprints per
   session, 30 days and 200 000 rows. The gateway's results count against the same
   session limit.

## Consequences

- Every agent with an after-call event gets the ADR-057 check once its PR lands. Hook-only
  agents gain the most: for them, this is the only check that knows what the page said.
- MCP output is linked for every agent whose servers are wrapped, before any per-host work.
- A subdomain of a planted host, a numeric IP of it, and a planted command run through
  `sh -c` or with an environment prefix are linked.
- Each host adds a process start after each matched call. The guard's p95 budget applies
  (150 ms, `scripts/ci/latency_ab.py`), and the matchers keep it to calls whose output can
  be untrusted.
- Audit schema: no change (ADR-057's `injected_inputs` holds the gateway's rows too).
- `openmoat init` reports an existing install as stale until it adds the after-call entry,
  as ADR-057 did for Claude Code.
- The SDK's `Session` still takes no outputs (docs/SDK.md); unchanged.

## Alternatives

- **Store results as text for fuzzy matching.** Rejected for the reasons in ADR-057: the
  audit database would hold page and issue text, tokens included. Keyed fingerprints keep
  the "no secrets in the audit log" invariant.
- **Registrable-domain matching with a public suffix list.** That needs a data file in the
  core and makes `evil.github.io` match every `*.github.io`. Parent-domain probes with the
  allow list and source host skipped give most of the value without the list.
- **Read bodies in the proxy.** Only possible inside a terminated tunnel (ADR-043), and it
  would read every response, not only untrusted ones. Out of scope; the gateway and host
  events cover the sources ADR-057 names.
- **Block in the after-call hook.** The call already ran. Blocking would only delay the
  agent; the pre-call check of the *next* call is where the link pays off.

## Testing

- Per host: a golden after-call payload in `host/<module>/fixtures/` (shell, fetch and MCP
  where the host has them), a malformed one, and an oversized one. Real payloads are
  captured by the `latest agents` CI job in its throwaway home, never on a person's
  machine. Payloads carry no real tokens or personal paths.
- Conformance: session fixtures in `review.yaml` whose `session` reports an output per
  host, plus benign ones (a followed link, a documented `git push`, a subdomain of an
  allowed host).
- Core unit tests for each normalisation, with a negative test for each (`rm -rf` vs
  `rm -r -f`, `app.run` in code, a subdomain of an allowed host).
- e2e: one module per host family, as `e2e/claude_code` does for ADR-057.

## Docs to update

Each host's HOST.md "Injected input" paragraph; THREAT_MODEL §3 T15 and §5 "Injected input
is linked only …"; README Limits; POLICY.md §4 (the normalisations); ARCHITECTURE §3 (hook
entries) and §10; docs/ADDING_AN_AGENT.md (after-call event as part of an adapter).

## Plan (one PR each, ≤ 500 lines)

Verified sources first: the gateway, which OpenMoat runs itself, and Cline, whose payload
the repository already has. A host whose after-call payload is not yet captured from a
real release (the latest-agents job records one per host before its PR) waits for it.

1. `feat(mcp)`: the gateway keeps `injected_tokens` of wrapped servers' results, for every
   agent.
2. `host(cline)`: parse `tool_result` (fixture exists), install the `PostToolUse` script.
3. `feat(core)`: host and command normalisation for injected-input, with unit and
   conformance fixtures. No host change.
4. `host(codex)`: `PostToolUse`, after a captured payload.
5. `host(gemini-cli)`: `AfterTool`.
6. `host(copilot-cli)`: `postToolUse`.
7. `host(cursor)`: `afterShellExecution`, `afterMCPExecution`.
8. `host(goose)` and `host(hermes)`: `PostToolUse`, `post_tool_call`.
9. `host(opencode)`, `host(pi)`, `host(openclaw)`: plugin handlers, one PR each.
10. `ci`: a `post-tool-use` case in `guard latency`.

## Open questions

1. Which hosts block the agent on an after-call hook, and for how long? Unverified for
   every host but Claude Code; the CI capture should record it.
2. Should a host whose after-call event is blocking and slow be left out rather than add
   latency to every matched call?
3. Should the gateway's fingerprints be kept for sessions whose agent also reports MCP
   output itself (Claude Code), or is the duplicate dropped by the per-session dedup
   enough?
4. Is a parent-domain probe acceptable for word hosts too, or only for URL hosts (ADR-057
   already treats word hosts more strictly)?
5. Number: 061 assumes the staging-chain and proxy-path drafts take 059 and 060.
