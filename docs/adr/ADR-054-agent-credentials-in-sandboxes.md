# ADR-054: Agent credentials inside the OS sandboxes

Status: accepted · Date: 2026-11-05 · Builds on ADR-019, ADR-020, ADR-034 and ADR-043

## Context

The default policy's `agent-credentials` group names the files where each supported
agent keeps its login, provider keys and OAuth tokens (`~/.codex/auth.json`,
`~/.claude/.credentials.json`, `~/.local/share/opencode/auth.json`, …). The hook denies
the agent's own tools reading or writing them: a shell command naming them, a file tool,
an MCP argument, a glob or link to one. Until 0.15 the group was `hook_only` (ADR-034),
so every generated OS sandbox left it out: under `openmoat run` the agent process
itself is inside the sandbox and must read its login to work, and the host sandboxes
(Claude Code's, Codex's, Cursor's) are generated from the same IR.

So a program that an allowed command runs could read those files. `npm test` running a
dependency's script, a `python3 x.py` whose code builds the path at run time, a binary
the agent downloaded and the person allowed: none of them names the file in the call
the hook sees, and the OS layer let them open it. A provider key or refresh token read
that way can then leave through any channel the session still has (an allowed host, a
review the person approves). An external review raised this gap.

The OS layers see which process opens a file, not why. Everything inside one sandbox
is one principal: the agent and the commands it starts share the rules.

## Options

1. **Document the limit, and keep `hook_only`.** No change in behaviour; leaves the gap
   open everywhere. This was 0.14.1's interim state.
2. **Deny the files in the sandboxes that confine only the agent's commands.** Claude
   Code, Codex and Cursor sandbox the commands the agent starts, not the agent process:
   the agent reads its login outside their sandbox. Under `openmoat run` the agent is
   inside, so there only the other agents' logins can be denied.
3. **A broker for API-key logins under `openmoat run`.** For an agent that signs in
   with a provider API key, `openmoat secret add` gives the agent a placeholder and the
   proxy adds the real key for the provider's host only (ADR-020, ADR-043). The key is
   then never in the sandbox. Works only for API-key logins the agent reads from an
   environment variable or a file it does not rewrite. OAuth logins (Claude Code's and
   Codex's subscriptions, Copilot, Gemini CLI's Google sign-in) refresh and rewrite
   their token files, which a placeholder cannot follow.
4. **Read once at agent start**, hand the secret over, deny the file. Rejected: an
   environment variable or descriptor is inherited by every command the agent starts,
   so the secret moves rather than disappears; agents re-read and rewrite their token
   files on refresh; each agent's file format would have to be reproduced.
5. **Per-host credential stores (the OS keychain).** No file to read, but any process
   running as the person can ask the keychain for the item unless its access list or
   the sandbox stops it, and a sandbox that refuses the keychain refuses the agent too.
   Worth recommending where the agent offers it; not something OpenMoat can enforce.

## Decision

Options 2 and 3; 4 and 5 are not built.

**The policy.** `agent-credentials` is no longer `hook_only`. The IR denies its paths
for reads and writes like any deny group, so every backend gets them from the one
list the host specs generate (`crates/openmoat-hosts/tests/protect.rs`). The lowering
writes each brace alternative of a file pattern as a pattern of its own
(`ir::brace_alternatives`): `~/.codex/{auth.json,.credentials.json}` reaches Claude
Code's `denyRead`, Codex's profile and bubblewrap's masks as two paths, which every
backend can name, rather than as a glob only Seatbelt and the engine read.

**Host sandboxes (Standard tier).** Each confines only the commands its agent runs,
which we checked per host:

- Claude Code: its sandbox wraps `Bash`, `PowerShell` and `Monitor`; the agent and its
  file tools run outside it (`sandbox/claude.rs`). The login files go into `denyRead` and
  `denyWrite`, and into `permissions.deny` as `Read(//…)`/`Edit(//…)` rules, which the
  file tools obey; the hook denies those tool calls anyway, and Claude Code reads its own
  login without a tool.
- Codex: the profile applies to the commands Codex runs. It already denies the Codex
  home whole (`kernel-self`), which shows the Codex process signs in outside it; the
  other agents' login files are now `deny` entries too.
- Cursor: `sandbox.json` confines terminal commands. It has no key that denies a path,
  so the deny makes the generator leave out any read root holding a login (stricter,
  listed), as it does for `secrets-paths`; the workspace read boundary keeps the rest
  unreadable.

No host's sandbox there also confines the agent's own login, so no host is left out.

**`openmoat run` (Lightweight and Isolated tiers).** The agent runs inside the sandbox,
so `openmoat run` finds which agent it starts: the command as typed or the file it
resolves to, matched against each host's program names and package directories
(`Host::by_program`, the `ProcessSpec` that `openmoat`'s person-only commands already
look for among their parents). It lowers the sandbox from a copy of the policy whose
`agent-credentials` group lacks that agent's own patterns, those its spec names
(`sandbox/own_login.rs`), and lists them as wider (`run.own-login`). For a program that
is no agent OpenMoat knows (a wrapper, an MCP server under `openmoat mcp wrap`), the
login files inside its `--write` paths are left out instead: the person granted those
to it. Every other agent's login stays denied. The hook and the proxy keep deciding with
the whole policy, so the agent's own tools still may not read its login. A moved agent
directory follows: the carve-out is made on the policy's `~/…` patterns, before the
lowering spells each one in the moved directory too.

On Linux, Landlock cannot deny inside a grant. A login file inside a `--write` path is
listed as `landlock.inside-grants`; where the agent gets a network namespace (or under
`--isolate`) bubblewrap hides each one that exists, as for `secrets-paths`. Only
`kernel-self` refuses to start without a namespace, and the login files are not in it,
so no new refusal appears.

**Option 3** is documented as a recipe per API-key login ([BROKER_LOGINS.md](../BROKER_LOGINS.md)):
`openmoat secret add` for the provider key, the agent started with the placeholder.
The docs do not present it as closing the gap for OAuth sign-ins.

## Consequences

- A command an agent runs can no longer read any agent's login file under Claude
  Code's, Codex's or Cursor's sandbox, nor another agent's under `openmoat run`. Daily
  work is unchanged: the agents sign in as before, and no command a build runs needs
  an agent's login.
- A command that legitimately needs another agent's login stops working inside the
  sandbox: another agent's CLI started from a shell (`codex exec` from Claude Code), a
  tool reading Copilot's `config.json`. Each host handles the refused read its own way
  (Claude Code may offer to run the command outside its sandbox, which the hook then
  decides). A person who needs that can set `hook_only: true` on the group in their
  policy, which restores the old behaviour for every sandbox; `openmoat policy upgrade`
  shows the change for a policy that predates it.
- Under `openmoat run` the running agent's own login stays readable to every command it
  runs: the agent and its commands are one principal there. Option 3 closes that for
  API-key logins; OAuth logins stay a listed limit.
- `openmoat sandbox show` lists where the logins are denied and what `openmoat run`
  keeps per agent (`agent_logins` in `--format json`); the group no longer appears among
  the `hook_only` groups.
- A policy that already pins the old default keeps `hook_only: true` until the person
  upgrades it, and so keeps the old behaviour.
