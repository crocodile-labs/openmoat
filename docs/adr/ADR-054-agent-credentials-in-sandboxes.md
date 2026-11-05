# ADR-054: Agent credentials inside the OS sandboxes

Status: proposed · Date: 2026-11-05 · Builds on ADR-020, ADR-034 and ADR-043

## Context

The default policy's `agent-credentials` group names the files where each supported
agent keeps its login, provider keys and OAuth tokens (`~/.codex/auth.json`,
`~/.claude/.credentials.json`, `~/.local/share/opencode/auth.json`, …). The hook denies
the agent's own tools reading or writing them: a shell command naming them, a file tool,
an MCP argument, a glob or link to one. The group is `hook_only` (ADR-034), so every
generated OS sandbox leaves it out: under `openmoat run` the agent process itself is
inside the sandbox and must read its login to work, and the host sandboxes (Claude
Code's, Codex's, Cursor's) are generated from the same IR.

So a program that an allowed command runs can read those files. `npm test` running a
dependency's script, a `python3 x.py` whose code builds the path at run time, a binary
the agent downloaded and the person allowed: none of them names the file in the call
the hook sees, and the OS layer lets them open it. A provider key or refresh token read
that way can then leave through any channel the session still has (an allowed host, a
review the person approves). This is the gap an external review raised, and it is
larger than the docs said: the README's features list said these files "are denied,
however the path is spelt", which holds for the agent's tool calls only.

The OS layers see which process opens a file, not why. Everything inside one sandbox
is one principal: the agent and the commands it starts share the rules.

## Options

1. **Document the limit, and keep `hook_only`.** No change in behaviour. The person
   learns the gap from README "Limits", THREAT_MODEL §2 and §5, and SANDBOX.md. Cheap
   and honest; leaves the gap open everywhere.

2. **Deny the files in the host sandboxes (Standard tier) only.** Claude Code, Codex
   and Cursor sandbox the commands the agent starts, not the agent process: the agent
   reads its login outside their sandbox. Lowering `agent-credentials` to those
   backends, while `openmoat run` keeps leaving it out, closes the gap for the three
   agents with a host sandbox and costs nothing at login. Risks: a command the agent
   legitimately runs that needs an agent's login (another agent's CLI started from a
   shell, `codex exec` from Claude Code, `gh` reading Copilot's file) stops working
   inside that sandbox; each host handles a denied read its own way (Claude Code may
   offer to run the command outside its sandbox, which the hook then decides). Needs a per-backend switch in the lowering (ADR-019), golden files,
   e2e tests that the agent still signs in and that a sandboxed `cat` is refused, and
   the differential suite.

3. **A broker for API-key logins under `openmoat run`.** For an agent that signs in
   with a provider API key, `openmoat secret add` already gives the agent a placeholder
   and the proxy adds the real key for the provider's host only (ADR-020, with TLS
   termination ADR-043). The key is then never in the sandbox, so no command can read
   it; the policy can deny the agent's key file in the sandbox too. Works only for
   API-key logins that the agent reads from an environment variable or a file it does
   not rewrite, only under `openmoat run` (the proxy), and needs a per-agent recipe.
   OAuth logins (Claude Code's and Codex's subscriptions, Copilot, Gemini CLI's
   Google sign-in) refresh and rewrite their token files, which a placeholder cannot
   follow.

4. **Read once at agent start.** `openmoat run` reads the credential file before it
   starts the agent, hands it over (environment variable or inherited descriptor), and
   the sandbox then denies the file. Rejected: an environment variable or descriptor is
   inherited by every command the agent starts, so the secret moves rather than
   disappears; agents re-read and rewrite their token files on refresh; each agent's
   file format and sign-in code would have to be reproduced and kept in step.

5. **Per-host credential stores (the OS keychain).** Several agents can keep their
   login in the macOS Keychain or a Secret Service keyring instead of a file (Claude
   Code on macOS, goose with its keyring on, Copilot CLI). Then there is no file to
   read, but any process running as the person can ask the keychain for the item
   unless the item's access list or the sandbox stops it, and a sandbox that refuses
   the keychain service also refuses the agent. Worth recommending where the agent
   offers it; not something OpenMoat can enforce.

## Decision (proposed)

- **Now (0.14.1): option 1.** State the gap plainly where protection is described:
  README "Features" and "Limits", THREAT_MODEL §2, SANDBOX.md. The features line no
  longer says the files are denied however the path is spelt without saying to whom.
- **Next: option 2**, as its own change with the tests above, for the hosts whose
  sandbox confines only the agent's commands. It is the one option that closes the gap
  without a new prompt and without touching sign-in, for the agents most people use.
- **Then: option 3** as a documented recipe per agent for API-key logins under
  `openmoat run`, where the broker already exists; `openmoat run` keeps
  `agent-credentials` hook-only for OAuth logins, which stays a listed limit.
- Options 4 and 5 are not built; the docs may recommend an agent's own keychain
  storage where it offers one.

## Consequences

- Until option 2 ships, a program an allowed command runs can read every agent's
  login files on every tier; the hook still denies the agent's own tool calls on them,
  and session taint does not start from such a read, since the hook never saw it.
- Option 2 makes the Standard tier stricter than `openmoat run` on these paths: the
  first tier where a deny reaches the host sandboxes but not OpenMoat's own. `openmoat
  sandbox show` and `policy compile` must say which backends leave the group out.
- Option 3 adds per-agent setup and only helps API-key users; the docs must not
  present it as closing the gap for OAuth sign-ins.
