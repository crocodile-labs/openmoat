# ADR-105: A scrubbed environment for what `openmoat run` starts

Status: accepted · Date: 2026-11-20 · Builds on ADR-020 (brokered secrets), ADR-075 (relay
token kept from tool commands), ADR-077 (the environment allowlist), ADR-089 (the run's
boundary record) and ADR-103 (policy schema versions)

## Context

A secret in an environment variable is guarded by the classifier alone (THREAT_MODEL T3):
`env-secrets` denies reads of secret-shaped names and `env-dump` denies argument-less
`env`, `printenv`, `set`, `/proc/<pid>/environ` and inline interpreter code that reads the
whole environment. That is triage, not a boundary (ADR-013): an alias (`e = os.environ`), a
script file the agent wrote, a test runner that prints its environment on failure, or any
program that reads its own variables sees the whole shell environment the agent was
started from.

ADR-077 built an allowlist for `openmoat run`, applied only under `require.run:
full-boundary`. Nothing else turns it on, so a person who wants the variables gone, and
not the rest of the requirement, cannot have it. A brokered secret's variable is removed,
so a tool that refuses to start without its token (a CLI that says "not logged in") cannot
use the broker it was set up for.

## Decision 1: where a scrubbed environment can be enforced

Only where OpenMoat starts the process can it decide the process's environment. Per layer:

| Layer | Can it scrub? | What this ADR does |
|---|---|---|
| `openmoat run` (macOS Seatbelt, Linux Landlock and bubblewrap) | Yes. OpenMoat starts the agent, so it sets the environment of the agent and of everything the agent starts, which inherits it | Scrubs it (decisions 2 to 5) |
| Claude Code's own sandbox, as `openmoat init` writes it | Partly. Settings `env` can set a variable but not remove one ("In a settings file you can set a variable but you can't remove one", [environment variables](https://code.claude.com/docs/en/env-vars)). `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` "strip[s] credentials from the environments of the subprocesses Claude Code starts, such as Bash commands, hooks, and stdio MCP servers", by name or value; it keeps `GITHUB_TOKEN`, `GH_TOKEN` and the proxy variables and removes `CLAUDE_CONFIG_DIR` (same page, "What the subprocess environment scrub removes") | Nothing written; see "What needs a decision" |
| Codex's own sandbox | Yes, by its documentation. `shell_environment_policy` has `inherit` (`all`, `core`, `none`), `ignore_default_excludes` ("Keep variables containing KEY, SECRET, or TOKEN before other filters run (default: true). Set to false to apply automatic secret-name exclusions"), `filters`, `include_only` and `set` ([configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)) | Nothing written; see "What needs a decision" |
| Gemini CLI | Unclear. `security.environmentVariableRedaction` (`enabled`, `allowed`, `blocked`) is documented as "best effort" redaction, and the same page gives two different key spellings and two different defaults ([configuration](https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md)) | Nothing written |
| Cursor | No. Its `sandbox.json` has no key that sets or removes a variable (SANDBOX.md, the `safe.bareRepository` paragraph) | Nothing |
| Every other agent, and any agent started without `openmoat run` | No. The hook sees one tool call's text; the agent's process and its environment exist before any OpenMoat code runs | The classifier rules stay as they are; THREAT_MODEL says so |

## Decision 2: `sandbox.env` and `--scrub-env`

```yaml
sandbox:
  env: scrubbed          # or inherited; absent means the default (decision 6)
  env_allow: [JAVA_HOME] # ADR-077, unchanged
```

1. **One key, two values, optional.** `sandbox.env` is `scrubbed` or `inherited`. Schema
   version 1 gains it as an optional key (ADR-103); absent, the default applies
   (`RunEnv::DEFAULT`). The JSON Schema has it, and its drift test checks the model and the
   schema name the same values.
2. **Who may set it.** The person's own policy, which the lock pins. A repository policy and
   a pack have no `sandbox:` section; they scrub only through `require.run:
   full-boundary`, which still scrubs whatever `sandbox.env` says (ADR-077 decision 2).
3. **`openmoat run --scrub-env`** scrubs one run. It only raises: there is no flag that
   inherits when the policy scrubs, so a script cannot undo the person's choice; a person
   passes one variable on with `--env NAME`, as before.
4. **Order** (`env::Mode::choose`): the requirement, then the flag, then `sandbox.env`, then
   the default. The record and the run's notice name which one chose.
5. **The same list as ADR-077.** A scrubbed environment passes the base, the platform's
   own names, the agent's names from its spec (`HostSpec::run_env` and its configuration
   directory variable), `sandbox.env_allow` and `--env`. What the run sets itself (the proxy,
   the hook relay, the temp directory, git's settings, the CA files, the package managers'
   release age) is applied first and never withheld.
6. **The base gains toolchain locations**: `JAVA_HOME`, `GOPATH`, `GOROOT`, `GOBIN`,
   `CARGO_HOME`, `RUSTUP_HOME`, `RUSTUP_TOOLCHAIN`, `NVM_DIR`, `NVM_BIN`, `PYENV_ROOT`,
   `VIRTUAL_ENV`, `CONDA_PREFIX`, `CONDA_DEFAULT_ENV`, the three `HOMEBREW_*` locations,
   `MANPATH`, `INFOPATH`, `LESS` and `GPG_TTY`. They say where a build's tools are and hold
   nothing secret; without them a scrubbed run breaks ordinary builds. A unit test
   (`no_base_name_looks_like_a_credential`) fails if a base or platform name ever looks like
   a credential, and the end-to-end tests show a credential beside them is still withheld.
   This widens what `require.run: full-boundary` passes by these names only.
7. **MCP servers** started through `openmoat mcp proxy --sandbox` run under `openmoat run`,
   so they are scrubbed when the run is, and keep the names their accepted definition sets
   (ADR-077 decision 2.4).

## Decision 3: a brokered secret's variable holds its placeholder

For each brokered secret whose `source` is `env: NAME`, the run sets `NAME` in the agent's
environment to the secret's placeholder (`moat-secret:<id>:placeholder`), scrubbed or not,
instead of removing it. The run's proxy reads the value from the `openmoat run` process, as
before (ADR-020, ADR-043). A tool that needs the variable to be set starts, and what it
sends is the placeholder:

- to the secret's `host`, through a proxy that terminates TLS for it, the placeholder is
  replaced by the value (POLICY §2.1), which is what the broker is for;
- anywhere else, the hook denies the call that would send it (`placeholder-egress`) and the
  proxy refuses a request that carries it (`proxy-secret`); an untouched placeholder reaching
  a server is a string the server rejects.

The placeholder is not a credential, so this gives the agent nothing it could not already
send: POLICY §2.1 already tells a person to give the agent the placeholder. It is not a
widening of what leaves the machine.

## Decision 4: what `--print-boundary`, `--verbose`, `doctor` and the record show

The run's boundary record (ADR-089) gains an optional `environment` part, names only:
`scrubbed`, `why`, `passed` (the inherited names that pass, when scrubbed), `withheld` and
`brokered`. Records written before it read as they did. `openmoat run --print-boundary`
prints it in text and JSON from the same choices a run makes; the audit row of every run
holds it. `--verbose` names what was withheld, the notice counts it, and `openmoat doctor`
lists the names a run here withholds, or would with `sandbox.env: scrubbed`. No output ever
holds a value.

## Decision 5: the hook's rules stay

Scrubbing narrows what a command can find; it does not replace the rules that deny reading
it. `env-secrets` and `env-dump` are unchanged, and new attack fixtures (`T3-scrub-*`) show
the reads a scrubbed run might tempt someone to relax are still denied: a parent's
`/proc/<pid>/environ`, `env -0`, `printenv -0`, a child shell's `env`, `env` sent off with
`curl`, and a brokered variable read into a request header.

`ps eww` (BSD-style `e`: print each process's environment) is not denied by the hook: it
defers like any other `ps`. Under `openmoat run` the OS layer keeps other processes'
environments from it ("Limits", another process's environment), and a scrubbed environment removes what it would find in the agent's own
processes; outside `openmoat run` it is a gap, listed under "What needs a decision"
rather than fixed here, because the spellings that print environments (`ps e`, `ps auxe`,
macOS `ps -e`) overlap with the ones that only list processes (Linux `ps -e`, `ps -ef`).

## Decision 6: off by default for now

`sandbox.env` absent means `inherited` in this release.

- **Quiet by default.** Normal work must not break. A variable a tool needs and no list
  names is removed without the tool saying why; the run's one line says how many it
  withheld, but a build that fails a minute later does not point back at it.
- **ADR-077's bar is not met yet.** It made the allowlist the default "once the `doctor` row
  and real runs show the base and the hosts' names are complete". The hosts' lists come
  from documentation, several are marked "not checked", and no real agent has run under a
  scrubbed environment.
- **The agents' logins come from their specs**, so a scrubbed environment keeps an agent's
  own API key variables; most agents keep their login in a file or the keychain, which the
  environment does not touch (ADR-054). A login through a cloud account (Bedrock, Google
  Cloud) still needs the person to add those names, on purpose.

The default is one constant, `RunEnv::DEFAULT`. It should become `scrubbed` in a release
whose notes say so, once the pinned real Claude Code and Codex runs
(`tests/e2e/differential/agents`, `scripts/ci/host-binaries.sh`) pass under `--scrub-env`
and the `doctor` row has been read on the maintainers' own machines. Until then the run's
warning line names `sandbox.env: scrubbed` and `--scrub-env`.

## Consequences

- A person can remove the T3 category for everything `openmoat run` starts with one policy
  line or one flag, without the rest of `require.run: full-boundary`.
- The audit log records, per run, which names were withheld and which hold a placeholder.
- A tool that needs a brokered token sees the placeholder instead of an empty variable.
- `openmoat run` under `--scrub-env` can stop a tool that needs an unlisted variable; the
  fix is `--env NAME` or `sandbox.env_allow`.

## Limits

- **It is the environment at the start** (ADR-077's limits apply): a value in a file, the
  keychain or a helper is outside it.
- **The agent's own key reaches its commands.** It is on the list for that agent, and the
  agent passes its environment to what it starts. Claude Code's
  `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` would close that for Claude Code; it is not set (below).
- **Another process's environment.** Under `openmoat run` the macOS profile denies
  `kern.procargs*` (`ps eww` of another process), the Lightweight tier on Linux grants no
  `/proc` path, and the Isolated tier gives the agent its own process namespace, so the
  unscrubbed environment of `openmoat run` itself is out of reach (SANDBOX.md). A policy that
  grants `/proc` reopens it on Linux.
- **Hook-only agents and agents started without `openmoat run`** are not scrubbed.

## What needs a decision

- **Claude Code's `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB`.** Its documentation says it strips
  credentials from hooks too, by name. Under `openmoat run` the hook reaches the run through
  `MOAT_GUARD_TOKEN` (ADR-028), a name with `TOKEN` in it, and the scrub also removes
  `CLAUDE_CONFIG_DIR`, which every `openmoat` command of a non-default configuration
  directory needs. Setting it could make every hook call fail closed. It should be tried
  with the pinned real Claude Code in `differential/agents` before OpenMoat sets it.
- **Codex's `shell_environment_policy.ignore_default_excludes = false`** (or `inherit =
  "core"`). Documented for the commands Codex starts; its hooks page does not say whether
  hook commands get the same environment, and the same `MOAT_GUARD_TOKEN` question applies.
  It should be tried with the pinned Codex (`codex sandbox -P moat`, EVIDENCE.md) before
  `openmoat init` writes it.
- **`ps` that prints environments** (decision 5): a classifier atom for the BSD-style `e`
  (and macOS's `-e`/`-E`) that a `review` or `deny` rule names, with benign fixtures for
  `ps -ef` and `ps aux` on Linux; it needs an issue and a policy change of its own.
- **The default** (decision 6).
