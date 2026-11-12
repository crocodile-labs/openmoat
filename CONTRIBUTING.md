# Contributing to OpenMoat

Thank you for helping. This file is short on purpose; the detail lives in `docs/` and
in `AGENTS.md`, the working contract for people and coding agents.

## Where to start

- **A safe command is denied or held for review** (a *false positive*): open an issue with
  the false-positive form and paste the `openmoat policy check` output.
- **A dangerous action is allowed**, or anything else security-relevant: report it
  privately through a security advisory ([SECURITY.md](SECURITY.md)), never in a
  public issue or pull request.
- **Support another AI coding agent:** follow
  [docs/ADDING_AN_AGENT.md](docs/ADDING_AN_AGENT.md).
- **Change a rule or the shell classifier:** read [docs/POLICY.md](docs/POLICY.md)
  and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §3–4 first.
- Issues labelled `good first issue` and `help wanted` are open for contributors.

## Setup

```bash
git clone https://github.com/crocodile-labs/openmoat && cd openmoat
git config core.hooksPath .githooks        # runs the quality gate before every push
scripts/ci/quality-gate.sh                 # fmt, clippy -D warnings, tests: what CI runs
```

Rust 1.99 (pinned in `rust-toolchain.toml`). No other tooling is required.

## Toolchain and MSRV

The minimum supported Rust version (MSRV) is the pinned toolchain: `rust-version =
"1.99"` in `Cargo.toml`, `channel = "1.99"` in `rust-toolchain.toml`. It is raised on
purpose and only in a minor release (0.2.x → 0.3.0), with a `### Changed` line in
`CHANGELOG.md`, never in a patch release.

## Coverage

CI does not measure line coverage. Locally: `cargo install cargo-llvm-cov --version 0.9.1
--locked`, then `cargo llvm-cov --workspace --open`. `docs/COVERAGE.md` is a different
thing: which threats the conformance fixtures cover.

## Your first pull request

Every change lands through a pull request, including maintainers' own work; nothing
is pushed to `main` directly.

1. **Open an issue first** for anything that changes what an agent may do: a rule, a
   verdict, a host adapter, a sandbox setting. Changes to semantics, invariants or
   crate boundaries start as a design proposal issue and land with an ADR. A docs or
   test fix can go straight to a pull request.
2. **Branch** from `main` as `<type>/<short-topic>` (for example `fix/windows-paths`).
   Keep the PR to one concern and under 500 changed lines; split larger changes into a
   stack of PRs, or say in the PR why it cannot be split.
3. **Add tests at the right level** for a behaviour change:
   - unit tests next to the code (`#[cfg(test)]`),
   - conformance fixtures in `tests/conformance/` for every rule or parser change,
   - end-to-end tests in `crates/openmoat-cli/tests/` for CLI and hook behaviour,
   - architecture tests (`crates/*/tests/architecture.rs`) when crate boundaries move.
4. **Run `scripts/ci/quality-gate.sh`.** It runs what CI's `lint` and `test` jobs run;
   CI runs the tests on macOS, Linux and Windows.
5. **Open the PR with the template.** The title follows Conventional Commits
   (`fix(cli): …`); **Testing** and **Security impact** are required sections, and the
   **Release note** line feeds `CHANGELOG.md`.
   A user-visible change adds a fragment in `changelog.d/` (see "Changelog").
6. **Answer the review.** A maintainer reviews and makes the call.

## CI

`.github/workflows/ci.yml` runs on every pull request, every push to `main` and by hand
(Actions → ci → Run workflow):

| Job | Runner | What it does |
|---|---|---|
| `changes` | `ubuntu-latest` | `code=false` when a pull request changes documentation only (`*.md`, `docs/**`, `LICENSE*`, `changelog.d/**`); `true` on a push, a run by hand and any error |
| `lint` | `ubuntu-latest` | `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` |
| `test` | `ubuntu-latest`, `macos-15`, `windows-latest` | `cargo test --workspace --all-features --locked`; Linux installs bubblewrap first |
| `required` | `ubuntu-latest` | fails when any job above failed or was cancelled; a skipped job is fine |

A documentation-only pull request skips `lint` and `test`; every push to `main` runs
them, so a document a test reads is still checked there. The `main` ruleset requires
`required`, `conventional` (the title, `pr-title.yml`) and `labels · size · risk · body`
(`pr-standards.yml`): a new CI job goes in `required`'s `needs`, not in the ruleset. A new push cancels
the pull request's older run; runs on `main` are never cancelled. Rust build caches are
saved by runs on `main` only.

Not required: `codeql.yml` (CodeQL), `latest-agents.yml` (weekly, below) and
`release.yml` (on a pull request that changes the manifests, `dist plan` only).

## Pull requests

The PR body must have non-empty **Testing** and **Security impact** sections. CODEOWNERS
requests the maintainer's review on the paths it lists; with one maintainer it is not
enforced by the ruleset (two-maintainer review is a v1.0 item). Squash-merge; the PR
title becomes the commit subject and the **Release note** line feeds `CHANGELOG.md`.

Release tags (`v*`) can only be created, moved or deleted by repository admins (the
`release tags` ruleset), because pushing one starts the release workflow. Publishing to
crates.io additionally waits for approval on the `release` environment.

## AI-assisted contributions

Built with Claude Code, Codex, Cursor, OpenClaw or any other tool? Welcome. No disclosure,
label or attribution is required, and none is forbidden; commit trailers and PR footers are
your choice. The bar is the same for every change: you have read and understood what you
are submitting, you ran the quality gate, the Testing and Security impact sections are
true, and you can answer review questions about it. Keep PR descriptions the size a
reviewer can read; a generated wall of text is a reason to ask for a rewrite, not a merit.
`AGENTS.md` is written for coding agents as much as for people; point your tool at it.

## Conventions

- Commit and PR title types: `feat`, `fix`, `sec`, `policy`, `host(claude-code)`,
  `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`, lowercase subject.
- Library crates (`openmoat-core`, `openmoat-hosts`, `openmoat-audit`, `openmoat-proxy`,
  `openmoat-sdk`) use typed `thiserror` errors and never print; nor does `openmoat-wasm`.
  `anyhow` and terminal output live only in `openmoat-cli`.
- `openmoat-core` has no I/O, no `unsafe`, and no internal dependencies; it builds for
  `wasm32` (`cargo build -p openmoat-core --target wasm32-unknown-unknown`).
- Rust files stay at or under 500 lines of code; functions under 200 (clippy enforces
  the latter). `crates/openmoat-core/tests/architecture.rs` counts the code lines of
  every `.rs` file in each crate's `src/` and `tests/`: blank and comment lines, files
  under `fixtures/`, `golden/`, `goldens/` or `snapshots/`, and files marked
  `@generated` in their first lines are not counted. The cap only goes down.
- Comments explain *why*. Code says *what*.
- A new dependency needs a sentence in the PR on why the standard library or an
  existing dependency does not cover it. `cargo deny check` (`deny.toml`) checks licences
  and advisories.
- Workflows pin every action to a commit SHA, check out with `persist-credentials: false`,
  pass expressions to `run:` blocks through `env:`, and give tokens only the permissions
  they use.

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Pull requests do not edit it: each user-visible change adds one file to
[`changelog.d/`](changelog.d/README.md), so parallel PRs never conflict on the same
block, and the release folds the files in.

- Name the file `<pr>-<slug>.md` (`712-pi-dialog-timeout.md`): open the PR first, then
  add the fragment with its number.
- Its first line is the heading the entry goes under: `### Security`, `### Added`,
  `### Changed`, `### Removed` or `### Fixed`. Then one line per change, `- …`. Say what
  changed for the user, not how; the detail belongs in the PR and the docs.
- End each line with its pull request: `([#123](https://github.com/crocodile-labs/openmoat/pull/123))`.
- `python3 scripts/changelog-check.py` fails on a fragment that breaks these rules.
- At release time `python3 scripts/changelog-assemble.py` appends every fragment's lines
  to its heading under `## [Unreleased]` (adding the heading if it is missing, each
  heading once per version) and deletes the fragments; `--dry-run` prints the result
  instead. Entries already in `CHANGELOG.md` stay where they are.
- Internal changes (CI, refactors, tests) get no fragment; write "none" as their Release note.
- The version headings are links; the compare links at the end of the file name each
  version's range (`[0.2.0]: …/compare/v0.1.1...v0.2.0`, `[Unreleased]: …/compare/v0.2.0...HEAD`).

Entries of releases up to 0.2.0 predate this rule and stay as they are.

## Checks beyond the Rust gate

CodeQL runs in CI but is not required; the others are worth running by hand when you
touch what they check.

- **Shell scripts:** `shellcheck` on every `*.sh` file and `.githooks/pre-push`.
  A `# shellcheck disable=SCxxxx` comment needs the reason on the same line.
- **CodeQL:** `.github/workflows/codeql.yml` analyses the workflows, the JavaScript
  plugins, the Python scripts and the Rust code on every pull request (forks included),
  on `main` and weekly, without building anything. It analyses shipped code only
  (`.github/codeql/codeql-config.yml` leaves out test files and folders, whose assertion
  messages it would read as log injection).
- **Spelling:** [`typos`](https://github.com/crate-ci/typos) 1.51.1
  (`cargo install typos-cli --version 1.51.1 --locked`) with `_typos.toml`. The project
  writes British English (`behaviour`, `licence`); an American spelling that is someone
  else's name (`Serialize`, the `Authorization` header, `--color`) goes in the
  allow-list with a comment saying whose it is. Never "fix" a deliberate misspelling in
  a fixture; allow-list it.
- **Unused dependencies:** `cargo machete` (`cargo install cargo-machete --version 0.9.2
  --locked`) fails on a dependency in a `Cargo.toml` that no source file uses. Remove
  it; if it is used in a way machete cannot see, list it under
  `[package.metadata.cargo-machete] ignored` with a comment saying where it is used.

The JavaScript plugins OpenMoat installs into OpenClaw, pi and OpenCode
(`crates/openmoat-hosts/src/host/*/integration/`) are tested by `cargo test -p
openmoat-hosts --test js_plugins`, which runs each plugin under Node against a stand-in
for its host and for `openmoat guard` (`tests/js_plugins/`). It is part of the tests and
skips, saying so, when `node` is not on `PATH`. The plugins start with `// @ts-check`
(`crates/openmoat-hosts/jsconfig.json`); describe a host's objects with JSDoc types
rather than `any`, and keep the plugins free of dependencies.

## Testing with real agents

Most end-to-end tests hand `openmoat guard` a hook payload the test wrote. The
differential tests also run the real Claude Code and Codex binaries when
`MOAT_CLAUDE_BIN` and `MOAT_CODEX_BIN` name them (`scripts/ci/host-binaries.sh <dir>`
fetches the pinned ones and prints both lines; then `cargo test -p openmoat --test e2e
-- differential`), with no account and no traffic leaving the machine:

- `differential::claude` and `differential::codex` run the attack scenarios under each
  agent's own sandbox, without OpenMoat's hook.
- `differential::agents` runs Claude Code with OpenMoat's hook installed by `openmoat init`.
  A local fake Anthropic API (`tests/differential/fake_api.py --calls`) asks for a fixed
  sequence of tool calls, and a stdio MCP server (`tests/differential/fake_mcp.py`)
  answers MCP calls. The scenarios are token egress, a push of a committed token, the
  package near-miss review, a changed MCP server, file provenance across two sessions and
  `onFailure: block`, which is asserted only from Claude Code 2.1.295 (with an older pin
  the test reports what happened). The same calls also run through `openmoat guard` alone,
  on every machine.
- Codex is driven only through `codex sandbox`, and inside `openmoat run` the only network
  is the run's proxy, which refuses loopback, so no fake model API is reachable there.
  For hooks inside `openmoat run`, the tests check that the real `codex` starts inside the run and
  that a Codex hook call made in the run is decided and recorded outside it.

### Latest agents, weekly

Agents release weekly or daily, and the payloads above are checked against the release
each adapter was written for. The `latest agents` workflow
(`.github/workflows/latest-agents.yml`, weekly and by hand, optionally for one agent)
builds `openmoat` once per operating system, then runs `scripts/ci/latest-agents.sh` for
every agent in `scripts/ci/latest-agents/agents.json`, on Linux and, where the agent
ships a different build there, macOS:

- the agent's latest release is installed in a throwaway home: from npm with lifecycle
  scripts off and `npm audit signatures`, Hermes Agent with its own installer of the
  latest tag, Cursor's CLI from the package its install script names;
- `openmoat init --hosts <id> --yes`, then `openmoat status` and `openmoat doctor` must
  call the agent protected by its hook, doctor must be healthy, and the agent's files
  must still parse;
- where the agent runs without an account, the real agent is started against a local
  fake model API (`scripts/ci/latest-agents/fake_openai.py`,
  `tests/differential/fake_api.py`, Gemini CLI's own `--fake-responses`) or Hermes
  Agent's `hooks test`, asks for `cat ~/.ssh/id_rsa`, and the audit log must hold that
  call denied by `secrets-paths` with the fake key in none of its output;
- an allowed and a denied payload in the agent's own format (its golden fixture) go
  through `openmoat guard`.

The job summary shows each installed version beside the one the adapter was checked
against; a newer one is reported, not failed. A failure opens one issue per agent,
`latest <agent> <version> breaks OpenMoat`, or comments on the open one (the `report` job,
the only one with a write permission: `issues: write`). No job has a secret. What each
agent's run proves and what it cannot is in `scripts/ci/latest-agents/README.md`; when an
adapter is checked against a new release, update the version in its `HOST.md` (or the
file its record names) and in `agents.json` together:
`python3 -I scripts/ci/latest-agents/check.py records` fails when they disagree.

### By hand, with your own keys

To try the same checks with your own agents and model keys, run:

```bash
ANTHROPIC_API_KEY=… OPENAI_API_KEY=… scripts/smoke-real-agents.sh   # or name steps: egress push mcp
```

It creates a throwaway `HOME`, `MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
`GEMINI_CLI_HOME`, `PI_CODING_AGENT_DIR` and `COPILOT_HOME` under a new temporary
directory, runs `openmoat init` there, and walks through each check in headless mode
(`claude -p`, `codex exec` on its own and inside `openmoat run`, `gemini`, `pi` and
`copilot` with the prompt and auto-approve flags their `--help` names). Before each step
it says what to expect, and after it prints PASS, FAIL or LOOK (the model did not make
the call). The steps are `egress push near-miss mcp on-failure provenance codex-hook
codex-run gemini gemini-drift pi copilot`:

- `gemini`, `pi` and `copilot` run `openmoat init --hosts <id> --yes` for that agent,
  check that `openmoat status` and `openmoat doctor` say `hook only`, then ask the agent
  for a harmless command and `cat ~/.ssh/id_rsa`; they pass when the read is recorded as
  `deny [secrets-paths]` and the fake key is not in the answer.
- `gemini-drift` sets `model.name` in Gemini CLI's `settings.json` (calls must still be
  decided and `doctor` must report the change), then adds a hook entry there (every call
  must be denied with `kernel-integrity`), and puts the file back.

Gemini CLI takes `GEMINI_API_KEY`, Copilot `COPILOT_GITHUB_TOKEN` (a fine-grained token
with the "Copilot Requests" permission), and pi the key of `SMOKE_PI_PROVIDER` or of the
first of Anthropic, OpenAI and Google whose key is set. A Gemini or Copilot key you did
not set is asked for at the terminal without echo, and is given only to that agent's
process. Sign-ins these agents keep in your own `~/.gemini`, `~/.pi` or `~/.copilot` are
never copied; without a key the step prints SKIP and says why.
Before any agent starts it checks that none of those variables resolves to your real
home, `~/.claude`, `~/.codex`, `~/.cursor`, `~/.gemini`, `~/.pi`, `~/.copilot`, `~/.moat`
or `~/.ssh`, or to a config directory you had set, and refuses to run if one does. The
steps make real model calls billed to your keys. They use made-up tokens, a fake SSH key
and a `pip` that only prints. The temporary directory is kept so you can inspect it.

## Fuzzing

`fuzz/` holds `cargo fuzz` targets for every surface that takes untrusted input:
`decide_shell` (any command line through the lexer, classifier and engine),
`policy_parse` (any policy file), `host_payload` (any hook payload, every host),
`literal_pattern` (`openmoat allow --always` must produce a rule that lints and matches its
command), `proxy_parse` (any request head or TLS `ClientHello` `openmoat proxy` reads) and
`openclaw_json5` (any `openclaw.json`: the CLI's JSON5 reader, compiled from
`crates/openmoat-cli/src/json5.rs`), `repo_policy_merge` (any repository
`.moat/policy.yaml` merged into the default policy: untrusted it never weakens a verdict
of a fixed probe set, trusted it never allows what a deny rule denies),
`mcp_relay_framing` (any lines the agent host and an MCP server send `openmoat mcp proxy`,
through the relay's own line reader: what it passes on is one well-formed message per
line, and a server's response reaches the host only when it answers a request the host
is waiting for) and `check_diff_parse` (any unified diff `openmoat policy check-diff`
reads: the paths it reports come from the input, and a diff cut off inside a hunk is an
error). `openclaw_json5`, `mcp_relay_framing` and `check_diff_parse` compile the CLI's
own files through `#[path]`, since `moat` is a binary crate; `mcp_relay_framing`
replaces only the relay's pin store (`mcp/tools.rs`, which reads files) with a small
stand-in in the target, so it fuzzes framing and routing, not pin storage. Seeds live in
`fuzz/seed_corpus.py` (`fuzz/corpus/` is not committed); a crash's input goes there as a
regression seed. It is a separate workspace built with nightly:

```bash
cargo install cargo-fuzz --version 0.13.1 --locked
python3 fuzz/seed_corpus.py          # seeds from the conformance fixtures and host payloads
cd fuzz && cargo fuzz run -O decide_shell corpus/decide_shell   # fuzz/rust-toolchain.toml selects the pinned nightly
```

CI does not fuzz; run a target before changing the surface it covers. A crash becomes a
unit test or fixture next to the fix.

## Releasing

`.github/workflows/release.yml` is driven by [dist](https://axodotdev.github.io/cargo-dist/)
(config in `dist-workspace.toml`). A `v*` tag builds the seven targets, writes the shell and
PowerShell installers, the Homebrew formula and `sha256.sum`, attests every file, creates
the GitHub release, pushes `Formula/openmoat.rb` to `crocodile-labs/homebrew-tap` and, after a maintainer
approves the `release` environment, publishes the crates to crates.io. Pull requests that
touch the manifests or the workflow run `dist plan` only. Running the workflow by hand
(Actions → release → Run workflow) is a dry run: it builds every target and publishes nothing.

1. Dry-run the workflow on `main` if the build changed since the last release.
2. In a PR (`build: release vX.Y.Z`): bump `version` in `[workspace.package]` and
   the five `openmoat-*` entries of `[workspace.dependencies]` in `Cargo.toml` and the
   `version` of `sdk/js/package.json` (the JavaScript SDK, ADR-046), run
   `cargo check` to update `Cargo.lock` (and `fuzz/Cargo.lock`), fold the fragments with
   `python3 scripts/changelog-assemble.py`, move the `[Unreleased]`
   entries of `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD` (add its compare
   link at the end of the file and point `[Unreleased]` at the new tag), and update the
   version in the README status line and in `docs/ROADMAP.md` "Where it is today"
   (the "The latest release is" lines; the install commands carry no version). The
   release fails without that CHANGELOG section; its text becomes the release notes,
   after a line saying what the operating system does and does not enforce (ADR-013).
   Run `python3 scripts/ci/check-versions.py`: it fails until the manifests, `sdk/js/package.json`, both lockfiles, the README and ROADMAP "The latest
   release is" lines and the CHANGELOG headings agree.
3. After the merge, tag the merge commit: `git tag -s vX.Y.Z -m vX.Y.Z`
   and `git push origin vX.Y.Z`.
4. Check the GitHub release and the tap commit, then approve the `release` environment in
   the workflow run; `publish-crates` publishes openmoat-core, then openmoat-hosts,
   openmoat-audit and openmoat-proxy, then openmoat. `cargo publish --workspace` includes
   openmoat-sdk; its first publish is manual, like the others' was (below).
5. The JavaScript SDK is published by a maintainer, by hand, from the tagged commit:
   `scripts/ci/sdk-js.sh` (it builds `sdk/js/dist/openmoat.wasm` and runs every test),
   compare the printed SHA-256 with the CI job's, then `npm publish --access public` in
   `sdk/js` (docs/SDK.md, ADR-046).

The first crates.io publish is manual, because trusted publishing can only be configured
for a crate that exists. Reject the `release` deployment in the workflow run, then:

1. On crates.io (account with a verified email), create an API token that expires in a
   day, with the scopes `publish-new` and `publish-update` and the crate pattern
   `openmoat*`.
2. From a clean checkout of the tag:

   ```bash
   git checkout vX.Y.Z
   cargo login                                   # paste the token
   cargo publish --locked --workspace --dry-run
   cargo publish --locked --workspace            # openmoat-core, then openmoat-hosts,
                                                 # openmoat-audit, openmoat-proxy and
                                                 # openmoat-sdk, then openmoat
   ```

   If it stops halfway, publish the rest one by one in that order with
   `cargo publish --locked -p <crate>`; a published version cannot be replaced.
3. For each of the six published crates (`openmoat-wasm` is `publish = false`), open
   Settings → Trusted Publishing on crates.io and add a
   GitHub publisher: owner `crocodile-labs`, repository `openmoat`, workflow `release.yml`,
   environment `release`.
4. Revoke the token on crates.io and run `cargo logout`.

Later releases need no crates.io token: `publish-crates` exchanges the workflow's OIDC
token after the `release` environment is approved.

One-time repository setup: a `release` environment with the maintainer as required
reviewer and deployments limited to `v*` tags, and `HOMEBREW_TAP_TOKEN`, a fine-grained
token with contents write on `crocodile-labs/homebrew-tap` only (the tap needs one commit).

## API changes

`openmoat-core`, `openmoat-hosts`, `openmoat-audit` and `openmoat-proxy` are published
libraries, and `openmoat-sdk` joins them with its first release (ADR-046 is its
stability contract). While the version is 0.x, a breaking change to their public API needs a minor
bump (0.1.x → 0.2.0) and anything else a patch bump. An intended break is said in the
PR's **Release note** (what breaks and what to use instead); its changelog fragment goes
under `### Changed` or `### Removed` and the entry starts with **Breaking** and the crate.

Check a change with [cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks):
`cargo install cargo-semver-checks --version 0.51.0 --locked`, then
`cargo semver-checks check-release -p openmoat-core --baseline-rev origin/main`; before a
release, against the latest crates.io release (no `--baseline-rev`).

## Decisions

Non-obvious decisions are recorded as ADRs in `docs/adr/`. Propose one in the PR
when you change an invariant (policy semantics, exit codes, crate boundaries).

A shell-classifier bypass is not such a decision. The classifier triages; OS
enforcement is the boundary (ADR-013). Report the bypass, add an attack fixture, and
make the smallest change that turns it into `review` or `deny`. Since ADR-025 an
`unparseable` call defers under the default policy, so emit an atom a default rule
names instead (`<program> @<argument>`, `<shell> @stdin`, a `net` host, a real path).

## Governance

Single maintainer for now. CODEOWNERS routes review; the trusted core, the default
policy and CI require maintainer approval.

## License

When you contribute, your work is shared under the same two licenses as the rest of
the project: the [MIT License](LICENSE) and the [Apache License 2.0](LICENSE-APACHE).
Anyone who uses OpenMoat can pick either one. There's no separate agreement (CLA) to sign.
