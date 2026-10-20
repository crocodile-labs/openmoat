# Contributing to OpenMoat

Thank you for helping. This file is short on purpose; the detail lives in `docs/` and
in `AGENTS.md`, the working contract for people and coding agents.

## Where to start

- **A safe command is denied or asked about** (a *false positive*): open an issue with
  the false-positive form and paste the `moat policy check` output.
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
scripts/ci/quality-gate.sh                 # fmt, clippy -D warnings, doc, tests, policy lint
```

Rust 1.95 (pinned in `rust-toolchain.toml`). No other tooling is required.

## Toolchain and MSRV

The minimum supported Rust version (MSRV) is the pinned toolchain: `rust-version =
"1.95"` in `Cargo.toml`, `channel = "1.95"` in `rust-toolchain.toml`. It is raised on
purpose and only in a minor release (0.2.x → 0.3.0), with a `### Changed` line in
`CHANGELOG.md`, never in a patch release. The `weekly` workflow
(`.github/workflows/weekly.yml`, also runnable by hand) runs clippy and the tests on
the latest stable and beta, so a new compiler or clippy lint shows up there before the
pin moves. It is not a required check; a failure becomes an issue.

## Coverage

The same `weekly` workflow measures line coverage of the workspace with
[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) on the pinned toolchain. The
job summary shows a table per crate, and the `coverage` artefact holds `lcov.info` and
the HTML report. No coverage service is used and no threshold is enforced. Locally:
`cargo install cargo-llvm-cov --version 0.9.1 --locked`, then `cargo llvm-cov --workspace
--open`. `docs/COVERAGE.md` is a different thing: which threats the conformance
fixtures cover.

## Your first pull request

Every change lands through a pull request, including maintainers' own work; nothing
is pushed to `main` directly.

1. **Open an issue first** for anything that changes what an agent may do: a rule, a
   verdict, a host adapter, a sandbox setting. Changes to semantics, invariants or
   crate boundaries start as a design proposal issue and land with an ADR. A docs or
   test fix can go straight to a pull request.
2. **Branch** from `main` as `<type>/<short-topic>` (for example `fix/windows-paths`).
   Keep the PR to one concern and under 500 changed lines; split larger changes into a
   stack of PRs, or justify them with the `size: override` label.
3. **Add tests at the right level** for a behaviour change:
   - unit tests next to the code (`#[cfg(test)]`),
   - conformance fixtures in `tests/conformance/` for every rule or parser change,
   - end-to-end tests in `crates/openmoat-cli/tests/` for CLI and hook behaviour,
   - architecture tests (`crates/*/tests/architecture.rs`) when crate boundaries move.
4. **Run `scripts/ci/quality-gate.sh`.** CI runs the same script on macOS, Linux and
   Windows.
5. **Open the PR with the template.** The title follows Conventional Commits
   (`fix(cli): …`); **Testing** and **Security impact** are required sections, and the
   **Release note** line feeds `CHANGELOG.md`. Labels are set for you (below).
   A user-visible change adds its line under `## [Unreleased]` (see "Changelog").
6. **Answer the review.** `moat-reviewer` posts a first pass; address or answer its
   🔴 and 🟠 items. A maintainer makes the call.

## Pull request standards

`pr-standards.yml` labels every PR and fails it when the standards are not met:

| Label group | How it is set | Meaning |
|---|---|---|
| `type: *` | from the Conventional Commits title | what kind of change |
| `area: *` | from changed paths | `core`, `hosts`, `audit`, `proxy`, `cli`, `policy`, `ci`, `docs`, `deps` |
| `size: *` | additions + deletions | `XS` ≤ 10 · `S` ≤ 50 · `M` ≤ 200 · `L` ≤ 500 · `XL` fails without `size: override` |
| `risk: *` | from changed paths | `high`: engine, lexer/classifier, policy, guard, exit codes, proxy and broker, OS sandbox generation, `moat run`, integrity, secrets, workflows, SECURITY · `medium`: adapters, install, audit · `low`: the rest |
| `needs: fixture` | core or policy changed without `tests/conformance/` | add a fixture |

Checks that must pass before merge (enforced by the `main` ruleset; names as shown on the
PR): `macos-14`, `macos-15-intel`, `ubuntu-latest`, `windows-latest` (the quality gate),
`openmoat-core builds for wasm32 (no I/O)`, `cargo-deny`, `crates package and build from
their tarballs`, `workflows (actionlint, zizmor)`, `conventional` (title) and
`labels · size · risk · body` (pr-standards). The branch must be up to date with `main`
(strict checks), so rebase before merging. `fuzz (smoke)`, `guard latency` and
`standard tier` run on every PR but are not required: a fuzz finding or a noisy runner
should not block an unrelated change, so read them before merging. The PR body must have non-empty **Testing** and
**Security impact** sections. CODEOWNERS requests the maintainer's review on `risk:
high` paths; with one maintainer it is not enforced by the ruleset (two-maintainer
review is a v1.0 item). Squash-merge; the PR title becomes the commit subject and the
**Release note** line feeds `CHANGELOG.md`.

Release tags (`v*`) can only be created, moved or deleted by repository admins (the
`release tags` ruleset), because pushing one starts the release workflow. Publishing to
crates.io additionally waits for approval on the `release` environment.

Labels are defined in `scripts/ci/sync-labels.sh`; edit that script, not the GitHub UI.

Every pull request also gets a first-pass review from `moat-reviewer`, an automated
reviewer that checks the diff against `AGENTS.md` and posts inline comments tagged
`🔴 blocker` · `🟠 should fix` · `🟡 nit` · `💡 idea` plus one summary per revision. It is
advisory: address or answer its 🔴/🟠 items, push back in a reply when it is wrong, and
expect a maintainer to make the final call. Comment `@moat-reviewer` to run it again
(this is also how maintainers trigger it on fork PRs). Details and setup:
`.github/moat-reviewer/README.md`.

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
- Library crates (`openmoat-core`, `openmoat-hosts`, `openmoat-audit`, `openmoat-proxy`) use
  typed `thiserror` errors and never print. `anyhow` and terminal output live only in
  `openmoat-cli`.
- `openmoat-core` has no I/O, no `unsafe`, and no internal dependencies; CI builds it
  for `wasm32` to prove it.
- Files stay under 500 lines; functions under 200 (clippy enforces the latter).
- Comments explain *why*. Code says *what*.
- A new dependency needs a sentence in the PR on why the standard library or an
  existing dependency does not cover it. `cargo-deny` checks licences and advisories.
- Workflows pin every action to a commit SHA, check out with `persist-credentials: false`,
  pass expressions to `run:` blocks through `env:`, and give tokens only the permissions
  they use. CI runs `actionlint` and `zizmor` on `.github/workflows/`.

## Changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/):

- One line per change, under `### Added`, `### Changed`, `### Fixed`, `### Removed` or
  `### Security`, each heading once per version. Say what changed for the user, not how;
  the detail belongs in the PR and the docs.
- End the line with its pull request: `([#123](https://github.com/crocodile-labs/openmoat/pull/123))`.
- Internal changes (CI, refactors, tests) get no line; write "none" as their Release note.
- The version headings are links; the compare links at the end of the file name each
  version's range (`[0.2.0]: …/compare/v0.1.1...v0.2.0`, `[Unreleased]: …/compare/v0.2.0...HEAD`).

Entries of releases up to 0.2.0 predate this rule and stay as they are.

## Checks beyond the Rust gate

CI runs these on every pull request. `scripts/ci/quality-gate.sh` runs each one whose
tool is installed and prints a skip line for the others, so nothing extra is required
locally.

- **Shell scripts:** `shellcheck` 0.11.0 on every `*.sh` file and `.githooks/pre-push`.
  Fix the finding; a `# shellcheck disable=SCxxxx` comment needs the reason on the same
  line.
- **Markdown links:** `python3 scripts/ci/check-links.py` fails on a relative link to a
  missing file or heading. It is offline: links to websites are not fetched.
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

## Testing with real agents

Most end-to-end tests hand `moat guard` a hook payload the test wrote. CI's
`standard tier` job also runs the pinned Claude Code and Codex binaries
(`scripts/ci/host-binaries.sh`, then `scripts/ci/differential.sh`), with no account and
no traffic leaving the machine:

- `differential::claude` and `differential::codex` run the attack scenarios under each
  agent's own sandbox, without OpenMoat's hook.
- `differential::agents` runs Claude Code with OpenMoat's hook installed by `moat init`.
  A local fake Anthropic API (`tests/differential/fake_api.py --calls`) asks for a fixed
  sequence of tool calls, and a stdio MCP server (`tests/differential/fake_mcp.py`)
  answers MCP calls. The scenarios are token egress, a push of a committed token, the
  package near-miss ask, a changed MCP server, file provenance across two sessions and
  `onFailure: block`, which is asserted only from Claude Code 2.1.295 (with an older pin
  the test reports what happened). The same calls also run through `moat guard` alone,
  on every machine.
- Codex is driven only through `codex sandbox`, and inside `moat run` the only network
  is the run's proxy, which refuses loopback, so no fake model API is reachable there.
  For hooks inside `moat run`, CI checks that the real `codex` starts inside the run and
  that a Codex hook call made in the run is decided and recorded outside it.

To try the same checks with your own agents and model keys, run:

```bash
ANTHROPIC_API_KEY=… OPENAI_API_KEY=… scripts/smoke-real-agents.sh   # or name steps: egress push mcp
```

It creates a throwaway `HOME`, `MOAT_HOME`, `CLAUDE_CONFIG_DIR` and `CODEX_HOME` under a
new temporary directory, runs `moat init` there, and walks through each check in
headless mode (`claude -p`, `codex exec` on its own and inside `moat run`). Before each step it says what
to expect, and after it prints PASS, FAIL or LOOK (the model did not make the call).
Before any agent starts it checks that none of those variables resolves to your real
home, `~/.claude`, `~/.codex`, `~/.cursor`, `~/.moat` or `~/.ssh`, or to a config
directory you had set, and refuses to run if one does. The steps make real model calls
billed to your keys. They use made-up tokens, a fake SSH key and a `pip` that only
prints. The temporary directory is kept so you can inspect it.

## Fuzzing

`fuzz/` holds `cargo fuzz` targets for every surface that takes untrusted input:
`decide_shell` (any command line through the lexer, classifier and engine),
`policy_parse` (any policy file), `host_payload` (any hook payload, every host),
`literal_pattern` (`moat allow --always` must produce a rule that lints and matches its
command) and `proxy_parse` (any request head or TLS `ClientHello` `moat proxy` reads). It is a separate workspace built with nightly:

```bash
cargo install cargo-fuzz --version 0.13.1 --locked
python3 fuzz/seed_corpus.py          # seeds from the conformance fixtures and host payloads
cd fuzz && cargo fuzz run -O decide_shell corpus/decide_shell   # fuzz/rust-toolchain.toml selects the pinned nightly
```

CI runs each target for a minute on pull requests and ten minutes in the weekly run. A
crash becomes a unit test or fixture next to the fix.

## Releasing

`.github/workflows/release.yml` is driven by [dist](https://axodotdev.github.io/cargo-dist/)
(config in `dist-workspace.toml`). A `v*` tag builds the seven targets, writes the shell and
PowerShell installers, the Homebrew formula and `sha256.sum`, attests every file, creates
the GitHub release, pushes `Formula/moat.rb` to `crocodile-labs/homebrew-tap` and, after a maintainer
approves the `release` environment, publishes the crates to crates.io. Pull requests that
touch the manifests or the workflow run `dist plan` only. Running the workflow by hand
(Actions → release → Run workflow) is a dry run: it builds every target and publishes nothing.

1. Dry-run the workflow on `main` if the build changed since the last release.
2. In a PR (`build: release vX.Y.Z`): bump `version` in `[workspace.package]` and
   the four `openmoat-*` entries of `[workspace.dependencies]` in `Cargo.toml`, run
   `cargo check` to update `Cargo.lock` (and `fuzz/Cargo.lock`), move the `[Unreleased]`
   entries of `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD` (add its compare
   link at the end of the file and point `[Unreleased]` at the new tag), and update the
   version in the README status line and in `docs/ROADMAP.md` "Where it is today"
   (the "The latest release is" lines; the install commands carry no version). The
   release fails without that CHANGELOG section; its text becomes the release notes,
   after a line saying what the operating system does and does not enforce (ADR-013).
   `python3 scripts/ci/check-versions.py` (in the quality gate and the `crates package`
   CI job) fails until the manifests, both lockfiles, the README and ROADMAP "The latest
   release is" lines and the CHANGELOG headings agree.
3. After the merge, tag the merge commit: `git tag -s vX.Y.Z -m vX.Y.Z`
   and `git push origin vX.Y.Z`.
4. Check the GitHub release and the tap commit, then approve the `release` environment in
   the workflow run; `publish-crates` publishes openmoat-core, then openmoat-hosts,
   openmoat-audit and openmoat-proxy, then openmoat.

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
                                                 # openmoat-audit, openmoat-proxy, then openmoat
   ```

   If it stops halfway, publish the rest one by one in that order with
   `cargo publish --locked -p <crate>`; a published version cannot be replaced.
3. For each of the five crates, open Settings → Trusted Publishing on crates.io and add a
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
libraries. While the version is 0.x, a breaking change to their public API needs a minor
bump (0.1.x → 0.2.0) and anything else a patch bump. The `semver of the library crates`
CI job runs [cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks)
0.51.0 twice:

- **against the PR's base commit**, blocking: a PR that breaks the API fails. If the
  break is intended, say so in the PR's **Release note** (what breaks and what to use
  instead), ask a maintainer to add the `breaking` label, and re-run the job; it then
  passes with a warning. Under `[Unreleased]` in `CHANGELOG.md` the entry goes in
  `### Changed` or `### Removed` and starts with **Breaking** and the crate.
- **against the latest crates.io release**, reporting only, except on a release PR
  (`build: release …`), where it blocks until the version bump covers every break
  since that release.

Locally: `cargo install cargo-semver-checks --version 0.51.0 --locked`, then
`cargo semver-checks check-release -p openmoat-core --baseline-rev origin/main`.

## Decisions

Non-obvious decisions are recorded as ADRs in `docs/adr/`. Propose one in the PR
when you change an invariant (policy semantics, exit codes, crate boundaries).

A shell-classifier bypass is not such a decision. The classifier triages; OS
enforcement is the boundary (ADR-013). Report the bypass, add an attack fixture, and
make the smallest change that turns it into `ask` or `deny`. Since ADR-025 an
`unparseable` call defers under the default policy, so emit an atom a default rule
names instead (`<program> @<argument>`, `<shell> @stdin`, a `net` host, a real path).

## Governance

Single maintainer for now. CODEOWNERS routes review; the trusted core, the default
policy and CI require maintainer approval.

## License

By contributing you agree your work is licensed under MIT or Apache-2.0, at the
user's option, like the rest of the project. No CLA.
