# Checking pull requests before merge

OpenMoat's hook checks each tool call while an agent works. A pull request is the
other place to check: it holds what an agent wrote (on a machine with OpenMoat or
without it) and what people and forks wrote. `openmoat policy check-diff` reads a
change and reports:

- every file it adds, edits, deletes or renames that the policy protects: CI
  workflows, git hooks and hook managers, build and package files (`package.json`,
  `Makefile`, `Cargo.toml`, `pyproject.toml`, …), agent instructions, settings, hooks
  and MCP server lists (`CLAUDE.md`, `.claude/`, `.mcp.json`, `.cursor/`, …),
  OpenMoat's own files (`.moat/`) and secret files (`.env`);
- every added line that holds a known token format (GitHub, OpenAI and Anthropic, AWS
  access key ids, Slack, Google API, npm, GitLab), without printing the token;
- symbolic links and where they point, submodule changes, and paths that leave the
  repository.

It uses the same rules as the hook (the default policy, or yours), so the lists of
protected files are the ones in [POLICY.md](POLICY.md). The decision is recorded in
[ADR-050](adr/ADR-050-merge-check.md).

## Levels and exit codes

| Level | Exit code | Meaning |
|---|---|---|
| `deny` | 2 | the policy denies an agent this write (`kernel-self`, `secrets-paths`), the change adds a token, or a path leaves the repository |
| `review` | 3 | a person should look before merging: a file that CI, a build, a commit hook or an agent runs or reads later, a link, a submodule, a policy file |
| clean | 0 | nothing the policy protects |
| error | 64 | the change or a policy could not be read; never reported as clean |

## Run it locally

```bash
openmoat policy check-diff --base origin/main             # this branch against main
openmoat policy check-diff --base main --head feature --format json
git diff main | openmoat policy check-diff                # any unified diff on stdin
openmoat policy check-diff --base main --policy ci/openmoat.yaml
```

With `--base`, the change is everything from the commit `--base` and `--head` share
to `--head`, as a pull request shows it. Without `--policy`, the shipped default policy
is used, not the one installed in `~/.moat`, so every machine gives the same answer.

## The policy cannot be loosened by the change it checks

With `--base`, the policy files are read as the base revision has them, with git, not
from the checked-out files:

- `--policy <path>`, when the path is relative (a file of the repository);
- the repository's `.moat/policy.yaml`, whose `deny` and `ask` rules are added, as the
  hook adds them for an untrusted repository ([POLICY.md](POLICY.md) §10).

A change to either file is reported (`diff-policy`) and applies from the next change
after it is merged. A diff on stdin has no base revision: `--policy` is read from disk
and no repository policy is read.

## On GitHub

The repository has a composite action at its root. Add this workflow to your
repository as `.github/workflows/openmoat.yml`. Pin the action to the full commit SHA
of an OpenMoat release tag, and set `version` to that release:

```yaml
name: openmoat
on:
  pull_request:

permissions:
  contents: read

jobs:
  merge-check:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0             # the base and head commits and what they share
          persist-credentials: false
      - uses: crocodile-labs/openmoat@<full commit SHA of the release tag> # v<version>
        with:
          version: <version>         # the same release, without the leading v
          fail-on: review            # review (default), deny or never
          # policy: ci/openmoat.yaml # read as the pull request's base has it
```

The action downloads that release for the runner (Linux or macOS, x64 or arm64),
checks the archive's sha256 against the release's `sha256.sum` and its build
attestation with `gh attestation verify` (as [INSTALL.md](INSTALL.md) describes), and
runs `openmoat policy check-diff` on the pull request's base and head. Every finding
becomes an annotation on the pull request: `deny` as an error, `review` as a warning.

| Input | Default | What it does |
|---|---|---|
| `version` | none (required) | the OpenMoat release to run |
| `fail-on` | `review` | fail the step on anything found (`review`), only on `deny`, or `never` |
| `policy` | the default policy | a policy file in the repository, read as the base has it |
| `base`, `head` | the pull request's base and head commits | the revisions to compare |
| `token` | `github.token` | what `gh attestation verify` reads the attestation with |

The output `result` is `clean`, `review` or `deny`. Use the `pull_request` event, not
`pull_request_target`: the check needs no secrets, and `pull_request_target` runs with
the base repository's token while it reads code from the pull request.

## Example output

A pull request that changes a workflow trigger, sets hooks in `.claude/settings.json`,
adds a `postinstall` script and edits one source file:

```
review  .github/workflows/ci.yml [runs-later, session-taint]
        CI, commit hooks, the editor or the agent host run this later, outside any sandbox: write .github/workflows/ci.yml
        CI, a build or test tool, a commit hook or an AI agent runs or reads this file later
deny    .claude/settings.json [kernel-self]
        OpenMoat protects its own policy, hooks and binary: write .claude/settings.json
review  package.json [session-taint]
        CI, a build or test tool, a commit hook or an AI agent runs or reads this file later
deny: 1 deny, 2 review in 4 changed files (checked against the default policy)
```

Under GitHub Actions (`--format github`, the default there) the same findings come
first as workflow commands:

```
::warning file=.github/workflows/ci.yml,title=OpenMoat review%3A runs-later%2C session-taint::CI, commit hooks, the editor or the agent host run this later, outside any sandbox: write .github/workflows/ci.yml; CI, a build or test tool, a commit hook or an AI agent runs or reads this file later
::error file=.claude/settings.json,title=OpenMoat deny%3A kernel-self::OpenMoat protects its own policy, hooks and binary: write .claude/settings.json
::warning file=package.json,title=OpenMoat review%3A session-taint::CI, a build or test tool, a commit hook or an AI agent runs or reads this file later
```

`--format json` prints one document: `result`, `files`, `policy`,
`repository_policy` and `findings`, each with `level`, `path`, `line` (for an added
line), `rules` and `reasons`.

## Rule ids

The engine's rule ids appear as in the hook (`kernel-self`, `runs-later`,
`session-taint` for the files session taint protects, `repo:<id>` for the
repository policy). The check adds:

| Rule id | Level | When |
|---|---|---|
| `diff-secret` | deny | an added line holds a known token format |
| `diff-path` | deny | a path is absolute, leaves the repository (`../`) or is not a file name |
| `diff-policy` | review | the change edits a policy file the check read |
| `diff-link` | review | the change makes a symbolic link; where it points is checked too |
| `diff-submodule` | review | the change moves a submodule to another commit |
| `diff-unchecked` | review | the diff is larger than 64 MiB: its paths were checked, its added lines were not searched |

## How paths are compared

- Without letter case: `.GitHub/Workflows/ci.yml` and `.Claude/Settings.json` are the
  protected files on macOS and Windows, so they are reported as those.
- As Windows opens them too: trailing dots and spaces of each name are dropped
  (`.claude./settings.json`), and `\` separates like `/`.
- `.` and `..` are collapsed (`docs/../.github/workflows/ci.yml` is the workflow).
- A renamed file is checked under its old and its new name; a deleted file is checked
  too (deleting a security scan workflow is a change to CI).

## Limits

- It checks which files change and what lines are added, not what a program does. A
  source file that a build or a test runs is code like any other and is not flagged,
  and neither is a script that a flagged file (`package.json`) already named before the
  change.
- Binary files are not searched for tokens; their paths are checked.
- With `--base`, renames are read as a deletion and an addition, so a renamed file's
  whole content is searched and both names are checked. A diff on stdin may describe a
  rename; both names are checked, and only the lines it adds are searched.
- Only token formats with a vendor prefix are found: a password, a private key or a
  token without a known prefix is not. Commit messages are not searched.
- A submodule's code, and what a symbolic link points to outside the repository, are
  not read.
- `~/` rules do not apply to repository paths, so a repository whose files are copied
  into a home directory (dotfiles) is checked as an ordinary project. Windows short
  names (`GITHUB~1`) are not expanded.
- The action runs on Linux and macOS runners.
- A finding is a report, not a block on merging: make the job a required status check
  to hold merges until it passes, and merge past it when a person meant the change.
