# Checking pull requests before merge

[README](../README.md) · [Docs index](README.md) · [openmoat.dev/docs](https://openmoat.dev/docs/)

> [!NOTE]
> **Read this when** you want to check pull requests before merge.

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
  repository;
- what the added lines do ([content checks](#content-checks)): a typo-squatted or
  off-registry dependency, an install script, a lockfile hash swapped for the same
  version, a CI workflow a pull request can take over, a script downloaded or decoded
  and run, a private key, and every new host the code connects to that your network
  allow list does not name.

It uses the same rules as the hook (the default policy, or yours), so the lists of
protected files are the ones in [POLICY.md](POLICY.md). It runs offline: nothing is
looked up on the network, so the same change gives the same report everywhere. The
decisions are recorded in [ADR-050](adr/ADR-050-merge-check.md) and
[ADR-055](adr/ADR-055-check-diff-content-checks.md).

## Levels and exit codes

| Level | Exit code | Meaning |
|---|---|---|
| `deny` | 2 | the policy denies an agent this write (`kernel-self`, `secrets-paths`), the change adds a token or a private key, a path leaves the repository, or a content check finds what should never be merged unnoticed (a swapped lockfile hash, a CI takeover, decoded code that runs) |
| `review` | 3 | a person should look before merging: a file that CI, a build, a commit hook or an agent runs or reads later, a link, a submodule, a policy file, or a content check's review finding (a near-miss dependency, an unpinned action, a new host) |
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
- the repository's `.moat/policy.yaml`, whose `deny` and `review` rules are added, as the
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
| `diff-unchecked` | review | with `--base`, the diff is larger than 64 MiB: its paths were checked, its added lines were not searched (a diff on stdin that large is an error, exit 64) |

The content checks add the rule ids in the next section.

## Content checks

Each finding names the file and the added line (`path:line` in text, `line` in JSON
and in the GitHub annotation), a stable rule id, a level and a short reason. A secret's
value is never printed.

### Supply chain

Package manifests (`package.json`, `requirements*.txt`, `constraints*.txt`,
`pyproject.toml`, `Cargo.toml`, `go.mod`, `Gemfile`, `*.gemspec`) and lockfiles
(`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`,
`Cargo.lock`, `poetry.lock`, `uv.lock`).

| Rule id | Level | When |
|---|---|---|
| `diff-package-near-miss` | review | an added dependency is not on the bundled list of popular names but is one typo or trick away from one (`lodahs`, `reqeusts`, `python-dateutils`); the same lists and test as the hook's `package-near-miss` |
| `diff-install-script` | review | `package.json` sets `preinstall`, `install`, `postinstall` or `prepare`, which npm runs on install; the reason shows the command |
| `diff-package-source` | review | a dependency from git, a URL or `owner/repo` instead of its registry (`"x": "git+https://…"`, `x @ https://…`, `{ git = "…" }`, `gem "x", git:`, a `replace` in `go.mod`, a Gemfile `source` other than rubygems.org), or a lockfile entry resolved from git, plain http or a host that is not the registry; once per place per lockfile |
| `diff-lock-integrity` | deny | a lockfile's `integrity`, `checksum` or `hash` changes or is removed in a block where the package's version does not change (for `poetry.lock` and `uv.lock`: the same file name with another hash) |

```
review  web/package.json:14 [diff-package-near-miss]
        adds the npm dependency `lodahs`, one typo or trick away from the popular `lodash`, as typo-squats and made-up names are; check which one is meant
deny    package-lock.json:2041 [diff-lock-integrity]
        changes a package's integrity hash while its version stays: the next install accepts other code under the same version (…)
```

### CI takeover

GitHub workflow files (`.github/workflows/*.yml`) and action definitions
(`action.yml`).

| Rule id | Level | When |
|---|---|---|
| `diff-ci-pr-target` | deny | the change adds `pull_request_target` and a checkout of the pull request's code (`ref: ${{ github.event.pull_request.head.sha }}`, `github.head_ref`, `refs/pull/…`, `gh pr checkout`); review for the trigger alone |
| `diff-ci-permissions` | review | `permissions: write-all`, or any `<scope>: write` (one finding per file, naming the scopes) |
| `diff-ci-unpinned` | review | `uses:` an action at a tag or branch instead of a full 40-character commit SHA, or a `docker://` image without a digest; local actions (`./…`) are fine |
| `diff-ci-injection` | deny | a field the author of a pull request, issue or comment writes (`title`, `body`, `message`, `head_ref`, `head.ref`, `head.label`, commit author names and mails, `page_name`) expanded with `${{ }}` inside `run:` or `script:`; review for other `github.event.*` fields and `inputs.*` |
| `diff-ci-secret-out` | deny | `${{ secrets.* }}` printed in a script (`echo`, `printf`, `console.log`, …) or `toJSON(secrets)`; review when it is handed to `curl` or `wget` |

`${{ }}` in a `key: value` line (`env:`, `with:`, `if:`) is data, not script, and is not
reported: moving an expression into `env:` and using the variable is the fix.

```
deny    .github/workflows/greet.yml:12 [diff-ci-injection]
        expands `${{ github.event.issue.title }}`, text a pull request's or issue's author writes, into a script, where it runs as code; pass it through `env:` and use the variable instead
```

### Backdoors

Every file but prose (`.md`, `.rst`, `.txt`, …) and lockfiles.

| Rule id | Level | When |
|---|---|---|
| `diff-pipe-to-shell` | review | a download piped or substituted into a shell or interpreter (`curl … \| sh`, `bash <(curl …)`, `sh -c "$(wget …)"`, `iwr … \| iex`); not `\| jq`, `\| tar`, `\| python3 -m json.tool` |
| `diff-decode-exec` | deny | decoded text run as code: `base64 -d \| sh`, `eval "$(… base64 --decode)"`, `exec(base64.b64decode(…))`, `eval(atob(…))`, `eval(Buffer.from(…, 'base64'))`, PHP `eval(base64_decode(…))`, `powershell -enc <base64>`; review under a test or fixture folder, where attack samples live as data |
| `diff-python-startup` | deny | a `.pth` file with an `import` line, which Python runs on every start once the file is in a site directory (`sitecustomize.py` and `usercustomize.py` are path rules already); review under a test or fixture folder |
| `diff-docker-remote-add` | review | a Dockerfile `ADD` of an `http(s)://` or git URL without `--checksum=` |
| `diff-encoded-blob` | review | 400 or more characters of mixed-case base64 in source code (not tests, not `*.min.*`, not a `data:image/…` URI) |

Git hooks (`.githooks/`, `.husky/`, `.git/hooks/`) are path rules (`runs-later`,
`git-internals`).

### Secrets

| Rule id | Level | When |
|---|---|---|
| `diff-secret` | deny | (above) a known token format with a vendor prefix |
| `diff-private-key` | deny | a PEM `-----BEGIN … PRIVATE KEY-----` header or a PuTTY key; review under a test or fixture folder, in prose, or when the lines it is added with say `fake`, `dummy`, `test key`, `example key`, `not a real` or `do not use` |
| `diff-env-secret` | review | in a `.env`, `.env.*`, `*.env` or `.envrc` file, a variable named like a secret (`*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*API_KEY*`, …) set to 12 or more characters that are not a placeholder (`changeme`, `your-…`, `${VAR}`, `xxxx`) |

### New network endpoints

| Rule id | Level | When |
|---|---|---|
| `diff-new-host` | review | a URL (`http`, `https`, `ws`, `wss`, `ftp`) in an added line of code or configuration names a host the policy's network allow list does not allow; one finding per host for the whole change |

The host is decided as a `net` connection by the same compiled policy, so the default
policy's `registries` group (`github.com`, `registry.npmjs.org`, `pypi.org`, …) and your
own `allow` rules are quiet. Not read: prose, tests and fixtures (folders such as
`tests/`, `fixtures/`, `testdata/`, and files such as `*.test.ts`, `*_test.go`,
`test_*.py`, whose URLs are mostly sample data), manifests and lockfiles, comment lines,
hosts with a template (`https://${HOST}/`), loopback, names reserved for examples and
tests (`example.com`, `*.test`, `*.example`, `*.invalid`, `*.localhost`, `*.local`),
XML and JSON schema namespaces (`www.w3.org`, `json-schema.org`, …), and hosts the
change also removes (a moved line, a moved file).

### Setting the levels

Every content rule's level can be set in the policy that the check reads (`--policy`, or
your own policy file), under `check_diff.levels`: `deny`, `review` or `off`. The same
level then applies to every finding of that rule.

```yaml
version: 1
check_diff:
  levels:
    diff-ci-unpinned: off        # this repository pins actions by tag on purpose
    diff-new-host: deny          # nothing may add an endpoint unnoticed
    diff-package-source: off     # our packages come from a private registry
```

`openmoat policy lint` rejects a rule id that is not a content check and warns about
each rule set to `off`. A repository's `.moat/policy.yaml` cannot set levels: it only
adds rules (ADR-022).

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
- Tokens are found by their vendor prefix, private keys by their PEM or PuTTY header,
  and passwords only as values of `.env` files: a password or a token without a known
  prefix in source code is not found. Commit messages are not searched.
- A submodule's code, and what a symbolic link points to outside the repository, are
  not read.
- `~/` rules do not apply to repository paths, so a repository whose files are copied
  into a home directory (dotfiles) is checked as an ordinary project. Windows short
  names (`GITHUB~1`) are not expanded.
- The content checks read added lines (and, for lockfile hashes, the lines removed
  with them), not whole files: a workflow that already had `pull_request_target` and
  gains only a head checkout is not `diff-ci-pr-target` (the workflow edit is still
  `runs-later`), and a line is taken for a dependency or a script by its shape. They
  match text, not a parse of each language: an obfuscated payload built from pieces
  at run time is not found, and a benign line may match (set the rule's level).
- Nothing is looked up online: how young a package version is, whether a dependency
  exists, who owns a host or what a URL serves are not checked (`moat run` holds
  package versions younger than 7 days, ADR-030). GitLab, CircleCI, Azure and Jenkins
  files get the path rules and the backdoor checks, not the GitHub workflow checks.
  IPv6 literals in URLs, and hosts named only in tests and fixtures (which CI may
  run), are not reported as new hosts.
- The action runs on Linux and macOS runners.
- A finding is a report, not a block on merging: make the job a required status check
  to hold merges until it passes, and merge past it when a person meant the change.
