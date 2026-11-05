# ADR-055: `openmoat policy check-diff` checks what a change's added lines do, offline, with one rule table and levels the policy sets

Status: accepted · Date: 2026-11-05 · Builds on ADR-030 and ADR-050

## Context

ADR-050 made `check-diff` report which protected files a change touches and the
tokens it adds. A pull request an agent writes (or a person, or a fork) does its harm
through what those files then hold, and much of that is in files every change edits:
a typo-squatted dependency in `package.json`, a `postinstall` script, a lockfile entry
whose hash or source was swapped while the version stayed, a workflow that runs a
fork's code with the repository's secrets, `curl … | sh` in a build script, a payload
decoded and run, a `.pth` file Python runs on every start, a private key, a new host
the code sends data to. The path check reports `package.json` or a workflow edit as
`review`, but a reviewer then has to find the one line that matters among the many
that do not; a lockfile, a source file or a Dockerfile is not reported at all.

The check runs in CI on untrusted input, so it must be deterministic and offline (the
same change gives the same answer anywhere, and nothing it reads can make it reach
the network), and quiet on the changes of normal work: adding a normal dependency,
upgrading a lockfile, pinning an action, a README link, a test fixture.

## Decision

1. **Pure checks in core.** `openmoat_core::diffscan` holds every content check as a
   pure function over one changed file: its path, its added lines with their numbers,
   and its blocks (each run of removed and added lines with no kept line between
   them, so a lockfile hash can be compared with the one it replaced). The CLI's diff
   parser fills the blocks; nothing else changes in how a diff is read.
2. **One rule table.** `diffscan::RULES` lists every content rule id, its default level
   and what it finds; docs, the policy lint and the CLI read it. The near-miss check
   uses the bundled popular-package lists of ADR-030 (`packages::near_miss`), the same
   function the shell classifier's `package-near-miss` atom uses. Token formats stay
   the push check's scanner (`diff-secret`, ADR-050). The new-host check decides each
   host as a `net` connection with the compiled policy, so the allow list is the
   policy's own (the default `registries` group, the user's `allow` rules); core takes
   that decision as a function and holds no host list of its own beyond names that are
   no endpoint (loopback, RFC 2606/6761 reserved names, schema namespaces). Lockfile
   sources compare against the hosts each registry serves packages from, a fact about
   the registry rather than a policy choice.
3. **The checks** (MERGE_CHECK.md has each with examples):
   supply chain: `diff-package-near-miss`, `diff-install-script`, `diff-package-source`
   (review), `diff-lock-integrity` (deny); CI takeover in GitHub workflows and action
   files: `diff-ci-pr-target` (deny with a head checkout, review alone),
   `diff-ci-permissions`, `diff-ci-unpinned` (review), `diff-ci-injection` (deny for
   fields an author writes, review for other event fields and inputs),
   `diff-ci-secret-out` (deny printed, review handed to curl); backdoors:
   `diff-pipe-to-shell`, `diff-docker-remote-add`, `diff-encoded-blob` (review),
   `diff-decode-exec`, `diff-python-startup` (deny, review in tests and fixtures); secrets: `diff-private-key` (deny,
   review in a test fixture, prose or marked fake), `diff-env-secret` (review); network:
   `diff-new-host` (review, one finding per host for the whole change, a host the
   change also removes is not new). Deny is kept for what a change should never do
   unnoticed and has no ordinary use; anything with an ordinary use is review.
4. **Noise is a design input.** Prose files are not read by the backdoor and host
   checks (a README's `curl … | sh` runs nothing), tests and fixtures carry no new
   hosts and their attack samples are review, comment lines carry no hosts,
   `key: ${{ … }}` lines are data (the recommended fix for script injection), a secret
   written to a file or piped to a program is handed on rather than printed, a version
   bump that changes a hash is an upgrade, base64 in tests, minified bundles and
   `data:image/` URIs is not a blob. Every check has benign fixtures for the changes
   nearest to its attack.
5. **Levels from the policy.** A new `check_diff:` section of the user policy,
   `levels: { <rule id>: deny | review | off }`, sets the level of every finding of a
   rule. `policy lint` rejects an unknown id and warns about each `off`. A repository
   policy cannot set levels (ADR-022: it only adds rules). The path rules keep their
   levels from the policy's rule groups, as before.
6. **Output unchanged in form.** Each content finding is an ADR-050 finding with the
   file, the added line, the rule id and a reason; text shows `path:line`, JSON has
   `line`, GitHub annotations carry `line=` so the annotation lands on the added line.
   Exit codes are unchanged (deny 2, review 3).

## Alternatives

- **Content findings as engine atoms** (`@diff …` atoms decided by `review`/`deny`
  groups, as `@package-near-miss` is): levels would come from rule groups, but the
  atoms would sit in the shell atom space an agent's command could imitate, and every
  rule would need a group in the default policy, which every installed policy would
  have to upgrade to. A table with a level map gives the same control without either.
- **Parsing each file format fully** (JSON, TOML, YAML, the lockfile formats): more
  precise for the lines it covers, but a diff holds added lines, not whole files, and
  the core takes no new parser dependency (AGENTS.md). Line shapes cover the common
  cases; the limits say what they miss.
- **Looking packages up online** (release age, existence, maintainers): not offline
  and not deterministic. `moat run`'s release-age gate (ADR-030) covers young versions
  at install time.

## Limits

- Added lines only: a workflow that already had `pull_request_target` and gains only a
  head checkout is reported by the path rule, not `diff-ci-pr-target`; a line is
  judged by its shape, so an unusual layout can be missed and an unusual benign line
  matched.
- Text patterns, not program analysis: a payload assembled at run time is not found.
- GitHub workflows only for the CI checks; GitLab and others get path and backdoor checks.
- No network: version age, package existence, URL contents are not checked.
- `diff-lock-integrity` also reports an old npm lockfile rewritten from sha1 to sha512
  for the same version; in `Cargo.lock`, a version change up to three lines above a
  checksum counts for it (the `source` line sits between them).
- Tests and fixtures hold attack samples as data: there `diff-decode-exec`,
  `diff-python-startup` and `diff-private-key` are review, and hosts are not read, so a
  test that CI runs and that sends data to a new host is not reported by
  `diff-new-host`.

## Consequences

- A pull request that swaps a lockfile hash, takes over CI or runs decoded code fails
  with `fail-on: deny`; one that adds a near-miss dependency, an unpinned action or a
  new host needs review. Changes of normal work stay as ADR-050 reports them.
- `openmoat-core` (library API, breaking): the public module `diffscan` and the
  `Policy` field `check_diff`. The policy format gains the optional `check_diff:`
  section; an older OpenMoat rejects a policy that uses it.
