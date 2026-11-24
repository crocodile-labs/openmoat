# ADR-125: Lockfiles checked as direct dependencies are

Status: accepted · Date: 2026-11-24 · Builds on ADR-055 (the content checks of
`openmoat policy check-diff`), ADR-030 (popular-package lists and near misses), ADR-050
(the merge check)

## Context

`openmoat policy check-diff` read lockfiles (`package-lock.json`, `npm-shrinkwrap.json`,
`pnpm-lock.yaml`, `yarn.lock`, `Cargo.lock`, `poetry.lock`, `uv.lock`) for two things: an
entry resolved from git, plain http or another host (`diff-package-source`), and a hash
changed or removed while the version stays (`diff-lock-integrity`). The name of each
locked package was never checked, nor an install script the lockfile records, and `go.sum`
was not read at all. A manifest names only direct dependencies; a look-alike that one of
them pulls in, or a transitive package that starts running a script at install, appears in
the lockfile alone, often in a large generated diff a reviewer skims.

## Decision

1. **Every new or changed entry's name** gets the manifests' near-miss test
   (`packages::near_miss`, the same bundled lists, `diff-package-near-miss`, review), once
   per name per lockfile. The name is read from the line that opens or names the entry:
   npm's `"node_modules/…/<name>": {` (the last package of a nested path), pnpm's
   two-space keys in both lockfile versions (`/name@1.2.3:`, `name@1.2.3:`,
   `'@scope/name@1.2.3':`), yarn's top-level keys (v1 `name@^1, name@^1.2:` and berry
   `"name@npm:^1":`), `name = "…"` in `Cargo.lock`, `poetry.lock` and `uv.lock`, and the
   module of a `go.sum` line.
2. **An install script the lockfile records** is `diff-install-script` (review):
   `"hasInstallScript": true` in `package-lock.json`, `requiresBuild: true` in
   `pnpm-lock.yaml`. The reason names the package when the entry's name line is part of
   the same run of added lines, and says "a locked package" otherwise, so a flag added to
   an entry whose name line was kept is never pinned on a neighbour.
3. **`go.sum`** is a lockfile: a block that removes `module version h1:X` and adds the
   same module and version with another hash is `diff-lock-integrity` (deny), as for the
   other lockfiles. Go's checksum database refuses such a hash only where it is consulted
   (not for `GOPRIVATE` or `GONOSUMDB` modules, nor with `GOSUMDB=off`).
4. **No network.** Everything is read from the lockfile's text in the change: no registry
   is asked for a package's scripts, owner or age, so the same change gives the same
   findings on every machine (ADR-055).

## Consequences

- A look-alike pulled in by a dependency and a new install script deep in the tree are
  named in the merge check, with the line, for a person to look at; neither fails the
  check by default (review).
- A first lockfile, or a regenerated one, has every entry as an added line, so every
  name is checked; the near-miss test leaves popular names and names far from every
  popular one alone, and this repository's own `Cargo.lock` and a slice of a common npm
  tree are benign fixtures.
- Not covered: yarn and `Cargo.lock` record no install script flag, and pnpm 9 dropped
  `requiresBuild`; a package that is malicious under a name of its own; a changed owner
  or publish date, which only the registry knows.
