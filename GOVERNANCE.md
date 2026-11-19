# Governance

How decisions about OpenMoat are made today, and how that is meant to change as more
people take part. The working rules for changing the code are in
[AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Decisions today

OpenMoat has one maintainer. The maintainer reviews and merges every pull request,
decides what goes into a release and sets the order of work on the roadmap
([docs/ROADMAP.md](docs/ROADMAP.md); the live order is in issue #562).

How a decision is made and kept:

- Day-to-day changes are decided in the pull request: the change, its **Testing** and
  **Security impact** sections, and the review.
- A decision that changes an invariant, the policy semantics, an exit code, a crate
  boundary or a file format is written down as an ADR in [docs/adr/](docs/adr/README.md),
  in the same pull request. An accepted ADR is not edited; a later ADR supersedes it.
- A disagreement is raised in the issue or pull request. The maintainer decides, and
  says why in the thread. Where security and convenience pull apart, the safer choice
  wins (`review` over `allow`, `deny` over a crash, [AGENTS.md](AGENTS.md) §1).

`.github/CODEOWNERS` lists the paths that need the maintainer's review: the trusted
core, the default policy, the conformance fixtures, `SECURITY.md`, the workflows and the
scripts they run.

## Becoming a maintainer

There is no fixed number of contributions. A contributor is invited to become a
maintainer after a record of merged pull requests and reviews that shows:

- changes that meet the definition of done in [AGENTS.md](AGENTS.md) §6 without being
  asked, tests and docs included;
- care for the security claims: no widening without an attack fixture, and honest
  descriptions of what a change does not cover;
- reviews of other people's pull requests that find real problems.

The invitation comes from the existing maintainers and is recorded in a pull request
that adds the person to `.github/CODEOWNERS`. A maintainer who wants to step back says
so, and the same kind of pull request removes them.

With a second maintainer, changes to the paths CODEOWNERS marks as trusted (the core,
the default policy, the conformance fixtures, the workflows) are meant to need the
approval of two maintainers; that rule is not enforced while there is one.

## Security reports

Vulnerabilities are reported privately, never in public issues. How to report, what
counts as a vulnerability, the response times and how fixes ship are in
[SECURITY.md](SECURITY.md). Every confirmed bypass becomes a conformance fixture
before its fix is published.

## Releases

Releases are cut by a maintainer, following
[CONTRIBUTING.md "Releasing"](CONTRIBUTING.md#releasing):

1. a pull request that bumps the versions and folds the changelog fragments into
   `CHANGELOG.md`;
2. after it is merged, a signed `v*` tag, which only repository admins can create;
3. the release workflow builds and attests every artefact, and publishing to crates.io
   waits for a maintainer's approval of the `release` environment.

Security fixes go to the latest minor release line only, as [SECURITY.md](SECURITY.md)
says.

## Changing this document

This document changes through a pull request like any other, reviewed by the
maintainers.
