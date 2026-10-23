# Changelog fragments

One file per user-visible change, so pull requests do not all edit the same block of
`CHANGELOG.md`. The rules are in [CONTRIBUTING.md](../CONTRIBUTING.md#changelog).

- Name: `<pr>-<slug>.md`, for example `712-pi-dialog-timeout.md`.
- First line: the heading the entry goes under, `### Security`, `### Added`,
  `### Changed`, `### Removed` or `### Fixed`.
- Then one line per entry, ending with its pull request link:

```markdown
### Fixed
- pi's dialog no longer waits past the hook timeout ([#712](https://github.com/crocodile-labs/openmoat/pull/712)).
```

`python3 scripts/changelog-check.py` checks every fragment;
`python3 scripts/changelog-assemble.py` folds them into `## [Unreleased]` at release
time and deletes them.
