# Quarantined tests

A test that fails at random on `main` (CI opens an issue for one that needed a
retry) may be held here while it is fixed. CI's runs leave every test in the
table out (`scripts/ci/quarantine.py` turns the table into a nextest filter),
and the weekly workflow runs them on their own, reported but never failing.

Rules:

- Fix it or delete it within 14 days of `first red`; past that, CI warns on
  every run until the row goes.
- Never a test of the sandbox, a deny or a bypass (the tests `profile.ci` of
  `.config/nextest.toml` never retries): one that fails at random is a hole,
  and is fixed, not held. `quarantine.py` refuses them.
- Never your own pull request's new failure: quarantine only what fails on
  `main` without a change to it.
- One row per test: the nextest binary id, the full test name, how it fails,
  the date it first failed on `main`, who fixes it and the issue.

| binary id | test | failure signature | first red | owner | issue |
|---|---|---|---|---|---|
