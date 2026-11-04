# ADR-012: `!` exclusions in shell pattern lists

Status: accepted · Date: 2026-10-05

## Context

Shell rules are token prefixes, so an allow such as `find *`, `rg *` or `git fetch*` also
allows every option of that program, including options that run another program or write a
file: `find . -exec sh -c '…' \;`, `find . -delete`, `rg --pre=sh`, `git fetch
--upload-pack=cmd`, `go test -exec cmd`, `cargo test --config build.rustc-wrapper=…`. Evaluation
is `deny → allow → review`, so a review rule cannot take these back from an allow; the only
policy tools were deny (too strong for `find . -delete` inside a project) or dropping the
allow (too weak for everyday `find . -name`). Glob lists already support `!` exclusions
(`fs.write: ["${project}/**", "!${project}/.git/**"]`).

## Decision

- A shell pattern starting with `!` is an exclusion, with the same semantics as glob lists:
  within one list of one group, a command matches when at least one positive pattern matches
  and no exclusion does. This holds in `deny`, `allow` and `review`.
- The default `dev-shell` allow excludes `find … -exec/-execdir/-ok/-okdir/-delete/-fprint*/-fls`,
  `rg … --pre`, `git … --upload-pack/--receive-pack`, `go … -exec/-toolexec/-vettool` and
  `cargo … --config`. Those commands fall through to `review`.
- Independently, the classifier surfaces what such options do: the command after
  `find -exec …` is classified as a command of its own, and an `--output=FILE` value is an
  `fs.write` (`shell/options.rs`).

## Consequences

- Allow rules can be broad and still leave dangerous options to `review`. Deny stays absolute: an
  exclusion only removes matches from its own list, it never turns a deny into an allow.
- `policy lint` does not assume a list with exclusions covers anything, so shadowing warnings
  stay conservative.
- The exclusion lists are per program and incomplete by nature; every program that can run
  code through an option is a candidate. OS enforcement (`moat exec`) bounds what slips through.
