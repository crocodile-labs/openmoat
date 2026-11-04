# ADR-005: Own POSIX shell lexer and classifier in `moat-core`

Status: accepted · Date: 2026-10-03 (recorded 2026-10-05)

## Context

Shell rules are only as good as the kernel's view of the command line. Hosts hand over a
raw string; quoting, operators, redirections, `$( … )`, here-documents and `sh -c` nesting
all change what actually runs (`DESIGN.md` §7.2, G2). The options were a word-splitting
crate (`shlex`, `shell-words`), a full bash grammar (`conch-parser`, `tree-sitter-bash`)
or our own lexer. Word splitters drop operators and redirections, so `curl x | sh` and
`cat f > ~/.zshrc` become flat argv. Full parsers bring large dependency trees, and in
some cases C code, into the one crate that must stay pure, build for `wasm32` and be
auditable; most of what they parse (loops, functions, arithmetic) the kernel does not
need and should refuse rather than interpret.

## Decision

- `moat-core` owns a small POSIX lexer (`lexer/`) and classifier (`shell/`): words with
  quotes and escapes, control operators, redirections with descriptors, `$( … )` and
  backticks attached to the containing word, here-documents consumed as data, a 64 KB
  input limit.
- The classifier turns each simple command into atomic actions (`Shell`, `Pipeline`,
  `FsRead`, `FsWrite`, `Net`, `EnvRead`, `EnvSet`); wrappers (`sudo`, `env`, `xargs`, …),
  `sh -c`, `eval` and substitutions recurse to `MAX_DEPTH` 4; output is capped at
  `MAX_ATOMS` 2048.
- Inline interpreter payloads (`python -c`, `node -e`, `pwsh -Command`, …) are not parsed;
  they are scanned for paths, hosts and variable names.
- Anything the lexer or classifier cannot make sense of is `ParseOutcome::Unparseable`,
  which the engine maps to `review` (rule id `unparseable`), never `allow`.
- Shell *patterns* are tokenised by the same lexer, so `a|b` and `a | b` mean the same on
  both sides of a match, and tokens are compared as written (no flag normalisation).

## Consequences

- No parser dependency; the lexer and classifier have their own test modules and are
  exercised end to end by `tests/conformance/`.
- Unknown syntax costs a prompt, not a bypass; the benign corpus measures that cost.
- Until `moat exec` exists (ADR-003) the lexer is a security boundary, so every divergence
  from real `bash` is a finding; differential testing against `bash` is planned
  (`STRENGTH.md` §4.1).
- PowerShell and `cmd` are not tokenised; such lines are lexed as POSIX and fall through
  to the `review` default.
