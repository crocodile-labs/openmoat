# ADR-024: A pure-Rust YAML parser behind one module

Status: accepted · Date: 2026-10-12

## Context

`openmoat-core` parsed every policy with `serde_yaml_ng`, which runs on
`unsafe-libyaml`, a C-to-Rust translation of libyaml full of `unsafe` code.
RUSTSEC-2024-0449 marks it unmaintained, with no safe upgrade. The parser reads
the security policy on every `moat guard` call, and it reads repository
policies (ADR-022), which an agent working in the repository can write. A flaw
found in it later would not be fixed.

## Decision

- The core parses and writes YAML with `serde-saphyr`: pure Rust,
  `#![forbid(unsafe_code)]`, on the maintained `granit-parser` YAML 1.2
  parser, MIT OR Apache-2.0. The other candidates and why they lost are in
  pull request #488's description.
- Every caller goes through `openmoat_core::yaml::{from_str, to_string}`; no
  other code names the parser crate, so the next change of parser is one file.
- That module keeps parsing strict: only `true` and `false` are booleans
  (YAML 1.1's `yes`, `no`, `on`, `off` are not), duplicate keys are errors in
  every mapping, merge keys (`<<`) and unknown tags are errors, and `!!binary`
  text is not decoded. Unknown fields stay errors through
  `deny_unknown_fields`. Errors are one line and name the line and column.

## Consequences

- `unsafe-libyaml` is gone from the dependency tree, and cargo-deny no longer
  needs to ignore the advisory.
- A mapping that repeats a key (in `defaults`, say) is now rejected; it used to
  keep the last value.
- A quoted number or `"true"` is accepted where the schema wants a number or a
  boolean, with the value it spells; it used to be a type error.
- Parse error texts changed wording; nothing matches on them except tests.
