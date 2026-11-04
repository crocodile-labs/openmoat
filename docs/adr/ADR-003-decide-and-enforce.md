# ADR-003: v0.1 decides and enforces; the parser is not the security boundary

Status: accepted · Date: 2026-10-02

## Context

A policy decision on a command string can be wrong: quoting tricks, encodings,
interpreters and environment poisoning all create a gap between what the classifier
sees and what the shell executes (CVE-2026-22708 is the public example). A
decide-only release would be a regex firewall and would not survive scrutiny.

## Decision

- v0.1 ships OS enforcement on macOS and Linux: allowed shell commands are rewritten
  by the host adapter to run under `moat exec`, which applies a Seatbelt or
  Landlock+seccomp profile derived from the same policy, with a kernel-controlled
  environment.
- An egress proxy enforces `net` rules; a minimal session taint rule makes any
  network action after a secret read a `review`.
- The parser remains the first layer and the source of explanations, but a parser
  bug is a usability bug, not a security bug, once enforcement is on.
- Windows ships decide-only in v0.1, labelled as such in the coverage matrix.

## Consequences

- Phase 1 is six weeks instead of four.
- `moat-sandbox` and `moat-proxy` are v0.1 crates, not later work.
- Release is gated on the public benchmark (`docs/STRENGTH.md` §3.3).
