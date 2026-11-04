# ADR-051: Compliance evidence is a rule → control map in the CLI and a report over the audit log, never a claim of compliance

Status: accepted · Date: 2026-11-04 · Builds on ADR-031

## Context

Teams that let coding agents work on their code are asked by auditors and security
reviewers how they control what the agent does. OpenMoat already holds the answer's raw
material: every decision is in the audit log with the rules that produced it, redacted and
hash-chained (ADR-031), and the policy and lock say what was in force. What a person could
not do was turn that into the shape a review asks for: per control of a framework, which
records relate to it.

Two risks shape the design. A map that stretches (every rule "supports" every control)
gives a reviewer nothing to check, and a report that reads like a certificate makes a claim
OpenMoat cannot make: a rule firing shows the rule operated on that call, not that a
control is designed or operating effectively, and calls that never reached OpenMoat are not
in the log at all.

## Decision

1. **The map is data in one place.** `crates/openmoat-cli/src/compliance.rs` lists rule
   groups (secrets, secret egress, network egress, code execution, packages, code that runs
   later, self-protection, configuration integrity, MCP servers, destructive commands, the
   audit log itself) by rule id, and for each the controls of OWASP Top 10 for LLM
   Applications 2025, the SOC 2 Trust Services Criteria (CC6, CC7, CC8) and ISO/IEC
   27001:2022 Annex A its decisions give evidence for. Rule ids are the default policy's and
   the ones the code adds (`docs/POLICY.md` §5.1). A control is listed only where the rule
   restricts or records the thing the control is about; controls the rules do not serve
   are left out (for example LLM01 Prompt Injection, which OpenMoat does not detect).
2. **The map is tested against the policy.** Every `deny` and `ask` rule of the default
   policy is in exactly one group; no `allow` or `defer` rule is in any (a rule that lets a
   call run is no evidence of a restriction); every other id is documented in POLICY.md
   §5.1; control ids are well formed and none repeats. A new restrictive rule fails the
   tests until someone decides where it belongs.
3. **The map lives in the CLI, not the core.** It is a reporting concern; nothing decides
   by it. Keeping it out of `openmoat-core` and the SDK leaves their public API and the
   pure core unchanged.
4. **`openmoat audit evidence` reports over the existing reader.** It reads the window with
   `Store::export`, the reader `openmoat audit export` uses, so it covers exactly the
   events an export of the window holds, and it verifies the whole chain. For each control
   and rule group it gives decisions by verdict, each event counted once however many of
   the group's rules it names, and sample events as stored (already redacted; denies and
   asks first, newest first). Rules that fired and map to no control are listed so every
   decision is accounted for. It adds the policy file's SHA-256 and whether it is the
   shipped default, each mapped default rule the policy in force lacks ("cannot fire"), the
   lock's state and last pin time, and each agent's protection level (`protection.rs`).
   `--format json` (format `openmoat-evidence-v1`) and Markdown carry the same data.
5. **The report says what it is.** Both formats open with "Evidence, not a
   certification" and the Markdown ends with its limits. The policy, lock and protections
   are their state when the report is made: the audit log does not record which policy
   decided each call, so a lock re-pinned after the window started is flagged.

## Consequences

- A reviewer gets the rule ids, counts and event hashes to check against an export
  (`openmoat audit verify --anchor <hash>`), not a pass/fail.
- A changed policy keeps the map by rule id: a renamed or custom rule shows under "rules
  that map to no control", a removed one as "cannot fire".
- The report covers one machine. Several machines' exports are combined with
  `openmoat audit report`; it does not map controls.
- Recording the policy hash with each event would let the report show what was in force
  per call; that needs an audit schema change and is not part of this decision.
- Control titles are short paraphrases; the frameworks' own texts are the reference.
