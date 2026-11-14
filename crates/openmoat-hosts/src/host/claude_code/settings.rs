//! The keys of Claude Code's `settings.json` that may change while the guard
//! keeps deciding ([`InstallSpec::relaxed_keys`], compared key by key:
//! [`RelaxedCheck::ByKey`]), and the one left out of its digest
//! ([`InstallSpec::unpinned_keys`]).
//!
//! Each key below changes only how Claude Code looks, words its replies, which
//! model answers, or whether Claude Code asks the person itself. None runs a
//! program, loads code, sets the endpoint, or changes a hook, and the
//! `PreToolUse` hook still decides every call: Claude Code runs it in every
//! permission mode and a hook deny is final whatever these say. Any key not
//! listed is drift that denies every call until a person re-pins.
//!
//! [`InstallSpec::relaxed_keys`]: crate::InstallSpec::relaxed_keys
//! [`InstallSpec::unpinned_keys`]: crate::InstallSpec::unpinned_keys
//! [`RelaxedCheck::ByKey`]: crate::RelaxedCheck::ByKey

use crate::contract::RelaxedKey;

/// Claude Code writes `theme` on first run and whenever the person picks a
/// theme, and it changes only colours (#287).
pub(super) const UNPINNED_KEYS: &[&str] = &["theme"];

/// The modes in which Claude Code still asks the person before a call the
/// hook deferred runs: `default` asks, `plan` runs nothing, `dontAsk` refuses
/// what no allow rule names. `acceptEdits` writes files unasked, `auto` lets a
/// classifier run calls unasked and `bypassPermissions` runs every call
/// unasked, so a change to one of them (or to any value not listed here) is
/// drift: a deferred call would then run with nobody asked.
const PROMPTING_MODES: &[&str] = &["default", "plan", "dontAsk"];

pub(super) const RELAXED_KEYS: &[RelaxedKey] = &[
    // The JSON schema an editor validates the file with; Claude Code ignores it.
    RelaxedKey::any("$schema"),
    // Whether and how long the model thinks: same model, same endpoint.
    RelaxedKey::any("alwaysThinkingEnabled"),
    RelaxedKey::any("effortLevel"),
    // The text Claude Code adds to commits and pull requests.
    RelaxedKey::any("attribution"),
    RelaxedKey::any("includeCoAuthoredBy"),
    // Not `autoMode`: its rules tell Claude Code's auto-mode classifier which
    // calls to run unasked, and a call the hook defers is then run on their
    // word, as under a `defaultMode` that does not ask (`PROMPTING_MODES`).
    // How long Claude Code keeps its transcripts; OpenMoat's audit log is its own.
    RelaxedKey::any("cleanupPeriodDays"),
    // The language and style of replies: wording only.
    RelaxedKey::any("language"),
    RelaxedKey::any("outputStyle"),
    // Display only: motion, spinner, turn timing, the terminal's progress bar.
    RelaxedKey::any("prefersReducedMotion"),
    RelaxedKey::any("showTurnDuration"),
    RelaxedKey::any("spinnerTipsEnabled"),
    RelaxedKey::any("spinnerTipsOverride"),
    RelaxedKey::any("spinnerVerbs"),
    RelaxedKey::any("terminalProgressBarEnabled"),
    // Whether Claude Code's file picker lists ignored files; the hook decides
    // every read whatever the picker shows.
    RelaxedKey::any("respectGitignore"),
    // Written by Claude Code itself when the person switches models (`/model`,
    // #591). The model is a name: the endpoint it is sent to (`env`), the key
    // (`apiKeyHelper`) and every hook stay pinned, so it changes which model
    // answers, never what runs or what OpenMoat allows. A value of any other
    // shape, an object or a list, is drift like any other key's.
    RelaxedKey::string("model"),
    RelaxedKey::scalar("switchModelsOnFlag"),
    // Claude Code's own permission lists and a mode that keeps its prompts.
    // They decide only whether Claude Code asks the person about a call the
    // hook left to it. Left out on purpose: `additionalDirectories`, which
    // also adds directories Claude Code's own sandbox lets commands write, so
    // it can widen an OS boundary the guard does not see.
    //
    // The person's own allow list, which Claude Code reads only for calls the
    // hook defers.
    RelaxedKey::any("permissions.allow"),
    RelaxedKey::any("permissions.ask"),
    // Only while every rule OpenMoat wrote stays.
    RelaxedKey::keeping_written_rules("permissions.deny"),
    // Only to a mode in `PROMPTING_MODES`, or removed.
    RelaxedKey::one_of("permissions.defaultMode", PROMPTING_MODES),
    // Narrows what sandboxed commands and file tools may read. Turning it off
    // widens only the OS sandbox, and `moat status` shows the agent as `hook
    // only` while it is off. One guard decision reads the sandbox's state: a
    // call that runs code its session wrote needs review without an OS sandbox
    // (ADR-039); the CLI keys its kept answer by this drift too, so the hold
    // applies as soon as it is off.
    RelaxedKey::any("permissions.blockReadsOutsideWorkingDirectories"),
];
