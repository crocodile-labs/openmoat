//! The words of OpenMoat's own checks (ADR-059): the rules no policy holds,
//! which decide a call from what the session did, the lock, the hook payload
//! or OpenMoat itself. Their block message reads like a policy rule's, from
//! this one table.
//!
//! The rule ids that only allow or defer (`approved-session`, `session-start`,
//! `settings-drift`, …), the policy's own defaults (`default.<kind>`) and the
//! refusals that never reach a host's reason field (`openmoat mcp proxy`,
//! `openmoat proxy`, `policy check-diff`, the sandbox profiles) have none.

use openmoat_core::Verdict;

use super::Words;
use crate::commands::guard::{KERNEL_ERROR_RULE, UNGOVERNED_RULE};

/// One check's words. `next` is the person's step for a decision of the
/// check's own verdict, where the verdict's step would not fit.
struct Check {
    rule: &'static str,
    title: &'static str,
    why: &'static str,
    next: Option<(Verdict, &'static str)>,
}

/// Every check that can deny a call or hold it for review, in no order.
const CHECKS: &[Check] = &[
    Check {
        rule: openmoat_core::INJECTED_RULE,
        title: "acting on a command, host or path from content the agent read",
        why: "it may follow an instruction planted in a page or a file, not one you gave",
        next: Some((
            Verdict::Review,
            "approve it in this prompt only if you asked for it yourself",
        )),
    },
    Check {
        rule: openmoat_core::TAINT_RULE,
        title: "writing or sending after the session read untrusted content or a secret",
        why: "what the agent read can steer it, and a secret it read can leave with the next send",
        next: None,
    },
    Check {
        rule: crate::session_code::RULE,
        title: "running code this session wrote, with no OS sandbox below the hook",
        why: "the hook sees the command that starts the code, not what the code does",
        next: Some((
            Verdict::Review,
            "approve it in this prompt only if you know what that code does",
        )),
    },
    Check {
        rule: openmoat_core::mcp_flow::FLOW_RULE,
        title: "passing one MCP server's output to another server's tool",
        why: "a tool result can carry instructions that send your data somewhere else",
        next: None,
    },
    Check {
        rule: crate::mcp::SERVER_RULE,
        title: "using an MCP server whose definition changed since you accepted it",
        why: "a changed server can run other code, or offer other tools than the ones you checked",
        next: Some((
            Verdict::Deny,
            "if you made that change, accept it in your terminal with `openmoat mcp accept`",
        )),
    },
    Check {
        rule: crate::integrity::INTEGRITY_RULE,
        title: "any call while OpenMoat's own files differ from their pins",
        why: "a changed policy, hook or setting may not be the one you set up, so nothing runs",
        next: Some((
            Verdict::Deny,
            "run `openmoat doctor` in your terminal to see what changed",
        )),
    },
    Check {
        rule: crate::protection::required::RULE,
        title: "any call while this agent runs below the protection level the policy requires",
        why: "without what is missing, fewer of OpenMoat's checks hold, and the policy says that \
              is not enough",
        next: Some((
            Verdict::Deny,
            "in your terminal, take the step the rule line names after `to meet it`",
        )),
    },
    Check {
        rule: KERNEL_ERROR_RULE,
        title: "a call OpenMoat could not check",
        why: "a call that cannot be checked or recorded is not let through",
        next: Some((
            Verdict::Deny,
            "run `openmoat doctor` in your terminal to see what went wrong",
        )),
    },
    Check {
        rule: "unparseable",
        title: "a call OpenMoat could not read in full",
        why: "what OpenMoat cannot read, it cannot check",
        next: None,
    },
    Check {
        rule: openmoat_core::UNCHECKED_RULE,
        title: "a call the agent showed OpenMoat only in part",
        why: "OpenMoat cannot check the part the hook does not show",
        next: None,
    },
    Check {
        rule: openmoat_core::HOLDS_PROTECTED_RULE,
        title: "acting on a folder that holds files your policy denies",
        why: "a copy, move or archive of the folder takes those files with it",
        next: None,
    },
    Check {
        rule: "executables",
        title: "running a program from somewhere other than where it was pinned",
        why: "a program planted under a known name runs with the trust that name has",
        next: Some((
            Verdict::Deny,
            "check in your own terminal which program that name runs now",
        )),
    },
    Check {
        rule: crate::push::SECRET_RULE,
        title: "pushing commits that hold a secret",
        why: "a push publishes every commit it sends, and a published secret cannot be taken back",
        next: Some((
            Verdict::Deny,
            "take the secret out of those commits before anyone pushes them",
        )),
    },
    Check {
        rule: crate::push::RUNS_LATER_RULE,
        title: "pushing changes CI runs, after the session read untrusted content or a secret",
        why: "CI or a tool runs what the push changes later, with the repository's secrets",
        next: None,
    },
    Check {
        rule: crate::push::UNCHECKED_RULE,
        title: "a push OpenMoat could not check",
        why: "OpenMoat could not see what the commits it sends hold",
        next: None,
    },
    Check {
        rule: crate::project_settings::RULE,
        title: "loading project settings that could turn OpenMoat off or run a program",
        why: "a project's settings file is input the agent or a repository can write",
        next: Some((
            Verdict::Deny,
            "check the file and remove what you did not add",
        )),
    },
    Check {
        rule: UNGOVERNED_RULE,
        title: "using a tool OpenMoat does not check",
        why: "OpenMoat cannot tell what this tool does",
        next: None,
    },
];

/// The words of OpenMoat's own check `rule`; `None` for any other id.
pub fn words(rule: &str) -> Option<Words<'static>> {
    CHECKS.iter().find(|c| c.rule == rule).map(|c| Words {
        title: c.title,
        why: Some(c.why),
        next: c.next,
    })
}

/// The ids of every check with words, for the tests.
#[cfg(test)]
pub fn rules() -> impl Iterator<Item = &'static str> {
    CHECKS.iter().map(|c| c.rule)
}
