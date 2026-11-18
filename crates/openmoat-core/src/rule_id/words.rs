//! The words of OpenMoat's own checks (ADR-059): the rules no policy holds,
//! which decide a call from what the session did, the lock, the hook payload
//! or OpenMoat itself. Their block message reads like a policy rule's, and
//! their page on openmoat.dev is made from them.

use super::Words;
use crate::Verdict;

pub(super) const INJECTED_INPUT: Words = Words {
    title: "acting on a command, host or path from content the agent read",
    why: "it may follow an instruction planted in a page or a file, not one you gave",
    next: Some((
        Verdict::Review,
        "approve it in this prompt only if you asked for it yourself",
    )),
};

pub(super) const SESSION_TAINT: Words = Words {
    title: "writing or sending after the session read untrusted content or a secret",
    why: "what the agent read can steer it, and a secret it read can leave with the next send",
    next: None,
};

pub(super) const REQUEST_RULE: Words = Words {
    title: "sending a request your request rules refuse to a host you allow",
    why: "an allowed host can receive your data through an endpoint that publishes it, such as \
          a new gist",
    next: Some((
        Verdict::Review,
        "approve it in this prompt only if you know what the command sends and where",
    )),
};

pub(super) const SESSION_WRITTEN_CODE: Words = Words {
    title: "running code this session wrote, with no OS sandbox below the hook",
    why: "the hook sees the command that starts the code, not what the code does",
    next: Some((
        Verdict::Review,
        "approve it in this prompt only if you know what that code does",
    )),
};

pub(super) const UNATTENDED: Words = Words {
    title: "a call the agent's own prompt would decide, in a mode where it asks no one",
    why: "in that mode the agent runs such a call without a person seeing it, and your policy \
          says `unattended: review`",
    next: Some((
        Verdict::Review,
        "approve it only if you meant the agent to run it unattended",
    )),
};

pub(super) const MCP_CROSS_SERVER: Words = Words {
    title: "passing one MCP server's output to another server's tool",
    why: "a tool result can carry instructions that send your data somewhere else",
    next: None,
};

pub(super) const MCP_SERVER_CHANGED: Words = Words {
    title: "using an MCP server whose definition changed since you accepted it",
    why: "a changed server can run other code, or offer other tools than the ones you checked",
    next: Some((
        Verdict::Deny,
        "if you made that change, accept it in your terminal with `openmoat mcp accept`",
    )),
};

pub(super) const KERNEL_INTEGRITY: Words = Words {
    title: "any call while OpenMoat's own files differ from their pins",
    why: "a changed policy, hook or setting may not be the one you set up, so nothing runs",
    next: Some((
        Verdict::Deny,
        "run `openmoat doctor` in your terminal to see what changed",
    )),
};

pub(super) const PROTECTION_REQUIRED: Words = Words {
    title: "any call while this agent runs below the protection level the policy requires",
    why: "without what is missing, fewer of OpenMoat's checks hold, and the policy says that \
          is not enough",
    next: Some((
        Verdict::Deny,
        "in your terminal, take the step the rule line names after `to meet it`",
    )),
};

pub(super) const KERNEL_ERROR: Words = Words {
    title: "a call OpenMoat could not check",
    why: "a call that cannot be checked or recorded is not let through",
    next: Some((
        Verdict::Deny,
        "run `openmoat doctor` in your terminal to see what went wrong",
    )),
};

pub(super) const UNPARSEABLE: Words = Words {
    title: "a call OpenMoat could not read in full",
    why: "what OpenMoat cannot read, it cannot check",
    next: None,
};

pub(super) const UNCHECKED: Words = Words {
    title: "a call the agent showed OpenMoat only in part",
    why: "OpenMoat cannot check the part the hook does not show",
    next: None,
};

pub(super) const PROTECTED_CONTENTS: Words = Words {
    title: "acting on a folder that holds files your policy denies",
    why: "a copy, move or archive of the folder takes those files with it",
    next: None,
};

pub(super) const EXECUTABLES: Words = Words {
    title: "running a program from somewhere other than where it was pinned",
    why: "a program planted under a known name runs with the trust that name has",
    next: Some((
        Verdict::Deny,
        "check in your own terminal which program that name runs now",
    )),
};

pub(super) const PUSH_SECRET: Words = Words {
    title: "pushing commits that hold a secret",
    why: "a push publishes every commit it sends, and a published secret cannot be taken back",
    next: Some((
        Verdict::Deny,
        "take the secret out of those commits before anyone pushes them",
    )),
};

pub(super) const PUSH_RUNS_LATER: Words = Words {
    title: "pushing changes CI runs, after the session read untrusted content or a secret",
    why: "CI or a tool runs what the push changes later, with the repository's secrets",
    next: None,
};

pub(super) const PUSH_UNCHECKED: Words = Words {
    title: "a push OpenMoat could not check",
    why: "OpenMoat could not see what the commits it sends hold",
    next: None,
};

pub(super) const PROJECT_SETTINGS: Words = Words {
    title: "loading project settings that could turn OpenMoat off or run a program",
    why: "a project's settings file is input the agent or a repository can write",
    next: Some((
        Verdict::Deny,
        "check the file and remove what you did not add",
    )),
};

pub(super) const UNGOVERNED: Words = Words {
    title: "using a tool OpenMoat does not check",
    why: "OpenMoat cannot tell what this tool does",
    next: None,
};
