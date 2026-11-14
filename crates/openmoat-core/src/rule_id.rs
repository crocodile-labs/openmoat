//! Every rule id OpenMoat's own code names: the one place each is written.
//!
//! A decision's rule ids come from three places. The policy's rule groups
//! (`secrets-paths`, a pack's `pack:…`, a repository's `repo:…`, an approval's
//! `approved-…`), whose ids the policy file holds; the policy's defaults
//! ([`DEFAULT`] and [`DEFAULT_PREFIX`] with a kind); and OpenMoat's own
//! checks, which decide from what the session did, the lock, the hook payload
//! or OpenMoat itself, and whose ids are the constants here, listed in
//! [`BUILTIN_RULES`]. The few policy rule ids the code reads by name are in
//! [`POLICY_RULES`]. `policy check-diff`'s content checks keep their own table
//! ([`crate::diffscan::RULES`]).
//!
//! Rule ids are stable: they appear in audit logs, in user output and in the
//! page each block message links to (`https://openmoat.dev/r/<id>`). Every id
//! here is written once, as its constant; the tests (`rule_id/tests.rs`, and
//! `openmoat-hosts`' `tests/architecture/rule_ids.rs` over every crate's
//! source) keep it that way.

use crate::Verdict;

mod words;

/// The policy's default when it gives one verdict for every kind, and the
/// rule of a word that only looks like a host (ADR-025).
pub const DEFAULT: &str = "default";
/// The prefix of the policy's default for one kind: `default.<kind>`.
pub const DEFAULT_PREFIX: &str = "default.";
/// The policy's `defaults: net`, which a sandbox backend reports when it
/// cannot reproduce an allow-by-default network.
pub const DEFAULT_NET: &str = "default.net";

/// Input the lexer or classifier cannot understand: the policy's catch-all,
/// never `allow` (invariant 3, ADR-025).
pub const UNPARSEABLE: &str = "unparseable";
/// A call the hook payload shows only in part (`Action::Unchecked`): it needs
/// review whatever else it is decided.
pub const UNCHECKED: &str = "unchecked";
/// A review for a folder that holds paths a deny rule names.
pub const PROTECTED_CONTENTS: &str = "protected-contents";
/// A program that resolves to another path than its pin (`executables:`).
pub const EXECUTABLES: &str = "executables";
/// A decision tightened by session taint.
pub const SESSION_TAINT: &str = "session-taint";
/// A decision tightened by injected input.
pub const INJECTED_INPUT: &str = "injected-input";
/// A call held because its arguments carry text another MCP server returned
/// in this session.
pub const MCP_CROSS_SERVER: &str = "mcp-cross-server";

/// Every decision the policy lock forces.
pub const KERNEL_INTEGRITY: &str = "kernel-integrity";
/// A call `openmoat guard` could not check or record: a deny (invariant 4).
pub const KERNEL_ERROR: &str = "kernel-error";
/// A tool OpenMoat does not check.
pub const UNGOVERNED: &str = "ungoverned";
/// A call a person approved for the session with `openmoat allow`.
pub const APPROVED_SESSION: &str = "approved-session";
/// The guard's deny for an agent below the required protection level.
pub const PROTECTION_REQUIRED: &str = "protection-required";
/// A blocked project settings change, and its audit row.
pub const PROJECT_SETTINGS: &str = "project-settings";
/// The review of running code the session wrote.
pub const SESSION_WRITTEN_CODE: &str = "session-written-code";
/// A settings file that changed on disk and may load into the running
/// session (a host's `ConfigChange` hook).
pub const CONFIG_CHANGE: &str = "config-change";
/// A session start that issues nothing.
pub const SESSION_START: &str = "session-start";
/// Settings drift within the keys a host's spec allowlists
/// (`integrity/relaxed.rs`).
pub const SETTINGS_DRIFT: &str = "settings-drift";

/// A push of commits that hold a secret.
pub const PUSH_SECRET: &str = "push-secret";
/// A push that changes what CI runs, after the session read untrusted content
/// or a secret.
pub const PUSH_RUNS_LATER: &str = "push-runs-later";
/// A push OpenMoat could not check.
pub const PUSH_UNCHECKED: &str = "push-unchecked";

/// A tool call denied because its MCP server's definition is not the one a
/// person accepted.
pub const MCP_SERVER_CHANGED: &str = "mcp-server-changed";
/// A call `openmoat mcp proxy` passed.
pub const MCP_PROXY: &str = "mcp-proxy";
/// A tool `openmoat mcp proxy` holds until a person accepts it.
pub const MCP_TOOL_HELD: &str = "mcp-tool-held";
/// A call no hook decision names, refused by `openmoat mcp proxy`.
pub const MCP_UNATTRIBUTED: &str = "mcp-unattributed";
/// A request the server sent the client, refused by `openmoat mcp proxy`.
pub const MCP_SERVER_REQUEST: &str = "mcp-server-request";
/// The row that marks a session untrusted for what an MCP server sent it
/// outside a tool result.
pub const MCP_SERVER_TEXT: &str = "mcp-server-text";

/// A call's rule when a remote approval is used for it.
pub const APPROVED_REMOTE: &str = "approved-remote";
/// The approvals listener's row for an approval given.
pub const REMOTE_APPROVED: &str = "remote-approved";
/// An approver's deny: the listener's row, and the call's while it holds.
pub const REMOTE_DENIED: &str = "remote-denied";
/// An answer or request refused: not an approver, a bad button or
/// signature, too late.
pub const REMOTE_REFUSED: &str = "remote-refused";
/// A remote approval request nobody answered in time.
pub const REMOTE_EXPIRED: &str = "remote-expired";

/// The row `openmoat run` links its audit session with.
pub const RUN_SESSION: &str = "run-session";
/// The row of a run started with `--no-isolate`.
pub const RUN_NO_ISOLATE: &str = "run-no-isolate";
/// The row of a run that could not isolate.
pub const RUN_ISOLATION_UNAVAILABLE: &str = "run-isolation-unavailable";
/// The row of a run whose policy opened the project's top to commands
/// (`sandbox.project_top: writable`, ADR-090).
pub const RUN_PROJECT_TOP_OPEN: &str = "run-project-top-open";
/// The row of a run started over a project file that turns the agent's hook off
/// (`sandbox.project_hook_off: start`, ADR-098).
pub const RUN_PROJECT_HOOK_OFF: &str = "run-project-hook-off";
/// The row of a run that kept the hook on with the host's own option (ADR-098).
pub const RUN_PROJECT_HOOK_OFF_OVERRIDDEN: &str = "run-project-hook-off-overridden";
/// The row of a run refused because a project file turns the hook off (ADR-098).
pub const RUN_PROJECT_HOOK_OFF_REFUSED: &str = "run-project-hook-off-refused";
/// The row of a run whose person's own settings turn the agent's hooks off (ADR-098).
pub const RUN_OWN_SETTINGS_HOOK_OFF: &str = "run-own-settings-hook-off";
/// The row of a run's boundary.
pub const RUN_BOUNDARY: &str = "run-boundary";
/// The row a guard leaves when it found the relay variables but was not in a
/// run's sandbox, and so decided the call itself.
pub const RUN_GUARD_OUTSIDE: &str = "run-guard-outside";
/// The row a relayed call with a wrong token leaves.
pub const RUN_GUARD_TOKEN: &str = "run-guard-token";
/// The row a relayed call for another agent than the run's leaves.
pub const RUN_GUARD_HOST: &str = "run-guard-host";
/// The row a relayed call in a session that is not the run's leaves.
pub const RUN_GUARD_SESSION: &str = "run-guard-session";

/// The row the session-start hook records when it issues a session its proxy
/// credential.
pub const PROXY_CREDENTIAL: &str = "proxy-credential";
/// A proxy request refused for its session: no valid credential, the
/// session's connection share used up, or its history unreadable.
pub const PROXY_SESSION: &str = "proxy-session";
/// A proxy request that carries a brokered secret to a host that is not the
/// secret's own.
pub const PROXY_SECRET: &str = "proxy-secret";
/// A proxy request that would get a secret whose value has expired and was
/// not renewed (ADR-087): it is not sent.
pub const PROXY_SECRET_EXPIRED: &str = "proxy-secret-expired";
/// A request to a secret's host that the secret's `allow` rules do not name.
pub const PROXY_SECRET_ROUTE: &str = "proxy-secret-route";
/// A proxy request a host's request rules refuse (ADR-062).
pub const PROXY_REQUEST_RULE: &str = "proxy-request-rule";
/// A destination the proxy refuses whatever the policy says.
pub const PROXY_ADDRESS: &str = "proxy-address";
/// A tunnel whose TLS `ClientHello` does not name the CONNECT host.
pub const PROXY_SNI: &str = "proxy-sni";
/// A request the proxy could not parse or does not serve.
pub const PROXY_REQUEST: &str = "proxy-request";
/// A destination that could not be resolved or reached.
pub const PROXY_UPSTREAM: &str = "proxy-upstream";
/// A connection refused because it could not be recorded.
pub const PROXY_AUDIT: &str = "proxy-audit";
/// A terminated tunnel refused for its TLS: a handshake that failed on either
/// side, or an upstream certificate that did not verify.
pub const PROXY_TLS: &str = "proxy-tls";
/// A host the policy allows, refused on a port no rule names.
pub const PROXY_PORT: &str = "proxy-port";
/// A connection refused at accept because the proxy, or the connections not
/// yet authenticated, hold all the slots they may.
pub const PROXY_CAPACITY: &str = "proxy-capacity";

/// The audit event that records a delivery skip.
pub const AUDIT_DELIVERY_OVERFLOW: &str = "audit-delivery-overflow";
/// The audit event that records an event the sink refused as too large
/// (`413`) even alone.
pub const AUDIT_DELIVERY_TOO_LARGE: &str = "audit-delivery-too-large";
/// The audit event that records log records an OTLP collector accepted the
/// request without (`partial_success`).
pub const AUDIT_DELIVERY_PARTIAL: &str = "audit-delivery-partial";
/// The record `openmoat audit deliver test` sends.
pub const AUDIT_DELIVERY_TEST: &str = "audit-delivery-test";

/// `policy check-diff`: a path that leaves the repository or is not a file
/// name git checks out.
pub const DIFF_PATH: &str = "diff-path";
/// `policy check-diff`: an added line that holds a known token shape.
pub const DIFF_SECRET: &str = "diff-secret";
/// `policy check-diff`: a change to a policy file the check reads.
pub const DIFF_POLICY: &str = "diff-policy";
/// `policy check-diff`: a symbolic link the change adds or changes.
pub const DIFF_LINK: &str = "diff-link";
/// `policy check-diff`: a submodule the change adds or changes.
pub const DIFF_SUBMODULE: &str = "diff-submodule";
/// `policy check-diff`: a diff that was not read in full.
pub const DIFF_UNCHECKED: &str = "diff-unchecked";

/// The default policy's self-protection: OpenMoat's own files and the hosts'
/// hook files.
pub const KERNEL_SELF: &str = "kernel-self";
/// The default policy's group of the agents' login files.
pub const AGENT_CREDENTIALS: &str = "agent-credentials";
/// The default policy's rule for Kerberos ticket caches.
pub const KERBEROS_TICKETS: &str = "kerberos-tickets";
/// The default policy's `allow` rule naming each agent's own temporary
/// folders, generated from the host specs.
pub const AGENT_TEMP: &str = "agent-temp";
/// The default policy's secret files, whose reads taint a session.
pub const SECRETS_PATHS: &str = "secrets-paths";

/// The ids of the default policy's rule groups the code reads by name; each
/// is a group of the default policy (tested).
pub const POLICY_RULES: &[&str] = &[
    KERNEL_SELF,
    AGENT_CREDENTIALS,
    KERBEROS_TICKETS,
    AGENT_TEMP,
    SECRETS_PATHS,
];

/// The words of one of OpenMoat's own checks in a block message (ADR-059).
/// `next` is the person's step for a decision of the check's own verdict,
/// where the verdict's step would not fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Words {
    /// What the call does, as a policy rule's `title` reads.
    pub title: &'static str,
    /// Why that is held, as a policy rule's `why` reads.
    pub why: &'static str,
    /// The person's step for a decision of this verdict.
    pub next: Option<(Verdict, &'static str)>,
}

/// One rule id OpenMoat's own code decides or records with. A rule with
/// [`Words`] can deny a call or hold it for review, and has a page at
/// `https://openmoat.dev/r/<id>` made from them; one without only allows,
/// defers or records, or never reaches a host's reason field (`openmoat mcp
/// proxy`, `openmoat proxy`, `policy check-diff`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinRule {
    /// The rule id.
    pub id: &'static str,
    /// Its block message's words, and with them its page.
    pub words: Option<&'static Words>,
}

const fn quiet(id: &'static str) -> BuiltinRule {
    BuiltinRule { id, words: None }
}

const fn worded(id: &'static str, words: &'static Words) -> BuiltinRule {
    BuiltinRule {
        id,
        words: Some(words),
    }
}

/// Every rule id OpenMoat's own code decides or records with (not the
/// policy's, not `policy check-diff`'s content checks).
pub const BUILTIN_RULES: &[BuiltinRule] = &[
    worded(UNPARSEABLE, &words::UNPARSEABLE),
    worded(UNCHECKED, &words::UNCHECKED),
    worded(PROTECTED_CONTENTS, &words::PROTECTED_CONTENTS),
    worded(EXECUTABLES, &words::EXECUTABLES),
    worded(SESSION_TAINT, &words::SESSION_TAINT),
    worded(INJECTED_INPUT, &words::INJECTED_INPUT),
    worded(MCP_CROSS_SERVER, &words::MCP_CROSS_SERVER),
    worded(KERNEL_INTEGRITY, &words::KERNEL_INTEGRITY),
    worded(KERNEL_ERROR, &words::KERNEL_ERROR),
    worded(UNGOVERNED, &words::UNGOVERNED),
    quiet(APPROVED_SESSION),
    worded(PROTECTION_REQUIRED, &words::PROTECTION_REQUIRED),
    worded(PROJECT_SETTINGS, &words::PROJECT_SETTINGS),
    worded(SESSION_WRITTEN_CODE, &words::SESSION_WRITTEN_CODE),
    quiet(CONFIG_CHANGE),
    quiet(SESSION_START),
    quiet(SETTINGS_DRIFT),
    worded(PUSH_SECRET, &words::PUSH_SECRET),
    worded(PUSH_RUNS_LATER, &words::PUSH_RUNS_LATER),
    worded(PUSH_UNCHECKED, &words::PUSH_UNCHECKED),
    worded(MCP_SERVER_CHANGED, &words::MCP_SERVER_CHANGED),
    quiet(MCP_PROXY),
    quiet(MCP_TOOL_HELD),
    quiet(MCP_UNATTRIBUTED),
    quiet(MCP_SERVER_REQUEST),
    quiet(MCP_SERVER_TEXT),
    quiet(APPROVED_REMOTE),
    quiet(REMOTE_APPROVED),
    quiet(REMOTE_DENIED),
    quiet(REMOTE_REFUSED),
    quiet(REMOTE_EXPIRED),
    quiet(RUN_SESSION),
    quiet(RUN_NO_ISOLATE),
    quiet(RUN_ISOLATION_UNAVAILABLE),
    quiet(RUN_PROJECT_TOP_OPEN),
    quiet(RUN_PROJECT_HOOK_OFF),
    quiet(RUN_PROJECT_HOOK_OFF_OVERRIDDEN),
    quiet(RUN_PROJECT_HOOK_OFF_REFUSED),
    quiet(RUN_OWN_SETTINGS_HOOK_OFF),
    quiet(RUN_BOUNDARY),
    quiet(RUN_GUARD_OUTSIDE),
    quiet(RUN_GUARD_TOKEN),
    quiet(RUN_GUARD_HOST),
    quiet(RUN_GUARD_SESSION),
    quiet(PROXY_CREDENTIAL),
    quiet(PROXY_SESSION),
    quiet(PROXY_SECRET),
    quiet(PROXY_SECRET_EXPIRED),
    quiet(PROXY_SECRET_ROUTE),
    quiet(PROXY_REQUEST_RULE),
    quiet(PROXY_ADDRESS),
    quiet(PROXY_SNI),
    quiet(PROXY_REQUEST),
    quiet(PROXY_UPSTREAM),
    quiet(PROXY_AUDIT),
    quiet(PROXY_TLS),
    quiet(PROXY_PORT),
    quiet(PROXY_CAPACITY),
    quiet(AUDIT_DELIVERY_OVERFLOW),
    quiet(AUDIT_DELIVERY_TOO_LARGE),
    quiet(AUDIT_DELIVERY_PARTIAL),
    quiet(AUDIT_DELIVERY_TEST),
    quiet(DIFF_PATH),
    quiet(DIFF_SECRET),
    quiet(DIFF_POLICY),
    quiet(DIFF_LINK),
    quiet(DIFF_SUBMODULE),
    quiet(DIFF_UNCHECKED),
];

/// OpenMoat's own rule `id`; `None` for any other id.
#[must_use]
pub fn builtin(id: &str) -> Option<&'static BuiltinRule> {
    BUILTIN_RULES.iter().find(|r| r.id == id)
}

/// The block message words of OpenMoat's own check `id`; `None` for any
/// other id, and for a check that never denies or holds a call.
#[must_use]
pub fn words(id: &str) -> Option<&'static Words> {
    builtin(id).and_then(|r| r.words)
}

/// Whether a decision under `policy` may carry the rule `id`: a rule group of
/// the policy (a repository's review rules included), one of its defaults,
/// or one of OpenMoat's own rules.
#[must_use]
pub fn resolves(id: &str, policy: &crate::Policy) -> bool {
    id == DEFAULT
        || id
            .strip_prefix(DEFAULT_PREFIX)
            .is_some_and(|kind| kind.parse::<crate::Kind>().is_ok())
        || builtin(id).is_some()
        || policy.own_group(id).is_some()
        || policy.repo_review.iter().any(|g| g.id == id)
}

#[cfg(test)]
mod tests;
