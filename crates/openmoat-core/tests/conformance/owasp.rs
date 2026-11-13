//! The OWASP Top 10 for Agentic Applications (2026) in `docs/COVERAGE.md`: all
//! ten risks, what OpenMoat claims for each, and which fixture classes and
//! marked end-to-end tests ([`super::evidence`]) test it.
//!
//! Identifiers and names as OWASP prints them in
//! <https://genai.owasp.org/2026/10/08/genai-and-agentic-ai-exploit-roundup-q3-2026/>.

use std::fmt::Write as _;

use super::THREATS;
use super::evidence::Tests;

/// What OpenMoat claims for a risk. Never a claim that the risk is solved:
/// a [`Status::Covered`] reason has to say what it leaves out.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    /// Tested by fixture classes, within the limits its reason names.
    Covered,
    /// Part of the risk is handled, the reason says which.
    Partial,
    /// Not something a check of each tool call can see.
    OutOfScope,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Covered => "covered",
            Self::Partial => "partial",
            Self::OutOfScope => "out of scope",
        }
    }
}

/// One risk of the list and the one-line reason for its [`Status`].
struct Risk {
    id: &'static str,
    name: &'static str,
    status: Status,
    reason: &'static str,
}

/// Every risk of the list, in OWASP's order. The reasons state what
/// `docs/LIMITS.md` and `docs/THREAT_MODEL.md` say; change them together.
const ASI: [Risk; 10] = [
    Risk {
        id: "ASI01",
        name: "Agent Goal Hijack",
        status: Status::Partial,
        reason: "Does not detect the hijack: it limits the calls that follow, and links a later \
                 call to what untrusted output named only on Claude Code, the Continue CLI, \
                 Codex, Gemini CLI, GitHub Copilot CLI, the Cline CLI and wrapped MCP servers.",
    },
    Risk {
        id: "ASI02",
        name: "Tool Misuse and Exploitation",
        status: Status::Covered,
        reason: "Each tool call a hook reports is decided by the policy. Not covered: tools no \
                 hook exposes, a deferred call an auto-approve mode runs, and misuse through an \
                 allowed command or host.",
    },
    Risk {
        id: "ASI03",
        name: "Identity and Privilege Abuse",
        status: Status::Covered,
        reason: "Secret paths, secret-shaped variables, agent logins and OpenMoat's own state are \
                 guarded. Not covered: what a credential can do on a remote service, and the \
                 agent's own login, which commands under `openmoat run` can read.",
    },
    Risk {
        id: "ASI04",
        name: "Agentic Supply Chain Vulnerabilities",
        status: Status::Covered,
        reason: "Downloads piped into a shell, near-miss package names, MCP server definitions \
                 and the hook binary are checked. Not covered: other installs, left to the \
                 agent's own prompt, and the command of an MCP server `openmoat init` was not \
                 allowed to wrap, or a project's own, which runs before any check.",
    },
    Risk {
        id: "ASI05",
        name: "Unexpected Code Execution",
        status: Status::Covered,
        reason: "Shell commands are classified, nested and decoded ones included, and dangerous \
                 environment settings are denied. Not covered: what an allowed script or test \
                 runner then runs; outside an OS sandbox the hook decides alone.",
    },
    Risk {
        id: "ASI06",
        name: "Memory and Context Poisoning",
        status: Status::Partial,
        reason: "MCP servers are pinned, and after untrusted content a write to an agent's memory \
                 or instruction files needs review. Not covered: what memory already says, and \
                 stores outside the files the policy names, such as hosted memory.",
    },
    Risk {
        id: "ASI07",
        name: "Insecure Inter-Agent Communication",
        status: Status::OutOfScope,
        reason: "Messages between agents are neither read nor authenticated; a subagent's own \
                 tool calls are still checked where the host's hook reports them.",
    },
    Risk {
        id: "ASI08",
        name: "Cascading Failures",
        status: Status::OutOfScope,
        reason: "Nothing follows a fault as it spreads between agents or workflows and there is \
                 no circuit breaker; the policy and sandbox apply to each agent's own calls.",
    },
    Risk {
        id: "ASI09",
        name: "Human-Agent Trust Exploitation",
        status: Status::Partial,
        reason: "Reviews name the rule and reason, and commands that change protection need a \
                 person at a terminal. Not covered: what the agent tells the person, and \
                 auto-approve modes, which run deferred calls and on some agents approve reviews.",
    },
    Risk {
        id: "ASI10",
        name: "Rogue Agents",
        status: Status::Partial,
        reason: "Self-protection, the OS sandbox where one applies and the audit log bound and \
                 record a misbehaving agent. Not covered: judging behaviour over time, and a \
                 hook-only agent not started under `openmoat run`, which has no OS sandbox to \
                 stop a program rewriting the policy.",
    },
];

/// Which [`ASI`] risks each threat class of [`THREATS`] is a case of: an
/// agent's own tools turned on the machine (ASI02), its inherited rights and
/// credentials used beyond the task (ASI03), code or servers it pulls in
/// (ASI04), code it was never meant to run (ASI05), and content that changes
/// what later turns do (ASI06: poisoned MCP results and tools).
const ASI_OF: [(&str, &[&str]); 12] = [
    ("T1", &["ASI02", "ASI03"]),
    ("T2", &["ASI02", "ASI03"]),
    ("T3", &["ASI03"]),
    ("T4", &["ASI02"]),
    ("T5", &["ASI04", "ASI05"]),
    ("T6", &["ASI05"]),
    ("T7", &["ASI05"]),
    ("T8", &["ASI02", "ASI04", "ASI06"]),
    ("T9", &["ASI03"]),
    ("T10", &["ASI04"]),
    ("T11", &["ASI02"]),
    ("T12", &["ASI02"]),
];

/// The [`ASI`] risks of threat class `t`.
pub(super) fn asi_of(t: &str) -> &'static [&'static str] {
    ASI_OF
        .iter()
        .find(|(id, _)| *id == t)
        .map_or(&[], |(_, risks)| risks)
}

/// The threat classes that are a case of `risk`.
pub(super) fn classes_of(risk: &str) -> Vec<&'static str> {
    THREATS
        .iter()
        .map(|(t, _)| *t)
        .filter(|t| asi_of(t).contains(&risk))
        .collect()
}

/// Every risk's id and name, in OWASP's order.
pub(super) fn risks() -> Vec<(&'static str, &'static str)> {
    ASI.iter().map(|r| (r.id, r.name)).collect()
}

/// Whether anything tests `risk`: a threat class with fixtures maps to it, or
/// an end-to-end test is marked for it.
fn tested(risk: &Risk, tests: &Tests) -> bool {
    !classes_of(risk.id).is_empty() || tests.get(risk.id).is_some_and(|t| !t.is_empty())
}

/// The status a risk's row shows: what it claims, or `not tested` when
/// nothing tests it (ADR-079): a row never claims more than its evidence.
fn shown_status(risk: &Risk, tests: &Tests) -> &'static str {
    if tested(risk, tests) {
        risk.status.label()
    } else {
        "not tested"
    }
}

/// A risk that claims to be covered, in full or in part, and that nothing
/// tests: each one a problem the suite fails on.
pub(super) fn untested_claims(tests: &Tests) -> Vec<String> {
    ASI.iter()
        .filter(|r| r.status != Status::OutOfScope && !tested(r, tests))
        .map(|r| {
            format!(
                "{} is marked {} but no fixture class maps to it and no end-to-end test is \
                 marked `// coverage: {}`",
                r.id,
                r.status.label(),
                r.id
            )
        })
        .collect()
}

/// The start of a risk's table row: enough to tell it is in the document.
fn row_start(risk: &Risk, tests: &Tests) -> String {
    format!(
        "| {} | {} | {} |",
        risk.id,
        risk.name,
        shown_status(risk, tests)
    )
}

/// The `docs/COVERAGE.md` section of all ten risks. `count` gives a threat
/// class's fixtures in one file; `tests` the end-to-end tests marked for each
/// risk. A risk no class maps to shows a dash: a zero would read as a
/// measurement.
pub(super) fn section(count: impl Fn(&str, &str) -> usize, tests: &Tests) -> String {
    let mut out = String::from(
        "\n## By OWASP agentic risk\n\n\
         All ten risks of the list. `covered` means fixtures or end-to-end tests test it, not \
         that the risk is solved: each reason names what is left out. A risk nothing tests \
         reads `not tested`, whatever is claimed for it. A fixture counts under every risk its \
         class maps to; a dash means no class maps to the risk, so there is nothing to \
         count. The tests and fixture ids behind each row are listed under \"Evidence by \
         OWASP agentic risk\".\n\n\
         | Risk | Name | Status | Reason | Classes | Attacks | Reviews | End-to-end tests |\n\
         |---|---|---|---|---|---|---|---|\n",
    );
    for risk in &ASI {
        let classes = classes_of(risk.id);
        let total = |file: &str| classes.iter().map(|t| count(t, file)).sum::<usize>();
        let (names, attacks, reviews) = if classes.is_empty() {
            ("—".to_owned(), "—".to_owned(), "—".to_owned())
        } else {
            (
                classes.join(", "),
                total("attacks.yaml").to_string(),
                total("review.yaml").to_string(),
            )
        };
        let e2e = tests.get(risk.id).map_or(0, Vec::len);
        let _ = writeln!(
            out,
            "{} {} | {names} | {attacks} | {reviews} | {e2e} |",
            row_start(risk, tests),
            risk.reason
        );
    }
    out
}

/// Each threat class maps to at least one known OWASP agentic risk, so the
/// column cannot fall behind [`THREATS`]; a risk marked covered has a class
/// that tests it, and one marked out of scope has none.
#[test]
fn every_threat_class_maps_to_an_owasp_agentic_risk() {
    for (t, name) in THREATS {
        let risks = asi_of(t);
        assert!(!risks.is_empty(), "{t} ({name}) has no OWASP agentic risk");
        for risk in risks {
            assert!(ASI.iter().any(|r| r.id == *risk), "{t}: unknown `{risk}`");
        }
    }
    assert_eq!(
        ASI_OF.len(),
        THREATS.len(),
        "ASI_OF lists a class twice or an unknown one"
    );
    for risk in &ASI {
        let classes = classes_of(risk.id);
        match risk.status {
            Status::Covered => assert!(!classes.is_empty(), "{}: nothing tests it", risk.id),
            Status::OutOfScope => assert!(classes.is_empty(), "{}: has a class", risk.id),
            Status::Partial => {}
        }
    }
}

/// All of ASI01 to ASI10 have a row in order, in the data and in the generated
/// section (`threat_coverage_is_complete_and_documented` holds the file to that
/// text), with a reason that fits one table cell; a covered risk says what it
/// does not cover.
#[test]
fn every_owasp_agentic_risk_has_a_row() {
    let tests = Tests::new();
    let generated = section(|_, _| 0, &tests);
    for (n, risk) in (1..).zip(&ASI) {
        assert_eq!(risk.id, format!("ASI{n:02}"));
        assert!(!risk.name.is_empty(), "{}: no name", risk.id);
        assert!(!risk.reason.is_empty(), "{}: no reason", risk.id);
        assert!(
            !risk.reason.contains(['|', '\n']),
            "{}: the reason breaks the table",
            risk.id
        );
        if risk.status == Status::Covered {
            assert!(
                risk.reason.contains("Not covered:"),
                "{}: `covered` must name what it does not cover",
                risk.id
            );
        }
        assert!(
            generated
                .lines()
                .any(|l| l.starts_with(&row_start(risk, &tests))),
            "the generated section has no row for {}",
            risk.id
        );
    }
}

/// A risk nothing tests reads `not tested` in the table, and one that claims
/// coverage is reported until a fixture class or a marked test backs it; a
/// marked test is enough to show the claim.
#[test]
fn a_risk_without_evidence_claims_nothing() {
    let none = Tests::new();
    let generated = section(|_, _| 0, &none);
    assert!(
        generated.contains("| ASI07 | Insecure Inter-Agent Communication | not tested |"),
        "{generated}"
    );
    let claims = untested_claims(&none);
    assert!(claims.iter().any(|c| c.starts_with("ASI01 ")), "{claims:?}");
    assert!(
        !claims.iter().any(|c| c.starts_with("ASI02 ")),
        "{claims:?}"
    );
    let marked = Tests::from([("ASI01".to_owned(), vec!["taint::t".to_owned()])]);
    assert!(
        !untested_claims(&marked)
            .iter()
            .any(|c| c.starts_with("ASI01 "))
    );
    assert!(section(|_, _| 0, &marked).contains("| ASI01 | Agent Goal Hijack | partial |"));
}
