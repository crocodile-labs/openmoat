//! Which controls of three public frameworks each group of OpenMoat's rules
//! gives evidence for (ADR-051). `openmoat audit evidence` reads it; nothing
//! decides by it.
//!
//! The map is by rule id: the ids of the shipped default policy and the ids the
//! code adds itself (`docs/POLICY.md` §5.1). A control is listed only where the
//! rule's decisions are records of that control operating on an agent's tool
//! calls; a control the rules do not serve is left out rather than stretched to
//! fit (OWASP LLM01 Prompt Injection, for one: OpenMoat limits what an injected
//! instruction can make the agent do, which is LLM06, but does not detect
//! injection). The evidence is that a rule fired, not that a framework's
//! requirement is met.

use Framework::{Iso27001, OwaspLlm2025, Soc2};
use serde::Serialize;

#[cfg(test)]
mod tests;

/// A published control framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Framework {
    /// OWASP Top 10 for LLM Applications 2025.
    OwaspLlm2025,
    /// AICPA SOC 2 Trust Services Criteria (2017, revised points of focus 2022).
    Soc2,
    /// ISO/IEC 27001:2022 Annex A.
    Iso27001,
}

impl Framework {
    pub const ALL: [Self; 3] = [Self::OwaspLlm2025, Self::Soc2, Self::Iso27001];

    pub fn name(self) -> &'static str {
        match self {
            Self::OwaspLlm2025 => "OWASP Top 10 for LLM Applications 2025",
            Self::Soc2 => "SOC 2 Trust Services Criteria",
            Self::Iso27001 => "ISO/IEC 27001:2022 Annex A",
        }
    }
}

/// One control of a framework, by its published id and a short title.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Control {
    pub framework: Framework,
    pub id: &'static str,
    pub title: &'static str,
}

const fn control(framework: Framework, id: &'static str, title: &'static str) -> Control {
    Control {
        framework,
        id,
        title,
    }
}

pub const LLM02: Control = control(
    OwaspLlm2025,
    "LLM02:2025",
    "Sensitive Information Disclosure",
);
pub const LLM03: Control = control(OwaspLlm2025, "LLM03:2025", "Supply Chain");
pub const LLM05: Control = control(OwaspLlm2025, "LLM05:2025", "Improper Output Handling");
pub const LLM06: Control = control(OwaspLlm2025, "LLM06:2025", "Excessive Agency");
pub const CC6_1: Control = control(
    Soc2,
    "CC6.1",
    "Logical access security over protected information assets",
);
pub const CC6_6: Control = control(
    Soc2,
    "CC6.6",
    "Logical access measures against threats from outside the system boundaries",
);
pub const CC6_7: Control = control(
    Soc2,
    "CC6.7",
    "Restricts the transmission, movement and removal of information",
);
pub const CC6_8: Control = control(
    Soc2,
    "CC6.8",
    "Prevents or detects unauthorized or malicious software",
);
pub const CC7_1: Control = control(
    Soc2,
    "CC7.1",
    "Detects configuration changes that introduce vulnerabilities",
);
pub const CC7_2: Control = control(
    Soc2,
    "CC7.2",
    "Monitors system components for anomalies that indicate malicious acts",
);
pub const CC8_1: Control = control(Soc2, "CC8.1", "Authorises and approves changes");
pub const A5_14: Control = control(Iso27001, "A.5.14", "Information transfer");
pub const A5_17: Control = control(Iso27001, "A.5.17", "Authentication information");
pub const A8_3: Control = control(Iso27001, "A.8.3", "Information access restriction");
pub const A8_7: Control = control(Iso27001, "A.8.7", "Protection against malware");
pub const A8_9: Control = control(Iso27001, "A.8.9", "Configuration management");
pub const A8_12: Control = control(Iso27001, "A.8.12", "Data leakage prevention");
pub const A8_15: Control = control(Iso27001, "A.8.15", "Logging");
pub const A8_19: Control = control(
    Iso27001,
    "A.8.19",
    "Installation of software on operational systems",
);
pub const A8_23: Control = control(Iso27001, "A.8.23", "Web filtering");

/// Every control some group maps to, in report order.
pub const CONTROLS: &[&Control] = &[
    &LLM02, &LLM03, &LLM05, &LLM06, &CC6_1, &CC6_6, &CC6_7, &CC6_8, &CC7_1, &CC7_2, &CC8_1, &A5_14,
    &A5_17, &A8_3, &A8_7, &A8_9, &A8_12, &A8_15, &A8_19, &A8_23,
];

/// Which recorded events a group's evidence is made of.
#[derive(Debug)]
pub enum Covers {
    /// Events whose decision names one of these rule ids.
    Rules(&'static [&'static str]),
    /// Every recorded event: the record itself is the evidence.
    EveryEvent,
}

/// Rule ids that do one job, and the controls their decisions give evidence for.
#[derive(Debug)]
pub struct Group {
    pub id: &'static str,
    pub title: &'static str,
    /// What the rules do, in one sentence.
    pub does: &'static str,
    pub covers: Covers,
    pub controls: &'static [&'static Control],
}

impl Group {
    /// Whether an event whose decision names `rules` belongs to this group.
    pub fn matches<S: AsRef<str>>(&self, rules: &[S]) -> bool {
        match self.covers {
            Covers::EveryEvent => true,
            Covers::Rules(ids) => rules.iter().any(|r| ids.contains(&r.as_ref())),
        }
    }

    /// The rule ids the group names; none for [`Covers::EveryEvent`].
    pub fn rule_ids(&self) -> &'static [&'static str] {
        match self.covers {
            Covers::Rules(ids) => ids,
            Covers::EveryEvent => &[],
        }
    }
}

/// The map. Each rule id is in at most one group; every `deny` and `ask` rule
/// of the default policy is in one (tested).
pub const GROUPS: &[Group] = &[
    Group {
        id: "secrets",
        title: "Secrets and credentials",
        does: "deny or ask the agent's reads of key files, credential stores, secret \
               environment variables and folders that hold them",
        covers: Covers::Rules(&[
            "secrets-paths",
            "build-credentials",
            "agent-credentials",
            "env-secrets",
            "env-dump",
            "home-sweep",
            "other-home",
            "secret-names",
            "docker-secrets",
            "agent-token",
            openmoat_core::HOLDS_PROTECTED_RULE,
        ]),
        controls: &[&LLM02, &CC6_1, &A5_17, &A8_3],
    },
    Group {
        id: "secret-egress",
        title: "Secrets and personal data leaving the machine",
        does: "deny a known token or a brokered secret sent to a host that is not its own, \
               a payment card number sent off the machine, a push that publishes a \
               secret, and ask before a session that read secret material sends data out",
        covers: Covers::Rules(&[
            "token-egress",
            "placeholder-egress",
            "encoded-egress",
            "card-egress",
            openmoat_core::TAINT_RULE,
            crate::push::SECRET_RULE,
            openmoat_proxy::RULE_SECRET,
            openmoat_proxy::RULE_SECRET_ROUTE,
            openmoat_proxy::RULE_TLS,
        ]),
        controls: &[&LLM02, &CC6_7, &A5_14, &A8_12],
    },
    Group {
        id: "network",
        title: "Network egress",
        does: "deny outbound connections to hosts the policy does not list, cloud metadata \
               addresses, and connections `openmoat proxy` refuses",
        covers: Covers::Rules(&[
            "default.net",
            "cloud-metadata",
            openmoat_proxy::RULE_ADDRESS,
            openmoat_proxy::RULE_SNI,
            openmoat_proxy::RULE_REQUEST,
            openmoat_proxy::RULE_UPSTREAM,
            openmoat_proxy::RULE_PORT,
            openmoat_proxy::RULE_SESSION,
        ]),
        controls: &[&CC6_6, &A8_23],
    },
    Group {
        id: "code-execution",
        title: "Running code the agent did not show",
        does: "deny piping downloaded or decoded content into a shell and a program that \
               resolves to another path than its pin; ask before running opaque code or a \
               file the session wrote",
        covers: Covers::Rules(&[
            "pipe-to-shell",
            "opaque-code",
            crate::session_code::RULE,
            "executables",
        ]),
        controls: &[&LLM05, &CC6_8, &A8_7],
    },
    Group {
        id: "packages",
        title: "Package installs",
        does: "ask before installing a package whose name is one typo away from a popular one",
        covers: Covers::Rules(&["package-near-miss"]),
        controls: &[&LLM03, &CC6_8, &A8_19],
    },
    Group {
        id: "runs-later",
        title: "Code that runs later",
        does: "deny or ask writes to files that git, CI, the login shell, a scheduler or the \
               agent host run later, outside any sandbox",
        covers: Covers::Rules(&[
            "runs-later",
            "persistence",
            "shell-rc",
            "git-internals",
            "env-poison",
            crate::push::RUNS_LATER_RULE,
        ]),
        controls: &[&CC6_8, &A8_7],
    },
    Group {
        id: "self-protection",
        title: "OpenMoat's own policy, hooks and binary",
        does: "deny the agent changing or stopping OpenMoat and running the commands only a \
               person may run",
        covers: Covers::Rules(&["kernel-self", "agent-folders", "stops-openmoat"]),
        controls: &[&LLM06, &CC8_1, &A8_9],
    },
    Group {
        id: "integrity",
        title: "Configuration integrity",
        does: "deny every call while a file the policy lock pins has changed, record \
               settings drift, and block project settings that turn hooks off",
        covers: Covers::Rules(&[
            crate::integrity::INTEGRITY_RULE,
            "settings-drift",
            crate::project_settings::RULE,
        ]),
        controls: &[&CC7_1, &CC8_1, &A8_9],
    },
    Group {
        id: "mcp",
        title: "MCP servers",
        does: "deny the tool calls of a new or changed MCP server definition and the start \
               of a wrapped one until a person accepts it; refuse a tool whose definition \
               changed and a call no hook decision names",
        covers: Covers::Rules(&[crate::mcp::SERVER_RULE, "mcp-tool-held", "mcp-unattributed"]),
        controls: &[&LLM03, &CC6_8, &CC7_1, &A8_19],
    },
    Group {
        id: "destructive",
        title: "Destructive commands",
        does: "deny irreversible deletions and history rewrites; ask before deleting local \
               work git can still recover",
        covers: Covers::Rules(&["destructive", "destructive-recoverable"]),
        controls: &[&LLM06],
    },
    Group {
        id: "audit-log",
        title: "Audit log",
        does: "record every decision, redacted, in a hash chain that `openmoat audit verify` \
               checks",
        covers: Covers::EveryEvent,
        controls: &[&CC7_2, &A8_15],
    },
];

/// The groups that map to `control`, in map order.
pub fn groups_for(control: &Control) -> impl Iterator<Item = &'static Group> + '_ {
    GROUPS.iter().filter(move |g| g.controls.contains(&control))
}

/// The group that names `rule`, if any.
pub fn group_of(rule: &str) -> Option<&'static Group> {
    GROUPS.iter().find(|g| g.rule_ids().contains(&rule))
}
