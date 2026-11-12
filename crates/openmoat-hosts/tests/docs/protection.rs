//! The tests of `docs/PROTECTION.md` (ADR-079 decision 5): the page matches
//! what [`crate::matrix`] builds from the specs and the evidence, and a claim
//! without evidence never reads as more than preview.

use openmoat_hosts::Host;

use crate::cfg::Os;
use crate::marks::{Claim, Mark};
use crate::matrix::{self, Evidence, Level};
use crate::weekly::{self, Record};
use crate::{check, hosts, repo_root};

/// What protects each agent's calls on each OS, from the specs, the
/// `// protection:` marks of the end-to-end tests and the weekly job's
/// records. A mark that is wrong, or a record that claims what the job cannot
/// check, fails here before the page is compared.
#[test]
fn protection_lists_each_agent_on_each_os_with_its_evidence() {
    let root = repo_root();
    let marks = crate::marks::marks(&root.join("crates/openmoat-cli/tests/e2e"))
        .unwrap_or_else(|p| panic!("wrong `// protection:` marks:\n{}", p.join("\n")));
    let records = weekly::records(&root).unwrap_or_else(|e| panic!("{e}"));
    for record in &records {
        assert!(
            Host::EVERY.iter().any(|h| h.id() == record.host),
            "{}: {} names no agent",
            weekly::RECORDS,
            record.agent
        );
    }
    let ev = Evidence {
        marks: &marks,
        records: &records,
    };
    let hosts = hosts();
    check(
        "docs/PROTECTION.md",
        &[
            ("protection-summary", matrix::summary(&hosts, &ev)),
            ("protection-matrix", matrix::table(&hosts, &ev)),
            ("protection-evidence", matrix::evidence(&hosts, &ev)),
        ],
    );
}

/// A claim nothing backs reads `no evidence yet` in the table and `preview` in
/// the summary; a marked test or a weekly record is enough to show it, and the
/// hook is shown protected only when every weekly record of the agent proves
/// it on that OS.
#[test]
fn a_claim_without_evidence_reads_preview() {
    let host = Host::ALL[0];
    let none = Evidence {
        marks: &[],
        records: &[],
    };
    let cell = matrix::hook(host, Os::Linux, &none);
    assert_eq!(cell.level, Level::Preview);
    assert!(cell.text.ends_with("; no evidence yet"), "{}", cell.text);
    let summary = matrix::summary(&[host], &none).join("\n");
    assert!(summary.contains("hook: preview"), "{summary}");
    assert!(!summary.contains("hook: protected"), "{summary}");

    let marked = [Mark {
        claim: Claim::Hook,
        hosts: vec![host],
        oses: vec![Os::Linux],
        test: "m::t".to_owned(),
    }];
    let tested = Evidence {
        marks: &marked,
        records: &[],
    };
    assert_eq!(matrix::hook(host, Os::Linux, &tested).text, "protected");
    assert_eq!(matrix::hook(host, Os::Mac, &tested).level, Level::Preview);

    let record = |agent: &str, proves: Vec<Claim>| Record {
        agent: agent.to_owned(),
        host: host.id().to_owned(),
        oses: vec![Os::Linux],
        proves,
        why: None,
        fixture: None,
    };
    let both = [
        record("a-1", vec![Claim::Hook]),
        record("a-2", vec![Claim::Hook]),
    ];
    let one = [record("a-1", vec![Claim::Hook]), record("a-2", Vec::new())];
    let proven = |records: &[Record]| {
        matrix::hook(
            host,
            Os::Linux,
            &Evidence {
                marks: &[],
                records,
            },
        )
        .level
    };
    assert_eq!(proven(&both), Level::Shown);
    assert_eq!(proven(&one), Level::Preview);
}

/// A payloads test never makes a hook protected: it tests OpenMoat's side.
#[test]
fn a_payloads_test_is_not_evidence_of_the_hook() {
    let host = Host::ALL[0];
    let marked = [Mark {
        claim: Claim::Payloads,
        hosts: vec![host],
        oses: Os::EVERY.to_vec(),
        test: "m::t".to_owned(),
    }];
    let ev = Evidence {
        marks: &marked,
        records: &[],
    };
    for os in Os::EVERY {
        assert_eq!(matrix::hook(host, os, &ev).level, Level::Preview);
    }
}
