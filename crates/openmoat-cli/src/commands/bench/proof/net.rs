//! The network boundary: the egress proxy's own decision functions, which
//! `openmoat proxy` and `openmoat run` call on every request, asked about a
//! host the policy allows, before and after the session read a secret. No
//! connection is made, so no network is needed.

use openmoat_core::{CompiledPolicy, EvalContext, Taint, TaintSecret, Verdict};
use openmoat_proxy::{decide_host, decide_tainted};

use super::super::hook::Scratch;
use super::status::Evidence;
use crate::home::Home;

/// A host the default policy allows, and where an agent can post data.
pub const ALLOWED_HOST: &str = "github.com";

/// The id the report names to reproduce it.
pub const PROBE: &str = "net-allowed-host-after-secret-read";

/// What the row checks, in a few words.
pub fn check() -> String {
    format!("the proxy allows {ALLOWED_HOST}, and refuses it once the session read ~/.ssh/id_rsa")
}

/// The proxy's decisions under the throwaway home's policy.
pub fn run(scratch: &Scratch) -> Evidence {
    match decide(scratch) {
        Ok(evidence) => evidence,
        Err(error) => Evidence::Unexercised(format!(
            "the throwaway home's policy could not be compiled: {error:#}"
        )),
    }
}

fn decide(scratch: &Scratch) -> anyhow::Result<Evidence> {
    let policy = Home::under(&scratch.home).load_policy()?;
    let home = crate::context::path_string(&scratch.home);
    let project = crate::context::path_string(&scratch.project);
    let ctx = EvalContext {
        home: home.clone(),
        project: Some(project.clone()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: project,
        case_insensitive_paths: crate::context::CASE_INSENSITIVE_PATHS,
    };
    let compiled = CompiledPolicy::compile(&policy, &ctx)?;
    let clean = decide_host(&compiled, ALLOWED_HOST);
    if clean.verdict != Verdict::Allow {
        // The question is about an allowed host; this policy does not allow it.
        return Ok(Evidence::Unexercised(format!(
            "this policy does not allow {ALLOWED_HOST} ({}), so the check has no allowed host",
            clean.verdict.as_str()
        )));
    }
    let taint = Taint {
        secrets: vec![TaintSecret {
            source: format!("read {home}/.ssh/id_rsa"),
            host: None,
        }],
        ..Taint::default()
    };
    Ok(match decide_tainted(&compiled, ALLOWED_HOST, 443, &taint) {
        Some(d) if d.verdict == Verdict::Deny => Evidence::Held,
        Some(d) => Evidence::Broken(format!(
            "after a secret read the proxy answers {} for {ALLOWED_HOST}",
            d.verdict.as_str()
        )),
        None => Evidence::Broken(format!(
            "after a secret read the proxy still lets requests reach {ALLOWED_HOST}"
        )),
    })
}
