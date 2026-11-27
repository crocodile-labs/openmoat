//! A glob the policy compile built on first use that did not build
//! (ADR-132).
//!
//! The core already turns every decision of such a compile into the
//! `kernel-error` deny; the session checks also match globs outside those
//! decisions (the fold of earlier calls, provenance, the session's code, the
//! hook ledger), so after them the guard reads the mark itself. A marked call
//! fails as a compile error fails it: the same deny, with the same words.

use anyhow::{Result, bail};
use openmoat_core::CompiledPolicy;

use super::Evaluated;

/// An error once a glob of `compiled` did not build, which [`super::run`]
/// answers with the `kernel-error` deny; nothing the call's checks found is
/// kept for its record then.
pub(super) fn checked(compiled: &CompiledPolicy<'_>, out: &mut Evaluated) -> Result<()> {
    if let Some(why) = compiled.unbuilt() {
        out.cache = None;
        out.provenance = crate::taint::provenance::Seen::default();
        bail!("{why}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use openmoat_core::{
        Action, CompiledPolicy, DEFAULT_POLICY, EvalContext, GlobBuilds, Policy, Verdict,
        rule_id::{KERNEL_ERROR, SECRETS_PATHS},
    };

    use super::super::{Evaluated, kernel_error};
    use super::checked;

    /// A compile whose broken glob a session check reached outside a decision
    /// fails the call as a compile error does: the `kernel-error` deny with the
    /// compile error's words.
    #[test]
    fn a_glob_that_did_not_build_is_the_compile_error_deny() {
        // a pattern added after the lint, as the CLI adds a repository's
        // rules, to the group whose reads the session's exposure checks
        let mut policy = Policy::parse(DEFAULT_POLICY).unwrap();
        let secrets = policy.deny.iter_mut().find(|g| g.id == SECRETS_PATHS);
        secrets.unwrap().fs_read.push("/x/{a".into());
        let ctx = EvalContext {
            home: "/h".into(),
            project: Some("/p".into()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: "/p".into(),
            case_insensitive_paths: false,
        };
        let at_compile = CompiledPolicy::compile(&policy, &ctx).unwrap_err();
        let compiled =
            CompiledPolicy::compile_owned_building(policy, &ctx, GlobBuilds::EveryOnFirstUse)
                .unwrap();
        let mut out = Evaluated::default();
        checked(&compiled, &mut out).unwrap();
        // the session's exposure matches the taint lists outside `decide`
        let read = Action::FsRead {
            path: "/x/{a".into(),
        };
        let exposed = compiled.exposure(&read, "/p", &openmoat_core::NoResolver);
        assert!(
            exposed.secrets.is_empty(),
            "the broken glob answered no match"
        );
        let error = checked(&compiled, &mut out).unwrap_err();
        let decision = kernel_error(&error);
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.rules, [KERNEL_ERROR]);
        let reason = &decision.reasons[0];
        assert!(
            reason.starts_with("kernel could not evaluate this action: bad glob `/x/{a`"),
            "{reason}"
        );
        // the words a compile error gets
        let compile_words = kernel_error(&anyhow::Error::from(at_compile)).reasons[0].clone();
        assert_eq!(reason, &compile_words);
        assert!(out.cache.is_none());
    }
}
