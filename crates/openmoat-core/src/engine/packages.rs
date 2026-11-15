//! A package runner's word the project already provides (ADR-102): an
//! `@package-run-unknown` atom is dropped when the word names a program the
//! project installed (`node_modules/.bin/<word>`, only for a word that may be
//! one), or a package the nearest manifest declares. The resolver is asked
//! only for such an atom, so a call without one reads nothing. A near miss
//! keeps its own atom whatever the project declares, and a program name is
//! never mapped to the package that provides it.

use crate::action::AtomicAction;
use crate::packages::Ecosystem;
use crate::programs::ProgramResolver;
use crate::shell::installs::{MAY_BE_LOCAL, UNKNOWN_RUN};

use super::EvalContext;

/// `atoms` without the unknown-package runs the project provides.
pub(super) fn on_hand(
    mut atoms: Vec<AtomicAction>,
    ctx: &EvalContext,
    resolver: &dyn ProgramResolver,
) -> Vec<AtomicAction> {
    if !atoms.iter().any(|a| unknown_run(a).is_some()) {
        return atoms;
    }
    let dirs = dirs(ctx);
    atoms.retain(|atom| {
        let Some((ecosystem, name, may_be_local)) = unknown_run(atom) else {
            return true;
        };
        let provided = (may_be_local && resolver.local_bin(&dirs, name))
            || resolver.declared(&dirs, ecosystem, name);
        !provided
    });
    atoms
}

/// The ecosystem, name and whether it may be a local program, of an
/// `@package-run-unknown` atom.
fn unknown_run(atom: &AtomicAction) -> Option<(Ecosystem, &str, bool)> {
    let AtomicAction::Shell { argv } = atom else {
        return None;
    };
    match argv.as_slice() {
        [tag, ecosystem, name, rest @ ..] if tag == UNKNOWN_RUN => Some((
            Ecosystem::from_id(ecosystem)?,
            name.as_str(),
            rest.first().is_some_and(|w| w == MAY_BE_LOCAL),
        )),
        _ => None,
    }
}

/// The working directory, then each parent up to the project root; only the
/// working directory when it is outside the project.
fn dirs(ctx: &EvalContext) -> Vec<String> {
    let mut out = vec![ctx.cwd.clone()];
    let Some(project) = ctx.project.as_deref() else {
        return out;
    };
    let inside = ctx.cwd == project || ctx.cwd.starts_with(&format!("{project}/"));
    if !inside {
        return out;
    }
    let mut here = ctx.cwd.as_str();
    while here != project {
        let Some((parent, _)) = here.rsplit_once('/') else {
            break;
        };
        here = if parent.is_empty() { "/" } else { parent };
        out.push(here.to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{Action, CompiledPolicy, DEFAULT_POLICY, NoResolver, Policy, Verdict};

    /// A project with these programs in `node_modules/.bin` and these
    /// declared packages (`npm:x`, `pypi:y`), in `/p`.
    struct Project {
        bins: BTreeSet<&'static str>,
        declared: BTreeSet<&'static str>,
    }

    impl ProgramResolver for Project {
        fn resolve(&self, _program: &str) -> Option<String> {
            None
        }

        fn local_bin(&self, dirs: &[String], name: &str) -> bool {
            dirs.iter().any(|d| d == "/p") && self.bins.contains(name)
        }

        fn declared(&self, dirs: &[String], ecosystem: Ecosystem, name: &str) -> bool {
            dirs.iter().any(|d| d == "/p")
                && self
                    .declared
                    .contains(format!("{}:{name}", ecosystem.id()).as_str())
        }
    }

    fn ctx(cwd: &str) -> EvalContext {
        EvalContext {
            home: "/Users/me".into(),
            project: Some("/p".into()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: cwd.into(),
            case_insensitive_paths: false,
        }
    }

    fn decide(cwd: &str, project: &Project, command: &str) -> (Verdict, Vec<String>) {
        let policy = Policy::parse(DEFAULT_POLICY).unwrap();
        let compiled = CompiledPolicy::compile(&policy, &ctx(cwd)).unwrap();
        let d = compiled.decide_with(
            &Action::Shell {
                command: command.into(),
            },
            project,
            &NoResolver,
        );
        (d.verdict, d.rules)
    }

    fn project() -> Project {
        Project {
            bins: ["tsc", "ng", "my-internal-cli"].into(),
            declared: ["npm:@acme/build-tools", "npm:lodahs", "pypi:acme-lint"].into(),
        }
    }

    #[test]
    fn a_program_the_project_installed_is_no_unknown_package() {
        let p = project();
        for command in [
            "npx tsc --noEmit",
            "npx ng build",
            "pnpm dlx my-internal-cli",
        ] {
            assert_eq!(decide("/p/app", &p, command).0, Verdict::Defer, "{command}");
        }
        // A version or a package option names a package, not the program.
        for command in ["npx tsc@5 --noEmit", "npx -p tsc tsc", "npx helper-kit-cli"] {
            assert_eq!(
                decide("/p", &p, command),
                (Verdict::Review, vec!["package-run-unknown".to_owned()]),
                "{command}"
            );
        }
        // Outside the project the project's programs are not looked for.
        assert_eq!(decide("/tmp", &p, "npx tsc").0, Verdict::Review);
    }

    #[test]
    fn a_declared_package_is_no_unknown_package_but_a_near_miss_stays_one() {
        let p = project();
        assert_eq!(
            decide("/p", &p, "npx @acme/build-tools lint").0,
            Verdict::Defer
        );
        assert_eq!(decide("/p", &p, "uvx acme-lint .").0, Verdict::Defer);
        assert_eq!(
            decide("/p", &p, "npx lodahs"),
            (Verdict::Review, vec!["package-near-miss".to_owned()])
        );
        // a program is never mapped through the package declared
        assert_eq!(decide("/p", &p, "npx build-tools").0, Verdict::Review);
        // a pypi name declared does not cover npm, nor the other way round
        assert_eq!(decide("/p", &p, "npx acme-lint").0, Verdict::Review);
    }

    #[test]
    fn the_directories_go_from_the_working_directory_to_the_project() {
        assert_eq!(dirs(&ctx("/p/a/b")), ["/p/a/b", "/p/a", "/p"]);
        assert_eq!(dirs(&ctx("/p")), ["/p"]);
        assert_eq!(dirs(&ctx("/pp/x")), ["/pp/x"]);
    }
}
