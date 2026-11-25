//! The entries a run as the agent account sets (ADR-129 §2). Pure, like the
//! token's plan beside it; `commands/run/windows/account.rs` sets them.
//!
//! - **Writes.** The token's plan, for the account's SID instead of each
//!   root's: an inherited allow entry on each write root, a deny of every
//!   write right on the literal places the policy's write denies name in a
//!   root, a deny of `DELETE` on the folders above them. Everything else in
//!   the profile is read-only to the account (setup's entry).
//! - **Reads.** Each read deny that names one literal place in the person's
//!   profile or in a write root, and that exists when the run starts, gets a
//!   deny of every right for the account, handed to everything below. The
//!   running agent's own login is not among them: the session's policy left
//!   it out (`own_login.rs`). A place an exception of the policy (`!…`)
//!   reaches into is left to the hook, since the entry would refuse the
//!   exception too; so is a glob no single place stands for, a place made
//!   later, and one outside the profile and the roots, where setting an entry
//!   would need rights the person may not have and the account holds only
//!   what the system grants every account.

use openmoat_core::Kind;
use openmoat_core::ir::Enforcement;

use super::super::patterns::{has_glob, literal_tree, push_unique, split};
use super::super::{Grants, Report};
use super::{Generated, READS, windows_path};
use crate::agent_account::{AclEntry, READ_DENY_MASK};

/// What a run as the account sets, and what it leaves to the hook.
#[derive(Debug, Default)]
pub struct AccountPlan {
    /// The write roots, as the token's plan found them.
    pub roots: Vec<String>,
    /// The write entries for the account.
    pub writes: Vec<AclEntry>,
    /// The read denies for the account.
    pub reads: Vec<AclEntry>,
    pub report: Report,
}

/// Whether `path` is `node` or below it, without regard to case: Windows
/// compares paths so.
fn at_or_below(path: &str, node: &str) -> bool {
    let path = path.to_lowercase();
    let node = node.trim_end_matches('/').to_lowercase();
    path == node || path.starts_with(&format!("{node}/"))
}

/// The plan for the IR `ir`, the run's `grants` and the person's `profile`;
/// `exists` says whether a place is there now.
pub fn generate(
    ir: &Enforcement,
    grants: &Grants,
    exists: &dyn Fn(&str) -> bool,
    profile: &str,
) -> anyhow::Result<AccountPlan> {
    let Generated { plan, mut report } = super::generate(ir, grants, exists)?;
    let mut writes: Vec<AclEntry> = Vec::new();
    for e in &plan.entries {
        let entry = AclEntry {
            path: e.path.clone(),
            allows: e.allows,
            mask: e.mask,
            inherit: e.inherit,
        };
        if !writes.contains(&entry) {
            writes.push(entry);
        }
    }
    let roots: Vec<String> = plan.roots.into_iter().map(|(root, _)| root).collect();
    report.allowances.retain(|a| a.rule != READS);
    let rules = &ir.fs.read.deny;
    let exceptions: Vec<&str> = rules
        .iter()
        .flat_map(|r| split(&r.patterns).1)
        .map(|p| p.split(['*', '?', '[', '{']).next().unwrap_or(p))
        .collect();
    let ours =
        |place: &str| at_or_below(place, profile) || roots.iter().any(|r| at_or_below(place, r));
    let mut reads = Vec::new();
    let mut unheld = Vec::new();
    for pattern in rules.iter().flat_map(|r| split(&r.patterns).0) {
        let place = literal_tree(pattern).filter(|p| windows_path(p) && !has_glob(p));
        let held =
            place.filter(|p| ours(p) && exists(p) && !exceptions.iter().any(|e| at_or_below(e, p)));
        match held {
            Some(place) => {
                let entry = AclEntry {
                    path: place.to_owned(),
                    allows: false,
                    mask: READ_DENY_MASK,
                    inherit: true,
                };
                if !reads.contains(&entry) {
                    reads.push(entry);
                }
            }
            None => push_unique(&mut unheld, pattern.to_owned()),
        }
    }
    if !unheld.is_empty() {
        let message = "the agent account cannot be denied these (a glob, a place that does not \
                       exist yet, one outside your profile and the write roots, or one an \
                       exception of the policy reaches into): the hook still decides them";
        report.allowance(Kind::FsRead, READS, unheld, message);
    }
    Ok(AccountPlan {
        roots,
        writes,
        reads,
        report,
    })
}

#[cfg(test)]
mod tests {
    use openmoat_core::{DEFAULT_POLICY, EvalContext, Policy};

    use super::*;

    const HOME: &str = "C:/Users/me";
    const PROJECT: &str = "C:/Users/me/proj";

    fn plan(yaml: &str, exists: &dyn Fn(&str) -> bool) -> AccountPlan {
        let policy = Policy::parse(yaml).expect("test policy lints");
        let ctx = EvalContext {
            home: HOME.into(),
            project: Some(PROJECT.into()),
            real_home: None,
            real_project: None,
            moved_dirs: Vec::new(),
            cwd: PROJECT.into(),
            case_insensitive_paths: true,
        };
        let grants = Grants {
            proxy_port: Some(18080),
            tmpdir: Some("C:/Users/me/AppData/Local/Temp/openmoat-run-1".into()),
            program: Some("C:/Users/me/bin/agent.exe".into()),
            writes: Vec::new(),
            terminals: Vec::new(),
            trust: None,
            tool_shell: None,
            helpers: None,
            listen: None,
        };
        let ir = openmoat_core::ir::lower(&policy, &ctx).expect("lowers");
        generate(&ir, &grants, exists, HOME).expect("generates")
    }

    fn read_denied<'a>(p: &'a AccountPlan, path: &str) -> Option<&'a AclEntry> {
        p.reads.iter().find(|e| e.path == path)
    }

    /// The token's write entries, without a SID of their own: the project's
    /// grant and its protected places' denies.
    #[test]
    fn the_writes_are_the_token_plans_for_the_account() {
        let p = plan(DEFAULT_POLICY, &|_| true);
        assert!(p.roots.iter().any(|r| r == PROJECT), "{:?}", p.roots);
        assert!(
            p.writes
                .iter()
                .any(|e| e.path == PROJECT && e.allows && e.mask == super::super::GRANT_MASK)
        );
        let git = format!("{PROJECT}/.git");
        assert!(p.writes.iter().any(|e| e.path == git && !e.allows));
    }

    /// `~/.ssh` and the other literal places in the profile get a deny of
    /// everything for the account; a place that does not exist, and a glob,
    /// are the hook's and named so.
    #[test]
    fn literal_read_denies_in_the_profile_get_a_deny_entry() {
        let p = plan(DEFAULT_POLICY, &|path| !path.ends_with("/.aws"));
        let ssh = read_denied(&p, "C:/Users/me/.ssh").unwrap_or_else(|| panic!("{:?}", p.reads));
        assert_eq!(
            (ssh.allows, ssh.mask, ssh.inherit),
            (false, READ_DENY_MASK, true)
        );
        assert!(read_denied(&p, "C:/Users/me/.aws").is_none());
        let unheld = p
            .report
            .allowances
            .iter()
            .find(|a| a.rule == READS && a.kind == Kind::FsRead)
            .map(|a| a.patterns.clone())
            .unwrap_or_default();
        assert!(unheld.iter().any(|u| u.contains(".aws")), "{unheld:?}");
        assert!(unheld.iter().any(|u| has_glob(u)), "{unheld:?}");
        // The token's "reads are not restricted" is not said of this run.
        assert!(
            !p.report
                .allowances
                .iter()
                .any(|a| a.message.contains("does not restrict reads"))
        );
    }

    /// A deny outside the profile and the roots, and one an exception
    /// reaches into, set nothing.
    #[test]
    fn places_outside_the_profile_or_with_exceptions_are_the_hooks() {
        let lf = DEFAULT_POLICY.replace("\r\n", "\n");
        let yaml = lf.replacen(
            "deny:\n",
            "deny:\n  - id: outside\n    fs.read: [\"D:/vault/**\"]\n  - id: partly\n    \
             fs.read: [\"~/.config/tool/**\", \"!~/.config/tool/public/**\"]\n",
            1,
        );
        let p = plan(&yaml, &|_| true);
        assert!(read_denied(&p, "D:/vault").is_none(), "{:?}", p.reads);
        assert!(
            read_denied(&p, "C:/Users/me/.config/tool").is_none(),
            "{:?}",
            p.reads
        );
        assert!(read_denied(&p, "C:/Users/me/.ssh").is_some());
    }
}
