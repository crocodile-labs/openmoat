//! `moat trust`: let a repository policy's allow rules apply (ADR-022).
//!
//! Person-only, like `moat allow`: trust widens the policy, so it needs a
//! terminal and an intact lock, and the default policy denies it to agents.
//! It shows the file it would trust (path, digest, what it allows, asks and
//! denies next to the person's own policy) and writes the record only on an
//! explicit yes: an agent may have edited the file just before.

use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Kind, Policy, REPO_RULE_PREFIX, RuleGroup};

use crate::cli::TrustArgs;
use crate::exit::Code;
use crate::home::{self, Home};
use crate::integrity::{self, HookPins};
use crate::render::{self, Deferred};
use crate::repo::Found;
use crate::trust::Trust;
use crate::{context, project, repo};

pub fn run(args: &TrustArgs) -> Result<Code> {
    crate::terminal::refuse_agent("openmoat trust")?;
    if !crate::terminal::interactive() {
        bail!("`openmoat trust` must be run by a person in a terminal, not from a hook or script");
    }
    let home = Home::locate()?;
    integrity::refuse_drift(&home, "change trust")?;
    let start = context::absolute(args.repo.as_deref().unwrap_or(Path::new(".")))?;
    let root = project::root_of(&start, &home::user_home()?).with_context(|| {
        format!(
            "{} is not in a project: it is the home directory, one of its ancestors or a filesystem root",
            start.display()
        )
    })?;

    let path = home.trust_path();
    let mut trust = Trust::load(&path)?;
    let mut out = Deferred::default();
    if args.revoke {
        if trust.repos.remove(&repo::root_key(&root)?).is_none() {
            writeln!(out, "{} is not trusted; nothing to revoke", root.display())?;
            out.finish()?;
            return Ok(Code::Ok);
        }
        writeln!(
            out,
            "✔ revoked: the repository policy of {} only tightens again",
            root.display()
        )?;
    } else {
        // A file that does not parse cannot be trusted: `find` says why.
        let found = repo::find(&home, &root)?
            .with_context(|| format!("{} has no .moat/policy.yaml", root.display()))?;
        let user = home.load_policy().ok();
        show(
            &mut out,
            &found,
            user.as_ref(),
            trust.repos.get(&found.root),
        )?;
        if !super::edit::confirm(&mut out, "Trust this file? [y/N] ")? {
            writeln!(
                out,
                "nothing trusted: the repository policy still only tightens"
            )?;
            out.finish()?;
            return Ok(Code::Ok);
        }
        writeln!(
            out,
            "✔ trusted {}  sha256:{}: its {} allow rule(s) apply until the file changes",
            found.path.display(),
            found.digest,
            found.policy.allow.len()
        )?;
        if user.is_some_and(|user| user.require_signed_repo_policy) {
            writeln!(
                out,
                "  note: your policy sets `require_signed_repo_policy: true`, so they apply only while a trusted key signs the file"
            )?;
        }
        trust.repos.insert(found.root, found.digest);
    }
    trust.save(&path)?;
    let lock = integrity::repin(&home, &crate::install::hook_binary()?, HookPins::Keep)?;
    writeln!(out, "✔ lock re-pinned ({} files)", lock.entries.len())?;
    out.finish()?;
    Ok(Code::Ok)
}

/// What trusting `found` changes, for the person to read before answering:
/// the file and its digest, the allow rules trust adds (and which of them a
/// deny rule of the person's policy makes moot), and the ask and deny rules
/// that apply trusted or not. `before` is the digest trusted until now.
fn show(
    out: &mut impl std::io::Write,
    found: &Found,
    user: Option<&Policy>,
    before: Option<&String>,
) -> Result<()> {
    render::line(out, &format!("repository policy {}", found.path.display()))?;
    writeln!(out, "  sha256:{}", found.digest)?;
    match before {
        Some(old) if *old == found.digest => writeln!(out, "  already trusted as it is")?,
        Some(old) => writeln!(out, "  replaces the trust given to sha256:{old}")?,
        None => {}
    }
    let shadowed: Vec<String> = user
        .and_then(|user| found.policy.merge(user, true).ok())
        .map(|merged| {
            openmoat_core::lint::warnings(&merged)
                .into_iter()
                .filter(|w| w.rule.starts_with(REPO_RULE_PREFIX))
                .map(|w| w.rule)
                .collect()
        })
        .unwrap_or_default();
    let p = &found.policy;
    writeln!(
        out,
        "  trusting it adds {} allow rule(s) to your policy; your deny rules still win:",
        p.allow.len()
    )?;
    for group in &p.allow {
        let id = format!("{REPO_RULE_PREFIX}{}", group.id);
        let note = if shadowed.contains(&id) {
            " (a deny rule covers some or all of it, and deny wins)"
        } else {
            ""
        };
        render::line(out, &format!("    allow {id}: {}{note}", patterns(group)))?;
    }
    writeln!(
        out,
        "  its {} ask and {} deny rule(s) apply trusted or not:",
        p.ask.len(),
        p.deny.len()
    )?;
    for (verdict, groups) in [("ask", &p.ask), ("deny", &p.deny)] {
        for group in groups {
            let id = format!("{REPO_RULE_PREFIX}{}", group.id);
            render::line(out, &format!("    {verdict} {id}: {}", patterns(group)))?;
        }
    }
    if user.is_none() {
        writeln!(
            out,
            "  (your policy could not be read, so rules it makes moot are not marked)"
        )?;
    }
    Ok(())
}

/// `shell: a, b; net: c`: what one allow group lets through.
fn patterns(group: &RuleGroup) -> String {
    Kind::ALL
        .into_iter()
        .filter(|k| !group.patterns(*k).is_empty())
        .map(|k| format!("{}: {}", k.as_str(), group.patterns(k).join(", ")))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use openmoat_core::RepoPolicy;

    use super::*;

    fn found(yaml: &str) -> Found {
        Found {
            path: "/code/app/.moat/policy.yaml".into(),
            root: "/code/app".into(),
            digest: "ab12".into(),
            text: yaml.to_owned(),
            policy: RepoPolicy::parse(yaml).unwrap(),
        }
    }

    #[test]
    fn the_question_names_the_file_its_digest_and_every_rule() {
        let yaml = "version: 1\nallow:\n  - id: deploy\n    shell: ['make deploy']\n  \
                    - id: keys\n    fs.read: ['~/.ssh/**']\nask:\n  - id: rel\n    \
                    shell: ['make release']\ndeny:\n  - id: no-push\n    shell: ['git push']\n";
        let user = Policy::parse(
            "version: 1\ndeny:\n  - id: keys\n    fs.read: ['~/.ssh/**']\n\
             allow:\n  - id: dev\n    shell: ['make *']\n",
        )
        .unwrap();
        let mut out = Vec::new();
        show(&mut out, &found(yaml), Some(&user), Some(&"0ld".to_owned())).unwrap();
        let shown = String::from_utf8(out).unwrap();
        for part in [
            "repository policy /code/app/.moat/policy.yaml\n",
            "  sha256:ab12\n",
            "replaces the trust given to sha256:0ld",
            "adds 2 allow rule(s) to your policy; your deny rules still win",
            "    allow repo:deploy: shell: make deploy\n",
            "    allow repo:keys: fs.read: ~/.ssh/** (a deny rule covers some or all of it",
            "its 1 ask and 1 deny rule(s) apply trusted or not",
            "    ask repo:rel: shell: make release\n",
            "    deny repo:no-push: shell: git push\n",
        ] {
            assert!(shown.contains(part), "{part}: {shown}");
        }

        let mut out = Vec::new();
        show(&mut out, &found(yaml), None, Some(&"ab12".to_owned())).unwrap();
        let shown = String::from_utf8(out).unwrap();
        assert!(shown.contains("already trusted as it is"), "{shown}");
        assert!(
            shown.contains("allow repo:deploy: shell: make deploy\n"),
            "{shown}"
        );
        assert!(shown.contains("could not be read"), "{shown}");
    }

    /// A right-to-left override in a rule would show it in another order than
    /// it is read: the question shows `?` in its place.
    #[test]
    fn the_question_shows_no_bidirectional_characters() {
        let yaml =
            "version: 1\nallow:\n  - id: deploy\n    shell: ['make \u{202E}yolped\u{202C} *']\n";
        let mut out = Vec::new();
        show(&mut out, &found(yaml), None, None).unwrap();
        let shown = String::from_utf8(out).unwrap();
        assert!(!shown.contains('\u{202E}'), "{shown:?}");
        assert!(
            shown.contains("allow repo:deploy: shell: make ?yolped? *"),
            "{shown}"
        );
    }
}
