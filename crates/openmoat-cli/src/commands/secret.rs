//! `moat secret add`: broker a secret in one step (ADR-020). The entry is added
//! to the policy's `secrets:`, the diff shown and nothing written until the person
//! agrees; then the lock is re-pinned and the sandbox settings synced, which is
//! what hands the agent the placeholder instead of the value.

use std::fs;
use std::io::Write as _;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Secret, SecretSource};
use similar::{Algorithm, udiff::unified_diff};

use crate::cli::SecretAddArgs;
use crate::context::read_policy;
use crate::exit::Code;
use crate::home::{Home, write_private};
use crate::integrity;
use crate::render::Deferred;

/// `moat secret add gh`: the GitHub API token most agents use, from the
/// variable `gh` and git's tools read.
const GITHUB: (&str, &str, &str) = ("api.github.com", "Authorization", "GITHUB_TOKEN");

pub fn add(args: &SecretAddArgs) -> Result<Code> {
    if !crate::terminal::interactive() {
        bail!("`moat secret add` must be run by a person in a terminal, not from a hook or script");
    }
    let secret = secret(args)?;
    let home = Home::locate()?;
    let path = home.policy_path();
    if !path.is_file() {
        bail!("no policy at {}; run `moat init`", path.display());
    }
    integrity::refuse_drift(&home, "add a secret")?;
    if home
        .load_policy()?
        .secrets
        .iter()
        .any(|s| s.id == secret.id)
    {
        bail!(
            "the policy already brokers a secret `{}`; `moat edit` changes it",
            secret.id
        );
    }
    let before = read_policy(&path)?;
    let after = with_entry(&before, &secret)?;
    // Lint the result as `moat edit` does, in the state directory agents cannot write.
    let draft = home.root().join("policy.secret.yaml");
    write_private(&draft, after.as_bytes())?;
    let linted = home.load_policy_at(&draft);
    let _ = fs::remove_file(&draft);
    let policy = linted.context("the policy with the new secret does not lint")?;
    let mut out = Deferred::default();
    for warning in openmoat_core::lint::warnings(&policy) {
        writeln!(out, "warning: {warning}")?;
    }
    let diff = unified_diff(
        Algorithm::Myers,
        &before,
        &after,
        3,
        Some(("policy.yaml (installed)", "policy.yaml (with the secret)")),
    );
    write!(out, "{diff}")?;
    writeln!(
        out,
        "The agent will hold `{}` instead of the value; OpenMoat puts the value in the \
         {} header of requests to {} only.",
        secret.placeholder(),
        secret.header,
        secret.host
    )?;
    if !super::edit::confirm(&mut out, "Apply? [y/N] ")? {
        writeln!(out, "the policy was not changed")?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    super::edit::apply(&home, &before, &after, &mut out)?;
    out.finish()?;
    super::sandbox::sync()?;
    println!("Start a new agent session to use it.");
    Ok(Code::Ok)
}

/// The secret `args` describe: `gh` alone is GitHub's API token, any other id
/// names its host and source.
fn secret(args: &SecretAddArgs) -> Result<Secret> {
    let preset = (args.id == "gh").then_some(GITHUB);
    let host = args
        .host
        .clone()
        .or(preset.map(|p| p.0.to_owned()))
        .context("give --host: the one host whose requests get the secret")?;
    let header = args
        .header
        .clone()
        .unwrap_or_else(|| preset.map_or("Authorization", |p| p.1).to_owned());
    let source = match (&args.env, &args.file) {
        (Some(name), None) => SecretSource::Env(name.clone()),
        (None, Some(file)) => SecretSource::File(file.clone()),
        (None, None) => match preset {
            Some(p) => SecretSource::Env(p.2.to_owned()),
            None => bail!("give --env NAME or --file PATH: where OpenMoat reads the value"),
        },
        (Some(_), Some(_)) => bail!("give --env or --file, not both"),
    };
    Ok(Secret {
        id: args.id.clone(),
        host,
        header,
        source,
        plain_http: false,
    })
}

/// `policy` with `secret` added to its `secrets:` list, or a new list at the end.
/// Comments and layout are kept: the entry is text inserted after `secrets:`.
fn with_entry(policy: &str, secret: &Secret) -> Result<String> {
    let entry = openmoat_core::yaml::to_string(&[secret])?;
    let lines: Vec<&str> = policy.lines().collect();
    let Some(at) = lines.iter().position(|l| l.starts_with("secrets:")) else {
        let mut out = policy.trim_end_matches('\n').to_owned();
        out.push_str("\nsecrets:\n");
        out.push_str(&indented(&entry, "  "));
        return Ok(out);
    };
    let rest = lines[at]["secrets:".len()..]
        .split('#')
        .next()
        .unwrap_or("")
        .trim();
    let indent = match rest {
        "" => lines[at + 1..]
            .iter()
            .map(|l| l.trim_end())
            .find(|l| !l.trim_start().is_empty() && !l.trim_start().starts_with('#'))
            .filter(|l| l.trim_start().starts_with('-'))
            .map_or("  ", |l| &l[..l.len() - l.trim_start().len()]),
        "[]" => "  ",
        _ => bail!("the policy's `secrets:` is not a block list; add the secret with `moat edit`"),
    };
    let mut out = String::new();
    for line in &lines[..at] {
        out.push_str(line);
        out.push('\n');
    }
    out.push_str("secrets:\n");
    out.push_str(&indented(&entry, indent));
    for line in &lines[at + 1..] {
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

fn indented(text: &str, indent: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        out.push_str(indent);
        out.push_str(line);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use openmoat_core::Policy;

    use super::*;

    fn gh() -> Secret {
        let args = SecretAddArgs {
            id: "gh".into(),
            host: None,
            header: None,
            env: None,
            file: None,
        };
        secret(&args).unwrap()
    }

    fn secrets(policy: &str) -> Vec<Secret> {
        Policy::parse(policy).unwrap().secrets
    }

    #[test]
    fn gh_alone_is_the_github_token() {
        let s = gh();
        assert_eq!(
            (s.host.as_str(), s.header.as_str()),
            ("api.github.com", "Authorization")
        );
        assert_eq!(s.source, SecretSource::Env("GITHUB_TOKEN".into()));
        let other = SecretAddArgs {
            id: "api".into(),
            host: None,
            header: None,
            env: Some("API_KEY".into()),
            file: None,
        };
        assert!(secret(&other).is_err(), "another id needs its host");
    }

    #[test]
    fn a_policy_without_secrets_gets_a_list() {
        let out = with_entry("version: 1\n# end\n", &gh()).unwrap();
        assert!(
            out.starts_with("version: 1\n# end\nsecrets:\n  - id: gh\n"),
            "{out}"
        );
        assert_eq!(secrets(&out), [gh()]);
    }

    #[test]
    fn an_existing_list_keeps_its_entries_and_indent() {
        let other = "- id: x\n  host: x.test\n  header: X-Key\n  source: { env: X_KEY }\n";
        let policy = format!("version: 1\nsecrets:\n{other}deny: []\n");
        let out = with_entry(&policy, &gh()).unwrap();
        let ids: Vec<String> = secrets(&out).into_iter().map(|s| s.id).collect();
        assert_eq!(ids, ["gh", "x"]);
        assert!(out.ends_with("deny: []\n"), "{out}");
        let empty = with_entry("version: 1\nsecrets: []  # none yet\n", &gh()).unwrap();
        assert_eq!(secrets(&empty), [gh()]);
        let flow =
            "version: 1\nsecrets: [{ id: x, host: x.test, header: X, source: { env: X } }]\n";
        assert!(with_entry(flow, &gh()).is_err());
    }
}
