//! `moat secret add`: broker a secret in one step (ADR-020). The entry is added
//! to the policy's `secrets:`, the diff shown and nothing written until the person
//! agrees; then the lock is re-pinned and the sandbox settings synced, which is
//! what hands the agent the placeholder instead of the value.

use std::fs;
use std::io::Write as _;

use anyhow::{Context as _, Result, bail};
use openmoat_core::{Secret, SecretSource, SecretTls};
use similar::{Algorithm, udiff::unified_diff};

use crate::cli::{Format, SecretAddArgs, SecretListArgs};
use crate::context::read_policy;
use crate::exit::Code;
use crate::home::{Home, write_private};
use crate::integrity;
use crate::render::{DIFF_CONTEXT_LINES, Deferred};

/// `moat secret add gh`: the GitHub API token most agents use, from the
/// variable `gh` and git's tools read.
const GITHUB: (&str, &str, &str) = ("api.github.com", "Authorization", "GITHUB_TOKEN");

/// One brokered secret as `moat secret list` shows it: where the value is read
/// from and where it goes, never the value.
#[derive(serde::Serialize)]
struct Listed<'a> {
    #[serde(flatten)]
    secret: &'a Secret,
    /// No deny rule covers where the value is read from, so the agent could
    /// read it there (`moat policy lint` warns too).
    source_exposed: bool,
}

/// `moat secret list`: read-only, so no terminal is needed.
pub fn list(args: &SecretListArgs) -> Result<Code> {
    let policy = Home::locate()?.load_policy()?;
    let listed: Vec<Listed<'_>> = policy
        .secrets
        .iter()
        .map(|secret| Listed {
            secret,
            source_exposed: openmoat_core::lint::exposed_source(&policy, secret).is_some(),
        })
        .collect();
    if args.format == Format::Json {
        crate::render::json(&serde_json::json!({ "secrets": listed }))?;
        return Ok(Code::Ok);
    }
    let mut out = Deferred::default();
    if listed.is_empty() {
        writeln!(out, "no brokered secrets; `openmoat secret add` adds one")?;
    }
    for item in &listed {
        let s = item.secret;
        let source = match &s.source {
            SecretSource::File(path) => format!("file {path}"),
            SecretSource::Env(name) => format!("env {name}"),
            SecretSource::Keychain { service, account } => {
                format!("keychain {service}/{account}")
            }
        };
        writeln!(
            out,
            "{:<14} {} header {}, from {source}",
            s.id, s.host, s.header
        )?;
        if item.source_exposed {
            writeln!(
                out,
                "{:<14} ! no deny rule covers its source: the agent can read the value there",
                ""
            )?;
        }
    }
    out.finish()?;
    Ok(Code::Ok)
}

pub fn add(args: &SecretAddArgs) -> Result<Code> {
    crate::terminal::refuse_agent("openmoat secret add")?;
    if !crate::terminal::interactive() {
        bail!(
            "`openmoat secret add` must be run by a person in a terminal, not from a hook or script"
        );
    }
    let secret = secret(args)?;
    let home = Home::locate()?;
    let path = home.policy_path();
    if !path.is_file() {
        bail!("no policy at {}; run `openmoat init`", path.display());
    }
    integrity::refuse_drift(&home, "add a secret")?;
    if home
        .load_policy()?
        .secrets
        .iter()
        .any(|s| s.id == secret.id)
    {
        bail!(
            "the policy already brokers a secret `{}`; `openmoat edit` changes it",
            secret.id
        );
    }
    let before = read_policy(&path)?;
    let mut after = with_entry(&before, &secret)?;
    let mut policy = lint_draft(&home, &after)?;
    // A brokered value the agent can read anyway protects nothing: deny its
    // source too, in the same diff, when no rule covers it yet.
    let mut source_denied = None;
    if openmoat_core::lint::exposed_source(&policy, &secret).is_some()
        && let Some((id, denied)) = with_source_deny(&after, &secret)?
    {
        policy = lint_draft(&home, &denied)?;
        after = denied;
        source_denied = Some(id);
    }
    let mut out = Deferred::default();
    for warning in openmoat_core::lint::warnings(&policy) {
        writeln!(out, "warning: {warning}")?;
    }
    let diff = unified_diff(
        Algorithm::Myers,
        &before,
        &after,
        DIFF_CONTEXT_LINES,
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
    if secret.terminates() {
        writeln!(
            out,
            "Inside `openmoat run`, OpenMoat decrypts HTTPS to {} to put it in, with its own \
             certificate authority (`openmoat proxy ca init`).",
            secret.host
        )?;
    }
    if !secret.allow.is_empty() {
        writeln!(
            out,
            "Only these requests get it, and any other request to {} is refused: {}.",
            secret.host,
            secret.allow.join(", ")
        )?;
    }
    if let Some(id) = &source_denied {
        writeln!(
            out,
            "The deny rule `{id}` keeps the agent from reading the value at its source."
        )?;
    }
    if !super::edit::confirm(&mut out, "Apply? [y/N] ")? {
        writeln!(out, "the policy was not changed")?;
        out.finish()?;
        return Ok(Code::Ok);
    }
    super::edit::apply(&home, &before, &after, &mut out)?;
    out.finish()?;
    super::sandbox::sync()?;
    if secret.terminates() {
        // The CA must cover the new host; making one is its own question.
        let policy = home.load_policy()?;
        let mut out = Deferred::default();
        if crate::proxy_ca::load(&home, &policy).is_ok() {
            writeln!(out, "The proxy CA already covers {}.", secret.host)?;
        } else {
            super::proxy::make_ca(&home, &policy, &mut out)?;
        }
        out.finish()?;
    }
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
        port: None,
        tls: args.tls_terminate.then_some(SecretTls::Terminate),
        allow: args.allow.clone(),
    })
}

/// Lint `text` as `moat edit` does, in the state directory agents cannot write.
fn lint_draft(home: &Home, text: &str) -> Result<openmoat_core::Policy> {
    let draft = home.root().join("policy.secret.yaml");
    write_private(&draft, text.as_bytes())?;
    let linted = home.load_policy_at(&draft);
    let _ = fs::remove_file(&draft);
    linted.context("the policy with the new secret does not lint")
}

/// `policy` with a deny rule for `secret`'s source (`env.read` of its variable,
/// `fs.read` of its file) first in the `deny:` list, and the rule's id. `None`
/// for a keychain source, a policy without a block `deny:` list, or one that
/// already has a rule with that id: then the lint warning stays.
fn with_source_deny(policy: &str, secret: &Secret) -> Result<Option<(String, String)>> {
    let (kind, value) = match &secret.source {
        SecretSource::Env(name) => ("env.read", name),
        SecretSource::File(path) => ("fs.read", path),
        SecretSource::Keychain { .. } => return Ok(None),
    };
    let id = format!("secret-{}", secret.id);
    let lines: Vec<&str> = policy.lines().collect();
    let taken = lines
        .iter()
        .any(|l| l.trim_start().trim_start_matches("- ").trim() == format!("id: {id}"));
    let Some(at) = lines
        .iter()
        .position(|l| l.split('#').next().unwrap_or("").trim_end() == "deny:")
    else {
        return Ok(None);
    };
    if taken {
        return Ok(None);
    }
    let indent = lines[at + 1..]
        .iter()
        .find(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter(|l| l.trim_start().starts_with('-'))
        .map_or("  ", |l| &l[..l.len() - l.trim_start().len()]);
    let quoted = serde_json::to_string(value)?;
    let group = format!(
        "{indent}- id: {id}\n{indent}  reason: the source of the brokered secret `{}`\n\
         {indent}  {kind}: [{quoted}]\n",
        secret.id
    );
    let mut out = String::new();
    for (n, line) in lines.iter().enumerate() {
        out.push_str(line);
        out.push('\n');
        if n == at {
            out.push_str(&group);
        }
    }
    Ok(Some((id, out)))
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
        _ => bail!(
            "the policy's `secrets:` is not a block list; add the secret with `openmoat edit`"
        ),
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
            tls_terminate: false,
            allow: Vec::new(),
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
            tls_terminate: false,
            allow: Vec::new(),
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

    fn other(id: &str, env: Option<&str>, file: Option<&str>) -> Secret {
        secret(&SecretAddArgs {
            id: id.into(),
            host: Some("api.example.com".into()),
            header: None,
            env: env.map(Into::into),
            file: file.map(Into::into),
            tls_terminate: false,
            allow: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn tls_termination_and_rules_are_written_as_the_policy_reads_them() {
        let routed = secret(&SecretAddArgs {
            id: "gh".into(),
            host: None,
            header: None,
            env: None,
            file: None,
            tls_terminate: true,
            allow: vec!["GET /repos/**".into(), "POST /repos/*/*/issues".into()],
        })
        .unwrap();
        assert!(routed.terminates());
        let out = with_entry("version: 1\n", &routed).unwrap();
        assert!(out.contains("tls: terminate"), "{out}");
        assert_eq!(secrets(&out), [routed]);
    }

    #[test]
    fn an_exposed_source_gets_a_deny_rule_and_a_covered_one_none() {
        use openmoat_core::DEFAULT_POLICY;
        use openmoat_core::lint::exposed_source;
        for (s, kind) in [
            (
                other("ex", None, Some("~/.config/example/token")),
                "fs.read",
            ),
            (other("db", Some("WEBHOOK_SALT"), None), "env.read"),
        ] {
            let with = with_entry(DEFAULT_POLICY, &s).unwrap();
            assert!(exposed_source(&Policy::parse(&with).unwrap(), &s).is_some());
            let (id, denied) = with_source_deny(&with, &s).unwrap().expect("a deny rule");
            assert_eq!(id, format!("secret-{}", s.id));
            assert!(denied.contains(&format!("    {kind}: [")), "{denied}");
            let policy = Policy::parse(&denied).expect("still lints");
            assert_eq!(exposed_source(&policy, &s), None);
            assert!(
                with_source_deny(&denied, &s).unwrap().is_none(),
                "the id is taken"
            );
        }
        // `*_KEY` and `DATABASE_URL` are already denied by `env-secrets`, and
        // `~/.ssh` by `secrets-paths`
        for s in [
            other("stripe", Some("STRIPE_API_KEY"), None),
            other("db", Some("DATABASE_URL"), None),
            other("ssh", None, Some("~/.ssh/deploy_token")),
        ] {
            let with = with_entry(DEFAULT_POLICY, &s).unwrap();
            assert_eq!(exposed_source(&Policy::parse(&with).unwrap(), &s), None);
        }
    }
}
