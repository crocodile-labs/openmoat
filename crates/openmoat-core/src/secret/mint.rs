//! Brokered secrets OpenMoat mints itself for one session (ADR-118): the
//! schema of `source: { mint: … }`, of a secret's `helper:`, and their
//! validation. Signing and sending the minting request is the CLI's job
//! (`secrets/mint.rs`), and only `openmoat proxy` and `openmoat run`'s proxy
//! do it.
//!
//! Each provider here has an official call that turns a credential the person
//! holds into a narrower one that expires on its own: a GitHub App
//! installation token limited to named repositories and permissions, an AWS
//! STS session limited by a session policy, a Google Cloud service account
//! access token limited to named scopes. Every narrowing field is required:
//! a mint that would hand out everything the person's credential can do is
//! refused here, so the token the agent's side can use is never wider than
//! the policy says.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::command::duration_secs;

/// The most repositories one GitHub installation token may name (GitHub's own limit).
pub const MAX_GITHUB_REPOSITORIES: usize = 500;
/// The shortest AWS STS session (AWS's own limit, 15 minutes).
pub const MIN_AWS_LIFETIME_SECS: u64 = 15 * 60;
/// The longest AWS STS session (AWS's own limit, 12 hours).
pub const MAX_AWS_LIFETIME_SECS: u64 = 12 * 60 * 60;
/// The shortest Google Cloud access token a mint asks for.
pub const MIN_GCP_LIFETIME_SECS: u64 = 60;
/// The longest Google Cloud access token without an organisation policy
/// that extends it (Google's default limit, 1 hour).
pub const MAX_GCP_LIFETIME_SECS: u64 = 60 * 60;
/// The lifetime a mint asks for when the policy names none.
pub const DEFAULT_LIFETIME: &str = "15m";
/// Where the AWS CLI keeps long-lived keys, read by the proxy only.
pub const AWS_CREDENTIALS: &str = "~/.aws/credentials";
/// Where `gcloud auth application-default login` keeps its credential.
pub const GCP_CREDENTIALS: &str = "~/.config/gcloud/application_default_credentials.json";
/// The scope prefix every Google OAuth scope has.
const GCP_SCOPE_PREFIX: &str = "https://www.googleapis.com/auth/";

/// `source: { mint: { <provider>: … } }`. `Debug` names the provider only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum MintSource {
    /// A GitHub App installation access token (one hour, GitHub's limit).
    GithubApp(GithubApp),
    /// AWS STS `AssumeRole` credentials with a session policy.
    AwsSts(AwsSts),
    /// A Google Cloud service account access token (`generateAccessToken`).
    Gcp(Gcp),
}

/// `mint: { github-app: … }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubApp {
    /// The App's client ID or numeric App ID: the JWT's issuer.
    pub app: String,
    /// The installation the token is for.
    pub installation: u64,
    /// The App's private key (PEM), absolute or under `~/`; read by the proxy only.
    pub key: String,
    /// The repositories (names, without the owner) the token may reach.
    pub repositories: Vec<String>,
    /// The permissions the token gets, `contents: read` and so on.
    pub permissions: BTreeMap<String, String>,
    /// How long before the token expires a new one is minted; 10 minutes when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_before: Option<String>,
}

/// `mint: { aws-sts: … }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSts {
    /// The role to assume, `arn:aws:iam::<account>:role/<name>`.
    pub role: String,
    /// The region whose STS endpoint is asked, `us-east-1` and so on.
    pub region: String,
    /// The profile of the credentials file the long-lived keys are in; `default` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// The credentials file; [`AWS_CREDENTIALS`] when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
    /// The actions the session may take (`s3:GetObject`); never `*`.
    pub actions: Vec<String>,
    /// The resources it may take them on (ARNs); never `*`.
    pub resources: Vec<String>,
    /// How long the session lasts, 15m to 12h; [`DEFAULT_LIFETIME`] when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<String>,
    /// How long before it ends a new one is minted; a fifth of the lifetime when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_before: Option<String>,
}

/// `mint: { gcp: … }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gcp {
    /// The service account the token is for, `name@project.iam.gserviceaccount.com`.
    pub service_account: String,
    /// The credential that may impersonate it (`authorized_user` or
    /// `service_account` JSON); [`GCP_CREDENTIALS`] when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
    /// The OAuth scopes the token gets.
    pub scopes: Vec<String>,
    /// How long the token lasts, 1m to 1h; [`DEFAULT_LIFETIME`] when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<String>,
    /// How long before it ends a new one is minted; a fifth of the lifetime when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_before: Option<String>,
}

/// `helper:` of a secret: a local helper protocol of a tool, through which
/// the tool gets the value from the proxy when it asks for the secret's host,
/// without TLS termination (ADR-118). The value then reaches that tool's
/// process: use it for minted, short-lived values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", deny_unknown_fields)]
pub enum Helper {
    /// git's credential helper, for `https://<host>`; `username` is what git
    /// sends with the value (`x-access-token` for a GitHub App token).
    Git {
        /// The user name git sends with the value.
        username: String,
    },
    /// The AWS CLI's and SDKs' `credential_process`, for an `aws-sts` mint.
    Aws,
}

impl Helper {
    /// The helper's name in the wire protocol and in audit rows.
    #[must_use]
    pub fn tool(&self) -> &'static str {
        match self {
            Self::Git { .. } => "git",
            Self::Aws => "aws",
        }
    }
}

impl std::fmt::Debug for MintSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintSource")
            .field("provider", &self.provider())
            .finish_non_exhaustive()
    }
}

impl MintSource {
    /// The provider's name as the policy writes it.
    #[must_use]
    pub fn provider(&self) -> &'static str {
        match self {
            Self::GithubApp(_) => "github-app",
            Self::AwsSts(_) => "aws-sts",
            Self::Gcp(_) => "gcp",
        }
    }

    /// The files the proxy reads the person's own credential from: the
    /// agent must be denied them (`openmoat policy lint` warns otherwise).
    #[must_use]
    pub fn files(&self) -> Vec<&str> {
        match self {
            Self::GithubApp(g) => vec![g.key.as_str()],
            Self::AwsSts(a) => vec![a.credentials.as_deref().unwrap_or(AWS_CREDENTIALS)],
            Self::Gcp(g) => vec![g.credentials.as_deref().unwrap_or(GCP_CREDENTIALS)],
        }
    }

    /// The lifetime asked for, in seconds; GitHub's tokens always last an hour.
    #[must_use]
    pub fn lifetime_secs(&self) -> u64 {
        let asked = |l: &Option<String>| {
            duration_secs(l.as_deref().unwrap_or(DEFAULT_LIFETIME)).unwrap_or(15 * 60)
        };
        match self {
            Self::GithubApp(_) => 60 * 60,
            Self::AwsSts(a) => asked(&a.lifetime),
            Self::Gcp(g) => asked(&g.lifetime),
        }
    }

    /// How long before the value expires a new one is minted, in seconds:
    /// `refresh_before`, else 10 minutes for GitHub and a fifth of the
    /// lifetime for the others.
    #[must_use]
    pub fn refresh_before_secs(&self) -> u64 {
        let (written, default) = match self {
            Self::GithubApp(g) => (&g.refresh_before, 10 * 60),
            Self::AwsSts(a) => (&a.refresh_before, self.lifetime_secs() / 5),
            Self::Gcp(g) => (&g.refresh_before, self.lifetime_secs() / 5),
        };
        written
            .as_deref()
            .and_then(duration_secs)
            .unwrap_or(default)
            .max(10)
    }
}

/// Why `source` cannot be used, if it cannot.
pub(super) fn check(source: &MintSource) -> Result<(), String> {
    for file in source.files() {
        if !(crate::paths::is_absolute(file) || file.starts_with("~/")) {
            return Err(format!(
                "mint file `{file}` must be absolute or start with `~/`"
            ));
        }
    }
    match source {
        MintSource::GithubApp(g) => check_github(g),
        MintSource::AwsSts(a) => check_aws(a),
        MintSource::Gcp(g) => check_gcp(g),
    }?;
    let lifetime = source.lifetime_secs();
    let before = source.refresh_before_secs();
    if before >= lifetime {
        return Err("mint refresh_before must be shorter than the lifetime".into());
    }
    Ok(())
}

fn check_github(g: &GithubApp) -> Result<(), String> {
    if g.app.is_empty()
        || !g
            .app
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.')
    {
        return Err("github-app `app` must be the App's client ID or numeric App ID".into());
    }
    if g.installation == 0 {
        return Err("github-app `installation` must be the installation's numeric ID".into());
    }
    if g.repositories.is_empty() || g.repositories.len() > MAX_GITHUB_REPOSITORIES {
        return Err(format!(
            "github-app `repositories` must name 1 to {MAX_GITHUB_REPOSITORIES} repositories: \
             without them the token reaches every repository of the installation"
        ));
    }
    let name = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    if let Some(bad) = g.repositories.iter().find(|r| !name(r)) {
        return Err(format!(
            "github-app repository `{bad}` must be a repository name without its owner"
        ));
    }
    if g.permissions.is_empty() {
        return Err(
            "github-app `permissions` must name each permission the token gets: without them \
             it gets every permission of the App"
                .into(),
        );
    }
    for (permission, level) in &g.permissions {
        if permission.is_empty()
            || !permission
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_')
        {
            return Err(format!(
                "github-app permission `{permission}` is not a permission name"
            ));
        }
        if !matches!(level.as_str(), "read" | "write" | "admin") {
            return Err(format!(
                "github-app permission `{permission}` must be `read`, `write` or `admin`"
            ));
        }
    }
    lifetime_text("github-app", None, g.refresh_before.as_deref(), (1, 1))
}

fn check_aws(a: &AwsSts) -> Result<(), String> {
    let role = a.role.split(':').collect::<Vec<_>>();
    let partition_ok = role.get(1).is_some_and(|p| p.starts_with("aws"));
    let account_ok = role
        .get(4)
        .is_some_and(|n| n.len() == 12 && n.bytes().all(|b| b.is_ascii_digit()));
    if role.len() != 6
        || role[0] != "arn"
        || !partition_ok
        || role[2] != "iam"
        || !account_ok
        || !role[5].starts_with("role/")
        || a.role.chars().any(char::is_control)
    {
        return Err(format!(
            "aws-sts `role` `{}` must be a role ARN, arn:aws:iam::<account>:role/<name>",
            a.role
        ));
    }
    if a.region.is_empty()
        || !a
            .region
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(format!(
            "aws-sts `region` `{}` is not a region name",
            a.region
        ));
    }
    if let Some(profile) = &a.profile
        && (profile.is_empty()
            || profile.contains([']', '['])
            || profile.chars().any(char::is_control))
    {
        return Err("aws-sts `profile` is not a profile name".into());
    }
    if a.actions.is_empty() || a.resources.is_empty() {
        return Err(
            "aws-sts needs `actions` and `resources`: the session policy is what narrows the \
             session below the role's own permissions"
                .into(),
        );
    }
    for action in &a.actions {
        let (service, name) = action.split_once(':').unwrap_or(("", ""));
        let ok = |s: &str, star: bool| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || (star && b == b'*'))
        };
        if !ok(service, false) || !ok(name, true) || name == "*" {
            return Err(format!(
                "aws-sts action `{action}` must be `service:Action` and not every action of a \
                 service"
            ));
        }
    }
    for resource in &a.resources {
        if !resource.starts_with("arn:")
            || resource == "arn:*"
            || resource
                .chars()
                .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return Err(format!(
                "aws-sts resource `{resource}` must be an ARN, not `*`"
            ));
        }
    }
    lifetime_text(
        "aws-sts",
        a.lifetime.as_deref(),
        a.refresh_before.as_deref(),
        (MIN_AWS_LIFETIME_SECS, MAX_AWS_LIFETIME_SECS),
    )
}

fn check_gcp(g: &Gcp) -> Result<(), String> {
    let account = &g.service_account;
    let (name, domain) = account.split_once('@').unwrap_or(("", ""));
    if name.is_empty()
        || !domain.ends_with(".gserviceaccount.com")
        || !account
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"@.-_".contains(&b))
    {
        return Err(format!(
            "gcp `service_account` `{account}` must be a service account's email"
        ));
    }
    if g.scopes.is_empty() {
        return Err("gcp `scopes` must name the OAuth scopes the token gets".into());
    }
    if let Some(bad) = g.scopes.iter().find(|s| {
        s.strip_prefix(GCP_SCOPE_PREFIX).is_none_or(|rest| {
            rest.is_empty()
                || !rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
    }) {
        return Err(format!(
            "gcp scope `{bad}` must be a Google OAuth scope, {GCP_SCOPE_PREFIX}…"
        ));
    }
    lifetime_text(
        "gcp",
        g.lifetime.as_deref(),
        g.refresh_before.as_deref(),
        (MIN_GCP_LIFETIME_SECS, MAX_GCP_LIFETIME_SECS),
    )
}

/// `lifetime` and `refresh_before` as written: durations, the lifetime within `range`.
fn lifetime_text(
    provider: &str,
    lifetime: Option<&str>,
    before: Option<&str>,
    (min, max): (u64, u64),
) -> Result<(), String> {
    if let Some(text) = lifetime {
        let secs = duration_secs(text).ok_or_else(|| {
            format!("{provider} lifetime `{text}` is not a duration such as `15m`")
        })?;
        if !(min..=max).contains(&secs) {
            return Err(format!(
                "{provider} lifetime `{text}` must be from {min}s to {max}s"
            ));
        }
    }
    if let Some(text) = before
        && duration_secs(text).is_none_or(|s| s < 10)
    {
        return Err(format!(
            "{provider} refresh_before `{text}` must be a duration of at least 10s"
        ));
    }
    Ok(())
}

/// Why `helper` cannot carry a secret with `source` to `host`, if it cannot.
pub(super) fn check_helper(
    helper: Option<&Helper>,
    source: &super::Source,
    host: &str,
) -> Result<(), String> {
    let aws_mint = matches!(source, super::Source::Mint(MintSource::AwsSts(_)));
    match helper {
        None if aws_mint => Err(
            "an `aws-sts` mint needs `helper: aws`: AWS requests are signed by the client, so \
             the proxy cannot put the credentials in a header"
                .into(),
        ),
        Some(Helper::Aws) if !aws_mint => {
            Err("`helper: aws` hands out credentials an `aws-sts` mint made, nothing else".into())
        }
        None | Some(Helper::Aws) => Ok(()),
        Some(Helper::Git { username }) => {
            if host.parse::<core::net::Ipv4Addr>().is_ok() {
                return Err(format!(
                    "`helper: git` needs a DNS name; {host} is an address"
                ));
            }
            if username.is_empty()
                || !username
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
            {
                return Err(
                    "`helper: git` needs a user name of letters, digits, `.`, `_`, `-` or `@`"
                        .into(),
                );
            }
            Ok(())
        }
    }
}
