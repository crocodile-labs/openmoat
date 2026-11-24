//! AWS STS `AssumeRole` credentials narrowed by an inline session policy (AWS
//! STS API Reference, `AssumeRole`: `Policy`, `DurationSeconds` 900 to
//! 43200; the session's permissions are the intersection of the role's and
//! the session policy's). Signed with `SigV4` from the long-lived keys of one
//! profile of the AWS credentials file, which only this process reads.
//!
//! The value is the JSON AWS's `credential_process` prints (AWS CLI User
//! Guide, "Sourcing credentials with an external process"), handed out by
//! `helper: aws` only: AWS requests are signed by the client, so no header
//! of them can be filled in by the proxy.

use anyhow::{Context as _, Result, bail, ensure};
use openmoat_core::mint::{AWS_CREDENTIALS, AwsSts};
use zeroize::Zeroizing;

use super::encode::{expiry_ms, form};
use super::sigv4::{Keys, ToSign, amz_date, authorization};
use super::{Minted, Request, Response, refused};

/// The most characters STS takes in session policies.
const MAX_POLICY: usize = 2048;
const FORM: &str = "application/x-www-form-urlencoded; charset=utf-8";

/// The STS endpoint of `region`.
pub fn host(region: &str) -> String {
    format!("sts.{region}.amazonaws.com")
}

/// The keys of `profile` in the text of an AWS credentials file.
pub fn keys(ini: &str, profile: &str) -> Result<Keys> {
    let mut in_profile = false;
    let (mut id, mut secret, mut token) = (None, None, None);
    for line in ini.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_profile = name.trim() == profile;
            continue;
        }
        let Some((key, value)) = line.split_once('=').filter(|_| in_profile) else {
            continue;
        };
        let value = Zeroizing::new(value.trim().to_owned());
        match key.trim() {
            "aws_access_key_id" => id = Some(value.to_string()),
            "aws_secret_access_key" => secret = Some(value),
            "aws_session_token" => token = Some(value),
            _ => {}
        }
    }
    match (id, secret) {
        (Some(access_key_id), Some(secret_access_key)) => Ok(Keys {
            access_key_id,
            secret_access_key,
            session_token: token,
        }),
        _ => bail!("profile `{profile}` of the credentials file has no access key and secret"),
    }
}

/// The inline session policy: `actions` on `resources`, nothing else.
pub fn policy(sts: &AwsSts) -> Result<String> {
    let policy = serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": sts.actions,
            "Resource": sts.resources,
        }],
    })
    .to_string();
    ensure!(
        policy.len() <= MAX_POLICY,
        "the session policy is {} characters; STS takes at most {MAX_POLICY}",
        policy.len()
    );
    Ok(policy)
}

/// The signed `AssumeRole` request for secret `id` at `now` (ms), for a
/// session of `lifetime_secs`.
pub fn request(
    id: &str,
    sts: &AwsSts,
    keys: &Keys,
    (now, lifetime_secs): (i64, u64),
) -> Result<Request> {
    let session_name: String = format!("openmoat-{id}").chars().take(64).collect();
    let duration = lifetime_secs.to_string();
    let policy = policy(sts)?;
    let body = form(&[
        ("Action", "AssumeRole"),
        ("DurationSeconds", &duration),
        ("Policy", &policy),
        ("RoleArn", &sts.role),
        ("RoleSessionName", &session_name),
        ("Version", "2011-06-15"),
    ]);
    let date = amz_date(now);
    let host = host(&sts.region);
    let mut signed: Vec<(&str, &str)> = vec![
        ("content-type", FORM),
        ("host", &host),
        ("x-amz-date", &date),
    ];
    if let Some(token) = &keys.session_token {
        signed.push(("x-amz-security-token", token.as_str()));
    }
    let auth = authorization(
        &ToSign {
            method: "POST",
            path: "/",
            query: "",
            headers: &signed,
            body: body.as_bytes(),
            amz_date: &date,
            region: &sts.region,
            service: "sts",
        },
        keys,
    );
    let mut headers = vec![
        ("X-Amz-Date", Zeroizing::new(date.clone())),
        ("Authorization", auth),
    ];
    if let Some(token) = &keys.session_token {
        headers.push(("X-Amz-Security-Token", token.clone()));
    }
    Ok(Request {
        method: "POST",
        path: "/".into(),
        headers,
        content_type: FORM,
        body: Zeroizing::new(body.into_bytes()),
    })
}

/// The text of the first `<name>` element of `xml`, trimmed and without
/// the line breaks AWS wraps long tokens with.
fn element(xml: &str, name: &str) -> Option<Zeroizing<String>> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml.find(&open)? + open.len();
    let end = start + xml[start..].find(&close)?;
    let text: String = xml[start..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    (!text.is_empty()).then(|| Zeroizing::new(text))
}

/// The `credential_process` JSON and its parts in STS's answer.
pub fn parse(response: &Response) -> Result<Minted> {
    let xml = std::str::from_utf8(&response.body).context("the answer is not text")?;
    if response.status != 200 {
        let code = element(xml, "Code").map(|c| c.to_string());
        return Err(refused("AWS STS", response, code));
    }
    let get = |name| element(xml, name).with_context(|| format!("the answer has no `{name}`"));
    let (id, secret, token, expiration) = (
        get("AccessKeyId")?,
        get("SecretAccessKey")?,
        get("SessionToken")?,
        get("Expiration")?,
    );
    let expires_ms =
        expiry_ms(&expiration).context("the answer's `Expiration` is not a UTC time")?;
    let value = serde_json::json!({
        "Version": 1,
        "AccessKeyId": id.as_str(),
        "SecretAccessKey": secret.as_str(),
        "SessionToken": token.as_str(),
        "Expiration": expiration.as_str(),
    })
    .to_string();
    Ok(Minted {
        value: Zeroizing::new(value),
        expires_ms,
        masked: vec![secret, token],
    })
}

/// Mint one session of `lifetime_secs` at `now` (ms) for secret `id`.
pub fn mint(
    (id, sts): (&str, &AwsSts),
    (now, lifetime_secs): (i64, u64),
    read: &dyn Fn(&str) -> Result<Zeroizing<String>>,
    send: &dyn Fn(&str, &Request) -> Result<Response>,
) -> Result<Minted> {
    let file = sts.credentials.as_deref().unwrap_or(AWS_CREDENTIALS);
    let keys = keys(&read(file)?, sts.profile.as_deref().unwrap_or("default"))?;
    let request = request(id, sts, &keys, (now, lifetime_secs))?;
    let response = send(&host(&sts.region), &request)?;
    parse(&response)
}
