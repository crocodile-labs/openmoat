//! Minting against recorded answers (ADR-118): no network. Each request is
//! compared with a golden file (`fixtures/*.request`, rewritten with
//! `OPENMOAT_TEST_UPDATE_GOLDEN=1`), each answer read from a fixture shaped
//! as the provider's documentation shows. Every credential here is made up.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use openmoat_core::Policy;
use openmoat_core::mint::MintSource;
use zeroize::Zeroizing;

use super::{Minted, Minter, Request, Response, Transport, answer, aws, gcp, github, rsa};
use crate::remote::https::head;
use crate::secrets::Fetch as _;

/// 2026-11-23T10:00:00Z.
fn now() -> i64 {
    crate::time::parse_rfc3339("2026-11-23T10:00:00Z").unwrap_or_default()
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/secrets/mint/fixtures")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// `request` to `host` as sent, compared with the golden file `name`.
fn golden(name: &str, host: &str, request: &Request) {
    let sent = format!(
        "{}{}",
        head(host, request).as_str(),
        String::from_utf8_lossy(&request.body)
    );
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/secrets/mint/fixtures")
        .join(name);
    if std::env::var_os("OPENMOAT_TEST_UPDATE_GOLDEN").is_some() {
        std::fs::write(&path, &sent).unwrap();
    }
    assert_eq!(
        sent,
        fixture(name),
        "{name}: rewrite with OPENMOAT_TEST_UPDATE_GOLDEN=1 and review"
    );
}

fn response(status: u16, body: &str) -> Response {
    Response {
        status,
        body: Zeroizing::new(body.as_bytes().to_vec()),
    }
}

fn mint(policy_source: &str) -> MintSource {
    let policy = Policy::parse(&format!("version: 1\nsecrets:\n{policy_source}")).unwrap();
    match &policy.secrets[0].source {
        openmoat_core::SecretSource::Mint(m) => m.clone(),
        other => panic!("not a mint: {other:?}"),
    }
}

fn github_app() -> openmoat_core::mint::GithubApp {
    match mint(
        "  - id: gh\n    host: api.github.com\n    header: Authorization\n    source:\n      mint:\n        \
         github-app:\n          app: Iv23liFakeApp\n          installation: 42\n          \
         key: ~/.config/moat/app.pem\n          repositories: [openmoat]\n          \
         permissions: { contents: read, pull_requests: write }\n",
    ) {
        MintSource::GithubApp(g) => g,
        _ => unreachable!("parsed as github-app"),
    }
}

fn sts() -> openmoat_core::mint::AwsSts {
    match mint(
        "  - id: s3\n    host: s3.us-east-1.amazonaws.com\n    header: X-Amz-Security-Token\n    \
         helper: aws\n    source:\n      mint:\n        aws-sts:\n          \
         role: arn:aws:iam::123456789012:role/agent\n          region: us-east-1\n          \
         actions: [s3:GetObject, s3:ListBucket]\n          \
         resources: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']\n",
    ) {
        MintSource::AwsSts(a) => a,
        _ => unreachable!("parsed as aws-sts"),
    }
}

fn gcp_source() -> openmoat_core::mint::Gcp {
    match mint(
        "  - id: gcs\n    host: storage.googleapis.com\n    header: Authorization\n    tls: terminate\n    \
         source:\n      mint:\n        gcp:\n          service_account: agent@demo.iam.gserviceaccount.com\n          \
         scopes: [https://www.googleapis.com/auth/devstorage.read_only]\n          lifetime: 10m\n",
    ) {
        MintSource::Gcp(g) => g,
        _ => unreachable!("parsed as gcp"),
    }
}

/// A 2048-bit RSA key in PKCS#8 PEM made by `openssl` now; `None` where
/// there is no `openssl` (then the signing tests say so and stop).
fn rsa_key() -> Option<String> {
    let out = std::process::Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:2048",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    String::from_utf8(out.stdout).ok()
}

#[test]
fn github_mints_a_token_for_the_named_repositories_and_permissions() {
    let app = github_app();
    let request = github::request(&app, "JWT");
    golden("github-access-token.request", github::HOST, &request);
    let minted = github::parse(&app, &response(201, &fixture("github-access-token.json"))).unwrap();
    assert_eq!(minted.value.as_str(), "FAKE-INSTALLATION-TOKEN-0123456789");
    let answered = answer(minted, now(), 3600).unwrap();
    // Its expiry, an hour after it was made, ends it; not the asked lifetime.
    assert_eq!(answered.lifetime, Duration::from_hours(1));
    assert_eq!(answered.masked.len(), 1);
}

#[test]
fn github_answers_that_widen_or_refuse_are_errors_without_the_body() {
    let app = github_app();
    let wider =
        fixture("github-access-token.json").replace("\"pull_requests\"", "\"administration\"");
    let err = github::parse(&app, &response(201, &wider))
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("`administration`"), "{err}");
    let denied = response(
        401,
        "{\"message\":\"Bad credentials\",\"token\":\"FAKE-NEVER-SHOWN\"}",
    );
    let err = format!("{:#}", github::parse(&app, &denied).err().unwrap());
    assert!(err.contains("HTTP 401: Bad credentials"), "{err}");
    assert!(!err.contains("FAKE-NEVER-SHOWN"), "{err}");
}

#[test]
fn github_jwt_is_rs256_with_the_apps_claims() {
    use ring::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    assert_eq!(
        github::claims("Iv23liFakeApp", 1_000_000),
        "{\"iat\":999940,\"exp\":1000540,\"iss\":\"Iv23liFakeApp\"}"
    );
    assert_eq!(
        github::claims("12345", 100),
        "{\"iat\":40,\"exp\":640,\"iss\":12345}"
    );
    let Some(pem) = rsa_key() else {
        eprintln!("no openssl here: the RS256 signature is not checked");
        return;
    };
    let key = rsa::key(&pem).unwrap();
    let jwt = rsa::jwt(&key, &github::claims("Iv23liFakeApp", 1_000_000)).unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(
        parts[0],
        super::encode::base64url(br#"{"alg":"RS256","typ":"JWT"}"#)
    );
    let signature = openmoat_proxy::base64(
        format!(
            "{}{}",
            parts[2].replace('-', "+").replace('_', "/"),
            "=".repeat((4 - parts[2].len() % 4) % 4)
        )
        .as_bytes(),
    )
    .unwrap();
    let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key().as_ref());
    public
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .unwrap();
    assert!(rsa::key("not a key").is_err());
}

#[test]
fn aws_keys_come_from_the_named_profile_only() {
    let ini = "[default]\naws_access_key_id = FAKEDEFAULT\naws_secret_access_key = fake/default\n\n\
               [work]\naws_access_key_id=FAKEWORK\naws_secret_access_key=fake/work\naws_session_token = fake-token\n";
    let keys = aws::keys(ini, "work").unwrap();
    assert_eq!(keys.access_key_id, "FAKEWORK");
    assert_eq!(keys.secret_access_key.as_str(), "fake/work");
    assert_eq!(
        keys.session_token.as_deref().map(String::as_str),
        Some("fake-token")
    );
    assert!(aws::keys(ini, "default").unwrap().session_token.is_none());
    let err = aws::keys(ini, "missing").err().unwrap().to_string();
    assert!(err.contains("`missing`") && !err.contains("fake/"), "{err}");
}

#[test]
fn aws_asks_sts_for_the_role_with_the_session_policy_and_lifetime() {
    let keys = aws::keys(
        "[default]\naws_access_key_id=FAKEKEYID\naws_secret_access_key=fake/secret\n",
        "default",
    )
    .unwrap();
    assert_eq!(
        aws::policy(&sts()).unwrap(),
        "{\"Statement\":[{\"Action\":[\"s3:GetObject\",\"s3:ListBucket\"],\"Effect\":\"Allow\",\
         \"Resource\":[\"arn:aws:s3:::example-bucket\",\"arn:aws:s3:::example-bucket/*\"]}],\
         \"Version\":\"2012-10-17\"}"
    );
    let request = aws::request("s3", &sts(), &keys, (now(), 900)).unwrap();
    golden("sts-assume-role.request", &aws::host("us-east-1"), &request);
    // Temporary base keys send and sign their token too.
    let mut temporary = keys;
    temporary.session_token = Some(Zeroizing::new("fake-base-token".into()));
    let request = aws::request("s3", &sts(), &temporary, (now(), 900)).unwrap();
    let sent = head("sts.us-east-1.amazonaws.com", &request);
    assert!(sent.contains("X-Amz-Security-Token: fake-base-token\r\n"));
    assert!(sent.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-security-token,"));
}

#[test]
fn aws_answers_become_credential_process_json() {
    let minted = aws::parse(&response(200, &fixture("sts-assume-role.xml"))).unwrap();
    let value: serde_json::Value = serde_json::from_str(&minted.value).unwrap();
    assert_eq!(value["Version"], 1);
    assert_eq!(value["AccessKeyId"], "FAKEACCESSKEYEXAMPLE");
    assert_eq!(
        value["SessionToken"],
        "FAKEsessionTOKENpartONEFAKEsessionTOKENpartTWO=="
    );
    assert_eq!(value["Expiration"], "2026-11-23T10:15:00Z");
    let masked: Vec<&str> = minted.masked.iter().map(|m| m.as_str()).collect();
    assert_eq!(
        masked,
        [
            "FAKE/secret+access/key/EXAMPLE",
            "FAKEsessionTOKENpartONEFAKEsessionTOKENpartTWO=="
        ]
    );
    // Asked for 20 minutes, given 15: the shorter one counts.
    assert_eq!(
        answer(minted, now(), 1200).unwrap().lifetime,
        Duration::from_mins(15)
    );
    let err = format!(
        "{:#}",
        aws::parse(&response(403, &fixture("sts-error.xml")))
            .err()
            .unwrap()
    );
    assert!(err.contains("HTTP 403: AccessDenied"), "{err}");
    assert!(!err.contains("not authorized"), "{err}");
}

#[test]
fn gcp_exchanges_the_callers_credential_then_asks_for_the_scoped_token() {
    let user = "{\"type\":\"authorized_user\",\"client_id\":\"fake-client.apps.googleusercontent.com\",\
                \"client_secret\":\"fake-client-secret\",\"refresh_token\":\"fake-refresh/token\"}";
    let request = gcp::caller_request(user, 1_000_000).unwrap();
    golden(
        "gcp-token-authorized-user.request",
        gcp::TOKEN_HOST,
        &request,
    );
    let caller = gcp::caller_token(&response(
        200,
        "{\"access_token\":\"fake-caller\",\"expires_in\":3599}",
    ))
    .unwrap();
    let request = gcp::request(&gcp_source(), 600, &caller);
    golden("gcp-generate-access-token.request", gcp::IAM_HOST, &request);
    let minted = gcp::parse(&response(200, &fixture("gcp-generate-access-token.json"))).unwrap();
    assert_eq!(minted.value.as_str(), "FAKE-GCP-ACCESS-TOKEN-0123456789");
    assert_eq!(
        answer(minted, now(), 600).unwrap().lifetime,
        Duration::from_mins(10)
    );
    let err = format!(
        "{:#}",
        gcp::parse(&response(403, &fixture("gcp-error.json")))
            .err()
            .unwrap()
    );
    assert!(err.contains("HTTP 403: PERMISSION_DENIED"), "{err}");
    let err = gcp::caller_request("{\"type\":\"external_account\"}", 0)
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("neither"), "{err}");
}

#[test]
fn gcp_service_account_keys_sign_a_jwt_bearer_assertion() {
    let Some(pem) = rsa_key() else {
        eprintln!("no openssl here: the service account assertion is not checked");
        return;
    };
    let file = serde_json::json!({
        "type": "service_account",
        "client_email": "caller@demo.iam.gserviceaccount.com",
        "private_key": pem,
        "token_uri": "https://evil.example/token",
    })
    .to_string();
    let request = gcp::caller_request(&file, 1_000_000).unwrap();
    let body = String::from_utf8(request.body.to_vec()).unwrap();
    assert!(body.starts_with(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
    ));
    // The file's `token_uri` is not followed: the request goes to Google's endpoint.
    assert_eq!(request.path, "/token");
}

#[test]
fn an_answer_that_is_already_ending_is_refused() {
    let minted = |left_ms: i64| Minted {
        value: Zeroizing::new("fake".into()),
        expires_ms: now() + left_ms,
        masked: Vec::new(),
    };
    let err = answer(minted(5_000), now(), 900).err().unwrap().to_string();
    assert!(err.contains("expires in 5s"), "{err}");
    assert!(answer(minted(-60_000), now(), 900).is_err());
    assert_eq!(
        answer(minted(120_000), now(), 900).unwrap().lifetime,
        Duration::from_mins(2)
    );
}

/// Answers each request from a queue and keeps what was sent.
struct Recorded {
    answers: Mutex<Vec<(String, Response)>>,
    sent: Mutex<Vec<String>>,
}

impl Transport for Recorded {
    fn send(&self, host: &str, request: &Request) -> anyhow::Result<Response> {
        self.sent
            .lock()
            .unwrap()
            .push(format!("{host} {}", request.path));
        let (expected, answer) = self.answers.lock().unwrap().remove(0);
        assert_eq!(expected, host);
        Ok(answer)
    }
}

#[test]
fn a_minter_reads_the_persons_credential_and_answers_with_a_deadline() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".aws")).unwrap();
    std::fs::write(
        home.path().join(".aws/credentials"),
        "[default]\naws_access_key_id=FAKEKEYID\naws_secret_access_key=fake/secret\n",
    )
    .unwrap();
    let transport = Recorded {
        answers: Mutex::new(vec![(
            "sts.us-east-1.amazonaws.com".into(),
            response(200, &fixture("sts-assume-role.xml")),
        )]),
        sent: Mutex::new(Vec::new()),
    };
    let home_text = home.path().to_string_lossy().replace('\\', "/");
    let minter = Minter::prepare("s3", &MintSource::AwsSts(sts()), &home_text)
        .with(Box::new(transport), now);
    assert_eq!(minter.id(), "s3");
    assert_eq!(minter.refresh_before(), Duration::from_mins(3));
    let answered = minter.fetch().unwrap();
    assert_eq!(answered.lifetime, Duration::from_mins(15));
    assert!(answered.value.contains("FAKEACCESSKEYEXAMPLE"));
    // A missing credentials file names the file, never a value.
    let empty = tempfile::tempdir().unwrap();
    let missing = Minter::prepare(
        "s3",
        &MintSource::AwsSts(sts()),
        &empty.path().to_string_lossy(),
    );
    let err = format!("{:#}", missing.fetch().err().unwrap());
    assert!(err.contains("~/.aws/credentials"), "{err}");
}
