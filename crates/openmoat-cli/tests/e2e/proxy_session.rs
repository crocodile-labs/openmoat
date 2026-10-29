//! Sessions at the standalone `openmoat proxy` (ADR-044): Claude Code's
//! `SessionStart` hook issues each session a credential in its environment
//! file, and the proxy serves only requests that carry one, as that session.
//!
//! The attacks: another local process without a credential, session A's
//! credential presented as session B, a credential replayed after it expired,
//! and a session that read a secret sending through the proxy. Nothing leaves
//! the machine: every request here is refused, or decided, before the proxy
//! would connect anywhere.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::common::{DENY, OK, Sandbox, json as json_of, stderr, stdout, text};
use crate::taint::call;

/// A session id as Claude Code makes them.
const SESSION_A: &str = "5f0c2d1e-0a4b-4c3d-9e8f-7a6b5c4d3e2f";
const SESSION_B: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";

/// An installed home with Claude Code, its sandbox sending traffic to
/// `openmoat proxy` on a free port, and a project.
fn setup() -> (Sandbox, u16, PathBuf) {
    let sb = Sandbox::installed(&[".claude"]);
    let port = sb.use_free_proxy_port();
    let project = sb.project();
    (sb, port, project)
}

fn session_start(session: &str, cwd: &Path) -> String {
    json!({
        "session_id": session, "cwd": cwd.to_string_lossy(),
        "hook_event_name": "SessionStart", "source": "startup",
        "transcript_path": "/dev/null"
    })
    .to_string()
}

/// Run the `SessionStart` hook for `session` with `env_file` as
/// `CLAUDE_ENV_FILE`.
fn start(sb: &Sandbox, session: &str, cwd: &Path, env_file: Option<&Path>) -> std::process::Output {
    let mut cmd = sb.command();
    cmd.args(["guard", "--host", "claude-code"]);
    if let Some(file) = env_file {
        cmd.env("CLAUDE_ENV_FILE", file);
    }
    crate::common::output(&mut cmd, Some(&session_start(session, cwd)))
}

/// The proxy URL the hook wrote for the session's commands.
fn issued_url(sb: &Sandbox, session: &str, cwd: &Path) -> String {
    let env_file = sb.home.join(format!("env-{session}.sh"));
    let out = start(sb, session, cwd, Some(&env_file));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    // Claude Code adds a SessionStart hook's stdout to the model's context.
    assert_eq!(stdout(&out), "", "nothing for the model");
    let lines = std::fs::read_to_string(&env_file).unwrap();
    for variable in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
    ] {
        assert!(
            lines.contains(&format!("export {variable}=http://v1.claude-code.")),
            "{lines}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&env_file).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "the environment file is the owner's only");
    }
    lines
        .lines()
        .find_map(|l| l.strip_prefix("export HTTPS_PROXY="))
        .unwrap()
        .to_owned()
}

/// `user` and `password` of a proxy URL.
fn userinfo(url: &str) -> (String, String) {
    let rest = url.strip_prefix("http://").unwrap();
    let (info, _) = rest.rsplit_once('@').unwrap();
    let (user, password) = info.split_once(':').unwrap();
    (user.to_owned(), password.to_owned())
}

fn base64(raw: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

/// 64 hex characters made at run time from freshly keyed hashers: a password
/// of the right shape that no key signed, and no fixed value in the source.
fn made_up_password() -> String {
    use std::hash::{BuildHasher as _, Hasher as _};
    (0..4).fold(String::new(), |mut out, _| {
        let random = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        let _ = write!(out, "{random:016x}");
        out
    })
}

fn authorization(user: &str, password: &str) -> String {
    format!(
        "Proxy-Authorization: Basic {}\r\n",
        base64(format!("{user}:{password}").as_bytes())
    )
}

/// Send `head` (a request line and headers, without the blank line) to the
/// proxy on `port`; its reply.
fn ask(port: u16, head: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(format!("{head}\r\n").as_bytes()).unwrap();
    let mut reply = String::new();
    let _ = s.read_to_string(&mut reply);
    reply
}

fn rows(sb: &Sandbox, session: &str) -> Vec<Value> {
    let shown = sb.moat(&["show", "--session", session, "--format", "json"]);
    json_of(&shown).as_array().cloned().unwrap_or_default()
}

fn rules(row: &Value) -> Vec<String> {
    row["rules"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r.as_str().map(str::to_owned))
        .collect()
}

/// Benign: a clean session's request is decided by the policy as before, and
/// recorded under the session.
#[test]
fn a_session_start_issues_a_credential_the_proxy_serves_as_that_session() {
    let (sb, port, project) = setup();
    let url = issued_url(&sb, SESSION_A, &project);
    assert!(url.ends_with(&format!("@127.0.0.1:{port}")), "{url}");
    let (user, password) = userinfo(&url);
    let issue = rows(&sb, SESSION_A);
    assert_eq!(rules(&issue[0]), ["proxy-credential"], "{issue:?}");
    assert_eq!(issue[0]["cwd"], project.to_string_lossy().as_ref());
    // Nothing of the password in the audit log.
    let all = text(&sb.moat(&["show", "--since", "all", "--format", "json"]));
    assert!(!all.contains(&password), "{all}");

    let _proxy = sb.start_proxy();
    let reply = ask(
        port,
        &format!(
            "GET http://evil.example/ HTTP/1.1\r\n{}",
            authorization(&user, &password)
        ),
    );
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert!(
        reply.contains("default.fetch"),
        "decided by the policy: {reply}"
    );
    let proxied: Vec<Value> = rows(&sb, SESSION_A)
        .into_iter()
        .filter(|r| r["host"] == "proxy")
        .collect();
    assert_eq!(proxied.len(), 1, "{proxied:?}");
    assert_eq!(proxied[0]["action"]["net"]["url"], "http://evil.example:80");
}

/// Attack: another local process (or a command that dropped its credential)
/// uses the proxy. Refused before its host is decided.
#[test]
fn a_request_without_a_credential_gets_407() {
    let (sb, port, _project) = setup();
    let _proxy = sb.start_proxy();
    for head in [
        "GET http://evil.example/ HTTP/1.1\r\n".to_owned(),
        "CONNECT crates.io:443 HTTP/1.1\r\nHost: crates.io:443\r\n".to_owned(),
    ] {
        let reply = ask(port, &head);
        assert!(reply.starts_with("HTTP/1.1 407"), "{reply}");
        assert!(reply.contains("Proxy-Authenticate: Basic"), "{reply}");
    }
    let shown = json_of(&sb.moat(&["show", "--since", "all", "--format", "json"]));
    let refused = shown
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["host"] == "proxy" && rules(r) == ["proxy-session"])
        .count();
    assert_eq!(refused, 2, "{shown}");
}

/// Attack: session B presents session A's password under its own name, or A's
/// name with a password of its own. Neither opens a session.
#[test]
fn a_credential_of_session_a_does_not_open_session_b() {
    let (sb, port, project) = setup();
    let (user_a, password_a) = userinfo(&issued_url(&sb, SESSION_A, &project));
    let (user_b, password_b) = userinfo(&issued_url(&sb, SESSION_B, &project));
    let _proxy = sb.start_proxy();
    for (user, password) in [
        (user_b.clone(), password_a.clone()),
        (user_a.replace(SESSION_A, SESSION_B), password_a.clone()),
        (user_a.clone(), password_b.clone()),
    ] {
        let reply = ask(
            port,
            &format!(
                "GET http://evil.example/ HTTP/1.1\r\n{}",
                authorization(&user, &password)
            ),
        );
        assert!(reply.starts_with("HTTP/1.1 407"), "{user}: {reply}");
    }
    assert!(rows(&sb, SESSION_B).iter().all(|r| r["host"] != "proxy"));
}

/// HMAC-SHA-256, for a credential the hook would not issue: one that expired.
fn hmac(key: &[u8], message: &[u8]) -> String {
    let mut block = [0u8; 64];
    block[..key.len()].copy_from_slice(key);
    let pad = |byte: u8| block.iter().map(|b| b ^ byte).collect::<Vec<u8>>();
    let inner = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(message)
        .finalize();
    let outer = Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize();
    outer.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Attack: a credential replayed after it expired, correctly signed with the
/// proxy's own key (read here as the person, which no sandboxed command may).
#[test]
fn a_credential_replayed_after_it_expired_gets_407() {
    let (sb, port, project) = setup();
    issued_url(&sb, SESSION_A, &project);
    let text_key = std::fs::read_to_string(sb.home.join(".moat/proxy.key")).unwrap();
    let key: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&text_key.trim()[i..i + 2], 16).unwrap())
        .collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let _proxy = sb.start_proxy();
    let send = |expires: u64| {
        let user = format!("v1.claude-code.{expires}.{SESSION_A}");
        let mut message = b"openmoat-proxy-session-v1\n".to_vec();
        message.extend_from_slice(user.as_bytes());
        let password = hmac(&key, &message);
        ask(
            port,
            &format!(
                "GET http://evil.example/ HTTP/1.1\r\n{}",
                authorization(&user, &password)
            ),
        )
    };
    // The same construction, still current, is served: the test signs right.
    assert!(send(now + 3600).starts_with("HTTP/1.1 403"));
    assert!(send(now - 1).starts_with("HTTP/1.1 407"));
    // Nor can one be made to last past the 24 hours a credential gets.
    assert!(send(now + 3 * 86_400).starts_with("HTTP/1.1 407"));
}

/// Attack: a session reads a secret, then a script it runs sends through the
/// proxy to an allowed host. Refused for that session; another session is not
/// affected.
#[test]
fn a_session_that_read_a_secret_cannot_send_through_the_proxy() {
    let (sb, port, project) = setup();
    // An untrusted repository policy may tighten: it makes this file a secret
    // whose read asks, and an asked read may have run.
    std::fs::create_dir_all(project.join(".moat")).unwrap();
    std::fs::write(
        project.join(".moat/policy.yaml"),
        "version: 1\nask:\n  - id: secrets-paths\n    fs.read: ['${project}/creds/**']\n",
    )
    .unwrap();
    std::fs::create_dir_all(project.join("creds")).unwrap();
    std::fs::write(project.join("creds/token"), "FAKE-TOKEN").unwrap();
    let (user_a, password_a) = userinfo(&issued_url(&sb, SESSION_A, &project));
    let (user_b, password_b) = userinfo(&issued_url(&sb, SESSION_B, &project));
    let read = json!({"file_path": project.join("creds/token").to_string_lossy()});
    let out = sb.guard("claude-code", &call(SESSION_A, &project, "Read", &read));
    assert!(stdout(&out).contains("\"ask\""), "{}", text(&out));

    let _proxy = sb.start_proxy();
    for head in [
        "GET http://crates.io/ HTTP/1.1\r\n".to_owned(),
        "CONNECT crates.io:443 HTTP/1.1\r\nHost: crates.io:443\r\n".to_owned(),
    ] {
        let reply = ask(
            port,
            &format!("{head}{}", authorization(&user_a, &password_a)),
        );
        assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
        assert!(reply.contains("session-taint"), "{reply}");
    }
    // Session B read nothing: decided by the policy alone.
    let reply = ask(
        port,
        &format!(
            "GET http://evil.example/ HTTP/1.1\r\n{}",
            authorization(&user_b, &password_b)
        ),
    );
    assert!(
        reply.contains("default.fetch") && !reply.contains("session-taint"),
        "{reply}"
    );
    assert!(
        rows(&sb, SESSION_A)
            .iter()
            .any(|r| r["host"] == "proxy" && rules(r).contains(&"session-taint".to_owned()))
    );
}

/// Without `CLAUDE_ENV_FILE` the session gets no credential, and the person
/// is told (exit 2: Claude Code shows the hook's stderr). Without
/// `sandbox.proxy_port` nothing is issued and nothing said.
#[test]
fn a_session_start_without_an_env_file_says_so_and_without_a_port_does_nothing() {
    let (sb, _port, project) = setup();
    let out = start(&sb, SESSION_A, &project, None);
    assert_eq!(out.status.code(), Some(DENY), "{}", text(&out));
    assert_eq!(stdout(&out), "");
    assert!(stderr(&out).contains("CLAUDE_ENV_FILE"), "{}", text(&out));

    let sb = Sandbox::installed(&[".claude"]);
    let project = sb.project();
    let env_file = sb.home.join("env.sh");
    let out = start(&sb, SESSION_A, &project, Some(&env_file));
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert_eq!(stdout(&out), "");
    assert!(!env_file.exists());
    assert!(!sb.home.join(".moat/proxy.key").exists());
}

/// `init` installs the `SessionStart` entry, and `doctor` and `status` say
/// what each host sandbox's traffic carries.
#[test]
fn init_installs_the_entry_and_doctor_and_status_name_each_host() {
    let sb = Sandbox::installed(&[".claude", ".codex"]);
    let settings: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.home.join(".claude/settings.json")).unwrap(),
    )
    .unwrap();
    let entry = &settings["hooks"]["SessionStart"][0];
    assert_eq!(
        entry["matcher"], "startup|resume|clear|compact",
        "{settings}"
    );
    assert_eq!(
        entry["hooks"][0]["args"],
        json!(["guard", "--host", "claude-code"]),
        "{entry}"
    );
    sb.use_free_proxy_port();
    for args in [["doctor"], ["status"]] {
        let shown = text(&sb.moat(&args));
        // No Claude Code sandbox on native Windows (#327), so no line for it.
        assert_eq!(
            shown.contains("each session's sandboxed commands send their own"),
            !cfg!(windows),
            "{shown}"
        );
        assert!(
            shown.contains("its proxy sends no session credential"),
            "{shown}"
        );
    }
    sb.serve_proxy_without_credential();
    for args in [["doctor"], ["status"]] {
        let shown = text(&sb.moat(&args));
        assert!(shown.contains("proxy_serve_without_credential"), "{shown}");
    }
}

/// `sandbox.proxy_serve_without_credential`: a request without a credential
/// is served with no session, as before ADR-044; a wrong one is still refused.
#[test]
fn serving_without_a_credential_is_the_named_fallback() {
    let (sb, port, project) = setup();
    let (user, _) = userinfo(&issued_url(&sb, SESSION_A, &project));
    sb.serve_proxy_without_credential();
    let _proxy = sb.start_proxy();
    let reply = ask(port, "GET http://evil.example/ HTTP/1.1\r\n");
    assert!(reply.contains("default.fetch"), "{reply}");
    let reply = ask(
        port,
        &format!(
            "GET http://evil.example/ HTTP/1.1\r\n{}",
            authorization(&user, &made_up_password())
        ),
    );
    assert!(reply.starts_with("HTTP/1.1 407"), "{reply}");
}
