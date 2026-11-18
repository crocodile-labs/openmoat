use super::Requests;
use openmoat_core::rule_id::REQUEST_RULE;

const HOST: &str = "api.github.com";

fn gists() -> Requests {
    Requests::default()
        .deny(HOST, &["POST /gists", "POST /gists/**"])
        .unwrap()
}

fn head(line: &str, extra: &str) -> Vec<u8> {
    format!("{line} HTTP/1.1\r\nHost: {HOST}\r\n{extra}Connection: close\r\n\r\n").into_bytes()
}

fn refused(r: &Requests, line: &str, extra: &str) -> String {
    let d = r.check(HOST, &head(line, extra)).unwrap_err();
    assert_eq!(d.rules, [REQUEST_RULE], "{line}");
    d.reasons.join("; ")
}

#[test]
fn a_denied_route_is_refused_in_every_spelling_and_names_no_path() {
    let r = gists();
    for line in [
        "POST /gists",
        "POST /gists/",
        "POST /gists?per_page=1",
        "POST /GISTS",
        "POST /Gists/",
        "post /gists",
        "Post /gists",
        "POST /gists/abc123/comments",
        "POST /gists/abc123/forks",
        "POST /%67ists",
        // folded after decoding: `%47` is `G`
        "POST /%47ists",
        "POST /%47ISTS/",
    ] {
        let why = refused(&r, line, "");
        assert!(why.contains("request rule"), "{line}: {why}");
        assert!(
            !why.contains("abc123") && !why.contains("per_page"),
            "{why}"
        );
    }
}

#[test]
fn a_path_the_server_could_read_as_another_or_a_method_override_is_refused() {
    let r = gists();
    for (line, extra) in [
        ("POST /x/../gists", ""),
        ("POST /x/%2e%2e/gists", ""),
        ("POST /gists%2f", ""),
        ("POST /gists;x", ""),
        ("POST //gists", ""),
        ("GET /gists?_method=POST", ""),
        ("GET /gists", "X-HTTP-Method-Override: POST\r\n"),
    ] {
        refused(&r, line, extra);
    }
}

#[test]
fn everything_else_to_the_host_passes() {
    let r = gists();
    for line in [
        "GET /gists",
        "GET /gists/abc",
        "PATCH /gists/abc",
        "GET /zen",
        "POST /repos/o/r/issues",
        "POST /gistsx",
        "HEAD /",
    ] {
        let why = r.check(HOST, &head(line, "")).unwrap();
        assert!(why.is_some_and(|w| w.contains("no request rule")), "{line}");
    }
    assert!(r.names("API.GitHub.com"));
}

#[test]
fn another_host_is_not_checked() {
    let r = gists();
    assert!(!r.names("github.com"));
    assert_eq!(r.check("github.com", &head("POST /gists", "")), Ok(None));
    assert!(!Requests::default().names(HOST));
}

#[test]
fn an_unreadable_head_is_refused() {
    let d = gists().check(HOST, b"POST /gists").unwrap_err();
    assert_eq!(d.rules, [REQUEST_RULE]);
}

#[test]
fn bad_rules_and_hosts_are_refused() {
    for (host, rule) in [
        (HOST, "post /gists"),
        (HOST, "POST gists"),
        (HOST, "TRACE /"),
        ("*.github.com", "POST /gists"),
        ("", "POST /gists"),
        ("api.github.com:443", "POST /gists"),
    ] {
        assert!(
            Requests::default().deny(host, &[rule]).is_err(),
            "{host} {rule}"
        );
    }
    assert!(
        Requests::default()
            .deny("API.github.com", &["POST /gists"])
            .is_err()
    );
    let hosts = Requests::default()
        .deny(HOST, &["POST /Gists"])
        .unwrap()
        .deny(HOST, &["PATCH /gists/**"])
        .unwrap()
        .hosts();
    assert_eq!(hosts, [HOST]);
}

#[test]
fn hook_only_entries_are_left_to_the_hook() {
    let entry = |hook_only| openmoat_core::RequestEntry {
        id: "gists".to_owned(),
        host: HOST.to_owned(),
        allow: Vec::new(),
        deny: vec!["POST /gists".to_owned()],
        hook_only,
    };
    let untrusted = openmoat_core::RequestsUntrusted::Refuse;
    assert!(
        !Requests::new(&[entry(true)], untrusted)
            .unwrap()
            .names(HOST)
    );
    assert!(
        Requests::new(&[entry(false)], untrusted)
            .unwrap()
            .names(HOST)
    );
}

#[test]
fn an_allow_list_refuses_what_it_does_not_name() {
    let entry = openmoat_core::RequestEntry {
        id: "api".to_owned(),
        host: HOST.to_owned(),
        allow: vec!["GET /**".to_owned()],
        deny: vec!["GET /gists".to_owned()],
        hook_only: false,
    };
    let r = Requests::new(&[entry], openmoat_core::RequestsUntrusted::Refuse).unwrap();
    assert!(
        r.check(HOST, &head("GET /repos/o/r", ""))
            .unwrap()
            .is_some()
    );
    refused(&r, "GET /gists", "");
    refused(&r, "POST /repos/o/r/issues", "");
}

#[test]
fn a_connection_that_cannot_be_terminated_is_refused_or_relayed() {
    let refuse = Requests::default();
    let d = refuse.untrusted(HOST, "the session has no CA").unwrap_err();
    assert_eq!(d.rules, [REQUEST_RULE]);
    let relay = Requests::new(&[], openmoat_core::RequestsUntrusted::Relay).unwrap();
    assert!(
        relay
            .untrusted(HOST, "x")
            .unwrap()
            .contains("relayed unread")
    );
}
