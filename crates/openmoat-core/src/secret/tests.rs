use crate::policy::{Policy, PolicyError};

use super::Source;

fn parse(secrets: &str) -> Result<Policy, PolicyError> {
    Policy::parse(&format!("version: 1\nsecrets:\n{secrets}"))
}

fn problem(secrets: &str) -> String {
    parse(secrets).unwrap_err().to_string()
}

const GH: &str = "  - id: gh\n    host: api.github.com\n    header: Authorization\n";

#[test]
fn parses_every_source() {
    let p = parse(&format!(
        "{GH}    source: {{ env: GITHUB_TOKEN }}\n  \
         - id: npm\n    host: registry.npmjs.org\n    header: Authorization\n    \
         source: {{ file: ~/.config/moat/npm }}\n  \
         - id: k\n    host: example.com\n    header: X-Api-Key\n    \
         source: {{ keychain: {{ service: moat, account: k }} }}\n"
    ))
    .unwrap();
    assert_eq!(p.secrets.len(), 3);
    assert_eq!(p.secrets[0].source, Source::Env("GITHUB_TOKEN".into()));
    assert_eq!(
        p.secrets[1].source,
        Source::File("~/.config/moat/npm".into())
    );
    assert!(matches!(&p.secrets[2].source, Source::Keychain { service, .. } if service == "moat"));
    assert_eq!(p.secrets[0].placeholder(), "moat-secret:gh:placeholder");
    assert!(Policy::parse("version: 1\n").unwrap().secrets.is_empty());
}

#[test]
fn debug_output_names_only_the_id() {
    let policy = parse(&format!("{GH}    source: {{ file: ~/.config/moat/gh }}\n")).unwrap();
    let secret = &policy.secrets[0];
    let brokered = crate::ir::BrokeredSecret {
        id: secret.id.clone(),
        host: secret.host.clone(),
        header: secret.header.clone(),
        source: secret.source.clone(),
        plain_http: false,
        port: None,
        tls_terminate: false,
        allow: Vec::new(),
    };
    for shown in [format!("{policy:?}"), format!("{brokered:?}")] {
        assert!(shown.contains("\"gh\""), "{shown}");
        for hidden in ["~/.config/moat/gh", "api.github.com", "Authorization"] {
            assert!(!shown.contains(hidden), "{hidden} in {shown}");
        }
    }
}

#[test]
fn plain_http_is_off_unless_set() {
    let off = parse(&format!("{GH}    source: {{ env: T }}\n")).unwrap();
    assert!(!off.secrets[0].plain_http);
    let on = parse(&format!(
        "{GH}    source: {{ env: T }}\n    plain_http: true\n"
    ))
    .unwrap();
    assert!(on.secrets[0].plain_http);
    assert!(!on.secrets[0].is_loopback());
    for (host, loopback) in [
        ("localhost", true),
        ("api.localhost", true),
        ("127.0.0.2", true),
        ("10.0.0.1", false),
        ("localhost.example", false),
    ] {
        let mut s = on.secrets[0].clone();
        s.host = host.into();
        assert_eq!(s.is_loopback(), loopback, "{host}");
    }
}

#[test]
fn a_plain_http_secret_goes_to_port_80_unless_it_names_one() {
    let plain = format!("{GH}    source: {{ env: T }}\n    plain_http: true\n");
    assert_eq!(parse(&plain).unwrap().secrets[0].plain_http_port(), 80);
    let on = parse(&format!("{plain}    port: 8080\n")).unwrap();
    assert_eq!(on.secrets[0].port, Some(8080));
    assert_eq!(on.secrets[0].plain_http_port(), 8080);
    assert!(problem(&format!("{plain}    port: 0\n")).contains("1 to 65535"));
    for bad in ["65536", "-1", "80.5", "http", "[80, 81]"] {
        assert!(
            parse(&format!("{plain}    port: {bad}\n")).is_err(),
            "{bad}"
        );
    }
    let without = format!("{GH}    source: {{ env: T }}\n    port: 8080\n");
    assert!(problem(&without).contains("needs `plain_http: true`"));
}

#[test]
fn rejects_bad_fields() {
    let src = "    source: { env: T }\n";
    for (yaml, want) in [
        (format!("  - id: Gh\n    host: a.com\n    header: A\n{src}"), "id must be"),
        (format!("  - id: g:h\n    host: a.com\n    header: A\n{src}"), "id must be"),
        (format!("  - id: g\n    host: '*.a.com'\n    header: A\n{src}"), "host `*.a.com`"),
        (format!("  - id: g\n    host: A.com\n    header: A\n{src}"), "host `A.com`"),
        (format!("  - id: g\n    host: a.com:443\n    header: A\n{src}"), "host `a.com:443`"),
        (format!("  - id: g\n    host: a.com\n    header: 'A B'\n{src}"), "not an HTTP header"),
        (format!("  - id: g\n    host: a.com\n    header: Host\n{src}"), "frames the request"),
        (format!("  - id: g\n    host: a.com\n    header: content-length\n{src}"), "frames"),
        ("  - id: g\n    host: a.com\n    header: A\n    source: { file: rel/t }\n".into(), "absolute"),
        ("  - id: g\n    host: a.com\n    header: A\n    source: { env: 'A-B' }\n".into(), "variable name"),
        (
            "  - id: g\n    host: a.com\n    header: A\n    source: { keychain: { service: '', account: a } }\n".into(),
            "keychain",
        ),
    ] {
        let got = problem(&yaml);
        assert!(got.contains(want), "{yaml}: {got}");
    }
    assert!(parse(&format!("{GH}    source: {{ vault: x }}\n")).is_err());
    assert!(parse(&format!("{GH}    source: {{ env: T }}\n    extra: 1\n")).is_err());
}

#[test]
fn rejects_duplicates() {
    let two = format!("{GH}    source: {{ env: A }}\n{GH}    source: {{ env: B }}\n");
    assert!(matches!(parse(&two), Err(PolicyError::DuplicateId(id)) if id == "secrets.gh"));
    let same_header = format!(
        "{GH}    source: {{ env: A }}\n  - id: gh2\n    host: api.github.com\n    header: authorization\n    source: {{ env: B }}\n"
    );
    assert!(problem(&same_header).contains("already sets"));
}

const ROUTED: &str = "    source: { env: T }\n    tls: terminate\n    allow:\n      - GET /repos/**\n      - POST /repos/*/*/issues\n";

#[test]
fn tls_terminate_is_off_unless_set_and_names_a_dns_host() {
    let off = parse(&format!("{GH}    source: {{ env: T }}\n")).unwrap();
    assert!(!off.secrets[0].terminates());
    assert_eq!(
        off.secrets[0].permit("DELETE", "/x", &[]),
        super::Permit::Unrestricted
    );
    let on = parse(&format!(
        "{GH}    source: {{ env: T }}\n    tls: terminate\n"
    ))
    .unwrap();
    assert!(on.secrets[0].terminates());
    assert!(parse(&format!("{GH}    source: {{ env: T }}\n    tls: pass\n")).is_err());
    let ip = "  - id: g\n    host: 10.0.0.1\n    header: A\n    source: { env: T }\n    tls: terminate\n";
    assert!(problem(ip).contains("needs a DNS name"), "{}", problem(ip));
    // Written back as it was read, so `openmoat secret add` round-trips it.
    let yaml = crate::yaml::to_string(&on.secrets).unwrap();
    assert!(yaml.contains("tls: terminate"), "{yaml}");
}

#[test]
fn allow_rules_need_a_readable_request_and_valid_rules() {
    let p = parse(&format!("{GH}{ROUTED}")).unwrap();
    assert_eq!(p.secrets[0].allow.len(), 2);
    let https_only = format!("{GH}    source: {{ env: T }}\n    allow: [GET /x]\n");
    assert!(problem(&https_only).contains("need `tls: terminate` or `plain_http: true`"));
    let plain =
        format!("{GH}    source: {{ env: T }}\n    plain_http: true\n    allow: [GET /x]\n");
    assert!(parse(&plain).is_ok());
    for (rule, want) in [
        ("get /x", "capital letters"),
        ("GET /a/../b", "`..`"),
        ("GET x", "`/`"),
    ] {
        let bad =
            format!("{GH}    source: {{ env: T }}\n    tls: terminate\n    allow: ['{rule}']\n");
        let got = problem(&bad);
        assert!(
            got.contains("secrets.gh") && got.contains(want),
            "{rule}: {got}"
        );
    }
    let many = "      - GET /r\n".repeat(65);
    let too_many = format!("{GH}    source: {{ env: T }}\n    tls: terminate\n    allow:\n{many}");
    assert!(problem(&too_many).contains("more than 64"));
}

#[test]
fn permit_names_the_rule_or_why_without_the_path() {
    use super::Permit;
    let p = parse(&format!("{GH}{ROUTED}")).unwrap();
    let s = &p.secrets[0];
    assert_eq!(
        s.permit("GET", "/repos/o/r", &[]),
        Permit::Rule("GET /repos/**".into())
    );
    assert_eq!(
        s.permit("POST", "/repos/o/r/issues", &["content-type"]),
        Permit::Rule("POST /repos/*/*/issues".into())
    );
    for (method, target, headers, why) in [
        ("DELETE", "/repos/o/r", &[][..], "matches none"),
        ("POST", "/repos/o/r/pulls", &[][..], "matches none"),
        ("GET", "/user/keys", &[][..], "matches none"),
        ("GET", "/repos/../user/keys", &[][..], "`..`"),
        ("GET", "/repos/%2e%2e/user/keys", &[][..], "`..`"),
        (
            "GET",
            "https://api.github.com/repos/o",
            &[][..],
            "not a path",
        ),
        (
            "POST",
            "/repos/o/r/issues",
            &["X-HTTP-Method-Override"][..],
            "another method",
        ),
        (
            "POST",
            "/repos/o/r/issues?_method=DELETE",
            &[][..],
            "`_method`",
        ),
    ] {
        let Permit::Refused(reason) = s.permit(method, target, headers) else {
            panic!("{method} {target} was permitted");
        };
        assert!(reason.contains(why), "{method} {target}: {reason}");
        assert!(reason.contains("secret `gh`"), "{reason}");
        assert!(
            !reason.contains("user/keys") && !reason.contains("/repos/o"),
            "{reason}"
        );
    }
}
