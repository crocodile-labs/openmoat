use super::*;
use crate::Policy;

const HOST: &str = "api.github.com";

fn entry(id: &str, allow: &[&str], deny: &[&str]) -> RequestEntry {
    RequestEntry {
        id: id.to_owned(),
        host: HOST.to_owned(),
        allow: allow.iter().map(|s| (*s).to_owned()).collect(),
        deny: deny.iter().map(|s| (*s).to_owned()).collect(),
        hook_only: false,
    }
}

fn gists() -> RequestRules {
    RequestRules::for_hook(&[entry("gists", &[], &["POST /gists", "PATCH /gists/**"])]).unwrap()
}

fn refused(rules: &RequestRules, method: &str, target: &str) -> bool {
    matches!(
        rules.check(HOST, method, target, &[]),
        RequestCheck::Refused(_)
    )
}

#[test]
fn deny_matches_every_letter_case_and_spelling_the_server_reads_alike() {
    let r = gists();
    for (method, target) in [
        ("POST", "/gists"),
        ("post", "/gists"),
        ("Post", "/GISTS"),
        ("POST", "/Gists?per_page=1"),
        ("POST", "/gists/"),
        ("PATCH", "/gists/abc"),
        ("PATCH", "/gists/abc/comments/1"),
        ("POST", "/%67ists"),
    ] {
        assert!(refused(&r, method, target), "{method} {target}");
    }
    for (method, target) in [
        ("GET", "/gists"),
        ("POST", "/repos/o/r/issues"),
        ("GET", "/"),
    ] {
        assert!(!refused(&r, method, target), "{method} {target}");
    }
    assert_eq!(
        r.check("example.com", "POST", "/gists", &[]),
        RequestCheck::Unlisted
    );
}

#[test]
fn a_path_read_as_another_or_another_method_asked_for_is_refused() {
    let r = gists();
    for target in [
        "/gists/..",
        "/a%2fgists",
        "/a/../gists",
        "//gists",
        "/gists;x",
        "/x%252f",
    ] {
        assert!(refused(&r, "GET", target), "{target}");
    }
    assert!(refused(&r, "GET", "/x?_method=POST"));
    assert!(matches!(
        r.check(HOST, "GET", "/x", &["X-HTTP-Method-Override"]),
        RequestCheck::Refused(_)
    ));
}

#[test]
fn an_allow_list_refuses_what_it_does_not_name_and_matches_as_written() {
    let r = RequestRules::for_hook(&[entry("api", &["GET /**", "POST /repos/*/*/issues"], &[])])
        .unwrap();
    assert!(!refused(&r, "GET", "/user"));
    assert!(!refused(&r, "POST", "/repos/o/r/issues"));
    assert!(refused(&r, "POST", "/gists"));
    // Written in capitals, the allow list errs closed on another spelling.
    assert!(refused(&r, "post", "/repos/o/r/issues"));
    assert!(refused(&r, "POST", "/REPOS/o/r/issues"));
}

#[test]
fn deny_wins_over_an_allow_of_any_entry() {
    let r = RequestRules::for_hook(&[
        entry("wide", &["POST /**"], &[]),
        entry("gists", &[], &["POST /gists"]),
    ])
    .unwrap();
    assert!(refused(&r, "POST", "/gists"));
    assert!(!refused(&r, "POST", "/user/repos"));
}

#[test]
fn a_request_known_in_part_could_be_refused_where_a_rule_may_match() {
    let r = gists();
    let known = |s: &str| Partial::Known(s.to_owned());
    assert!(r.could_refuse(Some(HOST), Some("POST"), None).is_some());
    assert!(
        r.could_refuse(Some(HOST), None, Some(&[known("gists")]))
            .is_some()
    );
    assert!(
        r.could_refuse(Some(HOST), Some("POST"), Some(&[Partial::Rest]))
            .is_some()
    );
    assert!(
        r.could_refuse(None, Some("patch"), Some(&[known("Gists"), Partial::One]))
            .is_some()
    );
    // No rule names these, whatever the unknown parts hold.
    assert!(r.could_refuse(Some(HOST), Some("GET"), None).is_none());
    let issues = [known("repos"), Partial::One, Partial::One, known("issues")];
    assert!(
        r.could_refuse(Some(HOST), Some("POST"), Some(&issues))
            .is_none()
    );
    let allow = RequestRules::for_hook(&[entry("api", &["GET /**"], &[])]).unwrap();
    assert!(allow.could_refuse(Some(HOST), Some("GET"), None).is_some());
}

#[test]
fn proxy_rules_leave_out_hook_only_entries() {
    let mut hook_only = entry("hook", &[], &["POST /gists"]);
    hook_only.hook_only = true;
    let entries = [hook_only, entry("both", &[], &["PATCH /gists/**"])];
    assert_eq!(RequestRules::for_hook(&entries).unwrap().entries.len(), 2);
    let proxy = RequestRules::for_proxy(&entries).unwrap();
    assert_eq!(proxy.entries.len(), 1);
    assert_eq!(proxy.hosts(), [HOST]);
}

fn policy_error(requests: &str) -> String {
    let yaml =
        format!("version: 1\nallow:\n  - id: gh\n    net: [api.github.com]\nrequests:\n{requests}");
    Policy::parse(&yaml).unwrap_err().to_string()
}

#[test]
fn the_schema_refuses_what_a_certificate_or_the_matcher_cannot_hold() {
    for (requests, want) in [
        (
            "  - id: x\n    host: '*.github.com'\n    deny: ['POST /gists']\n",
            "one lowercase DNS name",
        ),
        (
            "  - id: x\n    host: 140.82.112.6\n    deny: ['POST /gists']\n",
            "one lowercase DNS name",
        ),
        (
            "  - id: x\n    host: api.github.com:443\n    deny: ['POST /x']\n",
            "one lowercase DNS name",
        ),
        (
            "  - id: x\n    host: API.github.com\n    deny: ['POST /x']\n",
            "one lowercase DNS name",
        ),
        ("  - id: x\n    host: api.github.com\n", "lists no"),
        (
            "  - id: x\n    host: api.github.com\n    deny: ['TRACE /']\n",
            "TRACE",
        ),
        (
            "  - id: x\n    host: api.github.com\n    deny: ['post /x']\n",
            "capital letters",
        ),
        (
            "  - id: X\n    host: api.github.com\n    deny: ['POST /x']\n",
            "id must be",
        ),
        (
            "  - id: x\n    host: api.github.com\n    deny: ['POST /x']\n    ask: []\n",
            "unknown field",
        ),
        (
            "  - id: x\n    host: api.github.com\n    deny: ['POST /x']\n  - id: x\n    host: \
             api.github.com\n    deny: ['POST /y']\n",
            "requests.x",
        ),
    ] {
        let got = policy_error(requests);
        assert!(got.contains(want), "{requests}: {got}");
    }
    let many = (0..65)
        .map(|n| format!("'POST /x{n}'"))
        .collect::<Vec<_>>()
        .join(", ");
    let got = policy_error(&format!(
        "  - id: x\n    host: api.github.com\n    deny: [{many}]\n"
    ));
    assert!(got.contains("more than 64"), "{got}");
}

#[test]
fn requests_untrusted_is_refuse_unless_the_policy_says_relay() {
    let base = "version: 1\n";
    assert_eq!(
        Policy::parse(base).unwrap().requests_untrusted(),
        Untrusted::Refuse
    );
    let relay = Policy::parse(&format!("{base}requests_untrusted: relay\n")).unwrap();
    assert_eq!(relay.requests_untrusted(), Untrusted::Relay);
    assert!(Policy::parse(&format!("{base}requests_untrusted: maybe\n")).is_err());
}

#[test]
fn lint_says_when_no_allow_rule_reaches_the_host_and_what_the_proxy_needs() {
    let yaml =
        "version: 1\nrequests:\n  - id: x\n    host: api.github.com\n    deny: ['POST /x']\n";
    let warnings: Vec<String> = crate::lint::warnings(&Policy::parse(yaml).unwrap())
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("no net or fetch allow rule")),
        "{warnings:?}"
    );
    assert!(
        warnings.iter().any(|w| w.contains("proxy CA")),
        "{warnings:?}"
    );
    let hook = "version: 1\nallow:\n  - id: gh\n    net: [api.github.com]\nrequests:\n  - id: x\n    \
        host: api.github.com\n    hook_only: true\n    deny: ['POST /x']\n";
    assert!(
        crate::lint::warnings(&Policy::parse(hook).unwrap())
            .iter()
            .all(|w| !w.to_string().contains("requests.x"))
    );
}

/// The shipped `exfil-endpoints` pack is a pack (a repository policy's
/// shape). Its rules are the hook's unless the person's own policy has the
/// proxy hold api.github.com; then the proxy holds them too.
#[test]
fn the_exfil_endpoints_pack_reaches_the_proxy_only_where_the_person_opts_in() {
    let pack = crate::RepoPolicy::parse(include_str!("../../policies/packs/exfil-endpoints.yaml"))
        .unwrap();
    let default = Policy::parse(crate::DEFAULT_POLICY).unwrap();
    assert!(
        pack.requests
            .iter()
            .all(|e| !e.hook_only && e.allow.is_empty())
    );
    for hook in default.requests.iter().filter(|e| e.hook_only) {
        assert!(
            pack.requests
                .iter()
                .any(|e| e.host == hook.host && hook.deny.iter().all(|d| e.deny.contains(d))),
            "{}",
            hook.id
        );
    }
    // The default policy holds api.github.com in the hook only: so does the pack.
    let mut merged = default.clone();
    pack.add_requests(&mut merged, "pack:exfil-endpoints:");
    merged.lint_structure().unwrap();
    assert!(
        RequestRules::for_proxy(&merged.requests)
            .unwrap()
            .is_empty()
    );
    // The person opts in: an entry of their own the proxy holds.
    let mut opted = default.clone();
    opted
        .requests
        .push(entry("github-api", &["GET /**", "POST /**"], &[]));
    pack.add_requests(&mut opted, "pack:exfil-endpoints:");
    opted.lint_structure().unwrap();
    let proxy = RequestRules::for_proxy(&opted.requests).unwrap();
    assert!(matches!(
        proxy.check(HOST, "POST", "/gists", &[]),
        RequestCheck::Refused(_)
    ));
}

/// A repository's entry for a host the person's own policy does not have
/// the proxy hold is the hook's alone, so a repository cannot make the
/// proxy terminate (and without a CA refuse) a host git and package
/// managers use.
#[test]
fn a_repository_entry_is_hook_only_unless_the_person_has_the_proxy_hold_the_host() {
    let repo =
        "version: 1\nrequests:\n  - id: x\n    host: registry.npmjs.org\n    deny: ['PUT /**']\n";
    let user = Policy::parse("version: 1\n").unwrap();
    let merged = crate::RepoPolicy::parse(repo)
        .unwrap()
        .merge(&user, true)
        .unwrap();
    assert!(merged.requests[0].hook_only);
    let held = "version: 1\nrequests:\n  - id: npm\n    host: registry.npmjs.org\n    allow: ['GET /**']\n";
    let user = Policy::parse(held).unwrap();
    let merged = crate::RepoPolicy::parse(repo)
        .unwrap()
        .merge_deny(&user)
        .unwrap();
    assert!(!merged.requests[1].hook_only);
}

#[test]
fn a_repository_policy_adds_deny_lists_only() {
    let user = Policy::parse("version: 1\n").unwrap();
    let deny =
        "version: 1\nrequests:\n  - id: x\n    host: api.github.com\n    deny: ['POST /x']\n";
    let merged = crate::RepoPolicy::parse(deny)
        .unwrap()
        .merge(&user, false)
        .unwrap();
    assert_eq!(merged.requests.len(), 1);
    assert_eq!(merged.requests[0].id, "repo:x");
    let denies = crate::RepoPolicy::parse(deny)
        .unwrap()
        .merge_deny(&user)
        .unwrap();
    assert_eq!(denies.requests[0].id, "repo:x");
    let allow =
        "version: 1\nrequests:\n  - id: x\n    host: api.github.com\n    allow: ['GET /**']\n";
    let got = crate::RepoPolicy::parse(allow).unwrap_err().to_string();
    assert!(got.contains("`deny` request rules only"), "{got}");
    let untrusted = "version: 1\nrequests_untrusted: relay\n";
    assert!(crate::RepoPolicy::parse(untrusted).is_err());
}
