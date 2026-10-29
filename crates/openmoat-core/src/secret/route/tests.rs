use super::{PathRefusal, RequestPath, Route};

fn path(target: &str) -> RequestPath {
    RequestPath::parse(target).unwrap_or_else(|e| panic!("{target}: {e}"))
}

fn allows(rule: &str, method: &str, target: &str) -> bool {
    Route::parse(rule).unwrap().matches(method, &path(target))
}

#[test]
fn a_rule_is_a_method_and_a_path_of_segments() {
    for good in [
        "GET /repos/**",
        "POST /repos/*/*/issues",
        "GET /",
        "GET /a/",
        "DELETE /x/**/y",
        "GET /user:me/@x",
    ] {
        assert!(Route::parse(good).is_ok(), "{good}");
    }
    for (bad, want) in [
        ("GET", "METHOD /path"),
        ("get /x", "capital letters"),
        ("G-T /x", "capital letters"),
        ("GET x", "start with `/`"),
        ("TRACE /", "never given a secret"),
        ("TRACK /x", "never given a secret"),
        ("CONNECT /", "never given a secret"),
        ("GET  /x", "start with `/`"),
        ("GET /a//b", "empty segment"),
        ("GET /a/../b", "`.` and `..`"),
        ("GET /a/./b", "`.` and `..`"),
        ("GET /a%2fb", "a segment is"),
        ("GET /a*", "a segment is"),
        ("GET /a;b", "a segment is"),
        ("GET /a?b", "a segment is"),
        ("GET /a b", "a segment is"),
        ("GET /a\\b", "a segment is"),
    ] {
        let got = Route::parse(bad).unwrap_err();
        assert!(got.contains(want), "{bad}: {got}");
    }
    let long = format!("GET {}", "/a".repeat(65));
    assert!(Route::parse(&long).unwrap_err().contains("more than 64"));
}

#[test]
fn star_is_one_segment_and_double_star_any_number() {
    assert!(allows("GET /repos/**", "GET", "/repos"));
    assert!(allows("GET /repos/**", "GET", "/repos/o/r/issues/1"));
    assert!(allows("GET /repos/**", "GET", "/repos/o/r?per_page=1"));
    assert!(!allows("GET /repos/**", "GET", "/user/keys"));
    assert!(!allows("GET /repos/**", "GET", "/reposx"));
    assert!(allows(
        "POST /repos/*/*/issues",
        "POST",
        "/repos/o/r/issues"
    ));
    assert!(!allows("POST /repos/*/*/issues", "POST", "/repos/o/issues"));
    assert!(!allows(
        "POST /repos/*/*/issues",
        "POST",
        "/repos/o/r/x/issues"
    ));
    assert!(!allows(
        "POST /repos/*/*/issues",
        "POST",
        "/repos/o/r/issues/1"
    ));
    // A trailing slash is a segment of its own: only `**` or a rule with one takes it.
    assert!(!allows(
        "POST /repos/*/*/issues",
        "POST",
        "/repos/o/r/issues/"
    ));
    assert!(allows("GET /a/", "GET", "/a/"));
    assert!(!allows("GET /a/*", "GET", "/a/"));
    assert!(allows("DELETE /x/**/y", "DELETE", "/x/y"));
    assert!(allows("DELETE /x/**/y", "DELETE", "/x/1/2/y"));
    assert!(!allows("DELETE /x/**/y", "DELETE", "/x/1/2/z"));
    assert!(allows("GET /", "GET", "/"));
    assert!(!allows("GET /", "GET", "/a"));
}

#[test]
fn the_method_and_literals_are_compared_exactly() {
    assert!(!allows("GET /repos/**", "POST", "/repos/o"));
    assert!(!allows("GET /repos/**", "get", "/repos/o"));
    assert!(!allows("GET /repos/**", "HEAD", "/repos/o"));
    assert!(!allows("GET /repos/**", "GET", "/REPOS/o"));
    // Decoded once, as the server reads it.
    assert!(allows("GET /repos/**", "GET", "/%72epos/o"));
    assert!(allows("GET /repos/*/x", "GET", "/repos/a%20b/x"));
    assert!(allows("GET /repos/*", "GET", "/repos/%C3%A9"));
}

#[test]
fn a_path_the_server_could_read_as_another_is_refused() {
    for (target, why) in [
        ("https://evil.test/repos/x", PathRefusal::NotOriginForm),
        ("*", PathRefusal::NotOriginForm),
        ("", PathRefusal::NotOriginForm),
        ("repos/x", PathRefusal::NotOriginForm),
        ("/repos/../user/keys", PathRefusal::DotSegment),
        ("/repos/./x", PathRefusal::DotSegment),
        ("/repos/..", PathRefusal::DotSegment),
        ("/repos/%2e%2e/user", PathRefusal::DotSegment),
        ("/repos/%2E%2E/user", PathRefusal::DotSegment),
        ("/repos/.%2e/user", PathRefusal::DotSegment),
        ("/repos/%2e/user", PathRefusal::DotSegment),
        ("/repos/x%2f..%2fuser", PathRefusal::AmbiguousSegment),
        ("/repos/x%2F..", PathRefusal::AmbiguousSegment),
        ("/repos/x%5c..%5cuser", PathRefusal::AmbiguousSegment),
        ("/repos/%252e%252e/user", PathRefusal::AmbiguousSegment),
        ("/repos/..;/user", PathRefusal::AmbiguousSegment),
        ("/repos/x;jsessionid=1", PathRefusal::AmbiguousSegment),
        ("/repos/x%3b/user", PathRefusal::AmbiguousSegment),
        ("/repos/%00", PathRefusal::AmbiguousSegment),
        ("/repos/%0a", PathRefusal::AmbiguousSegment),
        ("/repos/%ff", PathRefusal::AmbiguousSegment),
        ("/repos//user", PathRefusal::EmptySegment),
        ("//user", PathRefusal::EmptySegment),
        ("/repos\\..\\user", PathRefusal::Malformed),
        ("/repos/x#frag", PathRefusal::Malformed),
        ("/repos/x y", PathRefusal::Malformed),
        ("/repos/\u{e9}", PathRefusal::Malformed),
        ("/repos/%zz", PathRefusal::Malformed),
        ("/repos/%+1", PathRefusal::Malformed),
        ("/repos/%2", PathRefusal::Malformed),
    ] {
        assert_eq!(RequestPath::parse(target), Err(why.clone()), "{target}");
        assert!(!why.to_string().is_empty());
    }
}

#[test]
fn a_method_override_in_the_query_is_seen() {
    for target in [
        "/repos/o?_method=DELETE",
        "/repos/o?a=1&_METHOD=DELETE",
        "/repos/o?%5Fmethod=DELETE",
        "/repos/o?_method",
        "/repos/o?%zz=1",
    ] {
        assert!(path(target).overrides_method(), "{target}");
    }
    for target in [
        "/repos/o",
        "/repos/o?method=x",
        "/repos/o?x=_method",
        "/repos/o?",
    ] {
        assert!(!path(target).overrides_method(), "{target}");
    }
}
