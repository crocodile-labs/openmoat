use super::*;

fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|w| (*w).to_owned()).collect()
}

fn one(words: &[&str]) -> Seen {
    let mut seen = read(&argv(words));
    assert_eq!(seen.len(), 1, "{words:?}: {seen:?}");
    seen.remove(0)
}

fn methods(seen: &Seen) -> Vec<&str> {
    seen.methods.iter().flatten().map(String::as_str).collect()
}

#[test]
fn curl_options_set_the_method_as_curl_does() {
    for (words, want) in [
        (&["curl", "https://h.example/x"][..], "GET"),
        (&["curl", "-d", "x", "h.example/x"], "POST"),
        (&["curl", "-G", "-d", "x", "h.example/x"], "GET"),
        (&["curl", "-I", "h.example/x"], "HEAD"),
        (&["curl", "-T", "f", "h.example/x"], "PUT"),
        (
            &["curl", "-X", "DELETE", "-d", "x", "h.example/x"],
            "DELETE",
        ),
        (&["curl", "-sXpost", "h.example/x"], "post"),
        (&["curl", "--request=put", "h.example/x"], "put"),
    ] {
        assert_eq!(methods(&one(words)), [want], "{words:?}");
    }
    let config = read(&argv(&["curl", "-K", "f", "h.example/x"]));
    assert!(config.iter().all(|s| s.methods.is_none()), "{config:?}");
}

#[test]
fn a_url_is_split_into_host_and_target() {
    let seen = one(&[
        "curl",
        "-o",
        "out",
        "https://u:p@H.Example.:8443/a/b?c=1#frag",
    ]);
    assert_eq!(seen.host.as_deref(), Some("h.example"));
    assert_eq!(seen.target, Target::Known("/a/b?c=1".to_owned()));
    assert_eq!(
        one(&["curl", "h.example"]).target,
        Target::Known("/".to_owned())
    );
    // Another scheme sends no HTTP request.
    assert_eq!(read(&argv(&["curl", "ftp://h.example/x"])), []);
    // A value the option takes is not a URL.
    assert_eq!(
        read(&argv(&["curl", "-e", "https://r.example/", "h.example"])).len(),
        1
    );
}

#[test]
fn what_the_shell_makes_at_run_time_is_unknown() {
    assert_eq!(one(&["curl", "$U"]).host, None);
    assert_eq!(
        one(&["curl", "https://h.example/a/$P/b"]).target,
        Target::Partial(vec![
            Partial::Known("a".into()),
            Partial::Rest,
            Partial::Known("b".into())
        ])
    );
    assert_eq!(one(&["curl", "-X", "$M", "h.example"]).methods, None);
    assert!(matches!(
        one(&["curl", "h.example/{a,b}"]).target,
        Target::Partial(_)
    ));
    assert!(matches!(
        one(&["curl", "-g", "h.example/{a,b}"]).target,
        Target::Known(_)
    ));
}

#[test]
fn httpie_and_xh_read_method_url_and_items() {
    let seen = one(&["http", "--form", "post", "h.example/x", "a=b", "X-Y:z"]);
    assert_eq!(methods(&seen), ["POST"]);
    assert_eq!(seen.headers, ["X-Y"]);
    assert_eq!(
        methods(&one(&["xh", "h.example/x", "q==1"])),
        ["GET", "POST"]
    );
    assert_eq!(methods(&one(&["http", "-I", "h.example/x"])), ["GET"]);
    assert_eq!(one(&["http", ":3000/x"]).host.as_deref(), Some("localhost"));
    assert_eq!(
        read(&argv(&["http", "--offline", "post", "h.example", "a=b"])),
        []
    );
}

#[test]
fn gh_api_and_gist_name_their_requests() {
    let seen = one(&["gh", "api", "repos/{owner}/{repo}/issues", "-f", "title=x"]);
    assert_eq!(seen.host.as_deref(), Some("api.github.com"));
    assert_eq!(methods(&seen), ["POST"]);
    assert_eq!(
        seen.target,
        Target::Partial(vec![
            Partial::Known("repos".into()),
            Partial::One,
            Partial::One,
            Partial::Known("issues".into())
        ])
    );
    let enterprise = one(&["gh", "api", "--hostname", "git.corp.example", "user"]);
    assert_eq!(enterprise.host.as_deref(), Some("git.corp.example"));
    assert_eq!(enterprise.target, Target::Known("/api/v3/user".to_owned()));
    assert_eq!(methods(&one(&["gh", "gist", "create", "f"])), ["POST"]);
    assert_eq!(read(&argv(&["gh", "pr", "create"])), []);
    assert_eq!(read(&argv(&["gh", "gist", "clone", "abc"])), []);
}

#[test]
fn wget_reads_its_method_and_marks_urls_from_a_file_unknown() {
    assert_eq!(
        methods(&one(&["wget", "--post-data=x", "h.example"])),
        ["POST"]
    );
    assert_eq!(methods(&one(&["wget", "-O", "-", "h.example"])), ["GET"]);
    let from_file = read(&argv(&["wget", "-i", "urls"]));
    assert_eq!(from_file.len(), 1);
    assert_eq!(from_file[0].host, None);
    // Every letter of a cluster, and `--config` like `-e`.
    for words in [
        &["wget", "-qi", "urls.txt"][..],
        &["wget", "-qiurls.txt"],
        &["wget", "--config=w.rc", "h.example"],
        &["wget", "--config", "w.rc", "h.example"],
    ] {
        let seen = read(&argv(words));
        assert!(
            seen.iter().any(|s| s.host.is_none() && s.methods.is_none()),
            "{words:?}"
        );
    }
}

#[test]
fn gh_hostnames_are_read_as_gh_normalises_them() {
    for hostname in [
        "github.com",
        "GITHUB.COM",
        "api.github.com",
        "foo.github.com",
        "github.com.",
    ] {
        let seen = one(&["gh", "api", "--hostname", hostname, "gists"]);
        assert_eq!(seen.host.as_deref(), Some("api.github.com"), "{hostname}");
        assert_eq!(
            seen.target,
            Target::Known("/gists".to_owned()),
            "{hostname}"
        );
    }
    let tenant = one(&["gh", "api", "--hostname", "acme.ghe.com", "user"]);
    assert_eq!(tenant.host.as_deref(), Some("api.acme.ghe.com"));
    assert_eq!(tenant.target, Target::Known("/user".to_owned()));
    let local = one(&["gh", "api", "--hostname", "github.localhost", "user"]);
    assert_eq!(local.host.as_deref(), Some("api.github.localhost"));
}

#[test]
fn curl_options_that_hide_the_request_leave_it_unknown() {
    let unknown = |words: &[&str]| {
        read(&argv(words))
            .iter()
            .any(|s| s.host.is_none() && s.methods.is_none() && s.target == Target::Unknown)
    };
    assert!(unknown(&["curl", "-K", "gist.cfg"]));
    assert!(unknown(&["curl", "--config=-"]));
    assert!(unknown(&["curl", "-sK", "f", "h.example"]));
    let target = one(&["curl", "--request-target", "/x", "-d", "x", "h.example/y"]);
    assert_eq!(target.target, Target::Unknown);
    for words in [
        &["curl", "--connect-to", "a:443:b:443", "h.example/x"][..],
        &["curl", "--resolve", "h.example:443:1.2.3.4", "h.example/x"],
        &["curl", "-H", "host: other.example", "h.example/x"],
        &["curl", "-H", "@headers.txt", "h.example/x"],
    ] {
        let seen = one(words);
        assert_eq!(seen.host, None, "{words:?}");
        assert!(matches!(seen.target, Target::Partial(_)), "{words:?}");
    }
    assert_eq!(
        one(&["curl", "-H", "Accept: x", "h.example/x"])
            .host
            .as_deref(),
        Some("h.example")
    );
    assert_eq!(one(&["curl", "https://h%2eexample/x"]).host, None);
}

#[test]
fn inline_code_shows_where_it_sends_and_whether_it_writes() {
    let posts = one(&[
        "python3",
        "-c",
        "requests.post('https://h.example/x', data=d)",
    ]);
    assert_eq!(posts.host.as_deref(), Some("h.example"));
    assert_eq!(posts.methods, None);
    let reads = one(&[
        "node",
        "-e",
        "fetch(\"https://h.example/x\").then(r => r.text())",
    ]);
    assert_eq!(methods(&reads), ["GET"]);
    assert_eq!(read(&argv(&["python3", "-c", "print(1)"])), []);
    assert_eq!(read(&argv(&["python3", "script.py"])), []);
}

#[test]
fn a_gh_alias_that_runs_api_or_gist_is_a_request_not_known() {
    for words in [
        &["gh", "alias", "set", "mk", "gist create"][..],
        &["gh", "alias", "set", "p", "api -X POST gists"],
        &[
            "gh",
            "alias",
            "set",
            "--shell",
            "s",
            "!gh gist create \"$1\"",
        ],
        &["gh", "alias", "import", "aliases.yml"],
    ] {
        let seen = one(words);
        assert_eq!(seen.methods, None, "{words:?}");
    }
    assert_eq!(
        read(&argv(&["gh", "alias", "set", "co", "pr checkout"])),
        []
    );
    assert_eq!(read(&argv(&["gh", "alias", "list"])), []);
}
