use super::{CURL, WGET, fetchable_host, wget_follows_no_redirect, words_send_nothing};

fn argv(line: &str) -> Vec<String> {
    line.split(' ').map(str::to_owned).collect()
}

#[test]
fn requests_that_send_nothing() {
    for line in [
        "curl -q https://docs.rs/serde",
        "curl --disable https://docs.rs/serde",
        "curl -q -sS https://example.com/f.txt -o out.txt",
        "curl -q -sSo out.txt https://example.com/f.txt",
        "curl -q -X GET -fsS https://example.com/api",
        "curl -q --request=HEAD https://example.com",
        "curl -q -O https://example.com/a.tar.gz",
        "curl -q --output-dir dl -o a.tgz https://example.com/a.tgz",
        "curl -q -- https://example.com",
    ] {
        assert!(words_send_nothing(&argv(line), &CURL), "{line}");
    }
    for line in [
        "wget --no-config --no-netrc https://x.test/a.tar.gz",
        "wget --no-config --no-netrc -qO- https://x.test/a",
        "wget --no-config --no-netrc -nv --tries=3 -P dl https://x.test/a",
        "wget --no-netrc --no-config -qnv https://x.test/",
    ] {
        assert!(words_send_nothing(&argv(line), &WGET), "{line}");
    }
}

#[test]
fn config_files_keep_the_command_net() {
    // curl reads `.curlrc` unless `-q` comes first; wget its rc files and `.netrc`
    for line in [
        "curl https://docs.rs/serde",
        "curl -sS -q https://docs.rs/serde",
        "curl -qsS https://docs.rs/serde",
        "curl -q -n https://docs.rs/serde",
        "curl -q --netrc https://docs.rs/serde",
        "curl -q --netrc-optional https://docs.rs/serde",
    ] {
        assert!(!words_send_nothing(&argv(line), &CURL), "{line}");
    }
    for line in [
        "wget https://x.test/a",
        "wget --no-config https://x.test/a",
        "wget --no-netrc https://x.test/a",
        "wget --no-con --no-netrc https://x.test/a",
    ] {
        assert!(!words_send_nothing(&argv(line), &WGET), "{line}");
    }
}

#[test]
fn redirects_keep_the_command_net() {
    for line in [
        "curl -q -sSL https://x.test",
        "curl -q --location https://x.test",
    ] {
        assert!(!words_send_nothing(&argv(line), &CURL), "{line}");
    }
    assert!(wget_follows_no_redirect(&argv(
        "wget --max-redirect=0 https://x.test"
    )));
    assert!(wget_follows_no_redirect(&argv(
        "wget --max-redirect 0 https://x.test"
    )));
    for line in [
        "wget https://x.test",
        "wget --max-redirect=0 --max-redirect=5 https://x.test",
        "wget --max-redirect=3 https://x.test",
    ] {
        assert!(!wget_follows_no_redirect(&argv(line)), "{line}");
    }
}

#[test]
fn requests_that_may_send_data() {
    for line in [
        "curl -q -d x https://x.test",
        "curl -q -sd x https://x.test",
        "curl -q -X POST https://x.test",
        "curl -q -sXPUT https://x.test",
        "curl -q -H a:b https://x.test",
        "curl -q -K cfg https://x.test",
        "curl -q -u a:b https://x.test",
        "curl -q -b c.txt https://x.test",
        "curl -q -A agent https://x.test",
        "curl -q https://x.test --next https://y.test",
        "curl -q https://a:b@x.test/",
        "curl -q @urls",
        "curl -q -o @x https://x.test",
        "curl -q --head=x https://x.test",
        "curl -q -o",
    ] {
        assert!(!words_send_nothing(&argv(line), &CURL), "{line}");
    }
    for line in [
        "wget --no-config --no-netrc --post-file=x https://x.test",
        "wget --no-config --no-netrc --method=GET https://x.test",
        "wget --no-config --no-netrc -i list",
        "wget --no-config --no-netrc -e cmd https://x.test",
        "wget --no-config --no-netrc --header=a:b https://x.test",
        "wget --no-config --no-netrc -nX https://x.test",
    ] {
        assert!(!words_send_nothing(&argv(line), &WGET), "{line}");
    }
}

#[test]
fn writes_the_line_does_not_show_keep_the_command_net() {
    for line in [
        // `%output{FILE}` writes agent-chosen text (curl 8.3)
        "curl -q -w %{http_code} https://example.com",
        "curl -q -w %output{.git/hooks/post-commit}x https://x.test",
        "curl -q --write-out=x https://x.test",
        // the server names the file
        "curl -q -OJ https://x.test/a",
        "curl -q -O --remote-header-name https://x.test/a",
        // no name, an escape or a glob in the remote name
        "curl -q -O https://x.test",
        "curl -q -O https://x.test/%2ebashrc",
        "curl -q -O https://x.test/{a,b}",
        "curl -q -o #1 https://x.test/{a,b}",
    ] {
        assert!(!words_send_nothing(&argv(line), &CURL), "{line}");
    }
    for line in [
        "wget --no-config --no-netrc --content-disposition https://x.test/a",
        "wget --no-config --no-netrc https://x.test/%2ebashrc",
    ] {
        assert!(!words_send_nothing(&argv(line), &WGET), "{line}");
    }
}

#[test]
fn allowlists_agree_with_the_parser() {
    for options in [&CURL, &WGET] {
        let client = options.client;
        for name in options.valued {
            assert!(client.long_valued().contains(name), "{name}");
        }
        for name in options.flags {
            assert!(client.long_flags().contains(name), "{name}");
        }
    }
}

#[test]
fn only_domain_names_are_fetchable() {
    assert!(fetchable_host("docs.rs"));
    assert!(fetchable_host("x.test"));
    assert!(fetchable_host("a-b.example.com"));
    for host in [
        "localhost",
        "intranet",
        "2852039166",
        "0x7f000001",
        "203.0.113.7",
        "169.254.169.254",
        "::1",
        "fd00:ec2::254",
        "169.254.169.254.nip.io",
        "x.123",
    ] {
        assert!(!fetchable_host(host), "{host}");
    }
}
