use super::{CURL, WGET, fetchable_host, output_words, words_send_nothing};
use crate::shell::options::transfer::Client;

fn argv(line: &str) -> Vec<String> {
    line.split(' ').map(str::to_owned).collect()
}

#[test]
fn requests_that_send_nothing() {
    for line in [
        "curl https://docs.rs/serde",
        "curl -q https://docs.rs/serde",
        "curl --disable https://docs.rs/serde",
        "curl -sS https://example.com/f.txt -o out.txt",
        "curl -sSo out.txt https://example.com/f.txt",
        "curl -X GET -fsS https://example.com/api",
        "curl --request=HEAD https://example.com",
        "curl -O https://example.com/a.tar.gz",
        "curl --output-dir dl -o a.tgz https://example.com/a.tgz",
        "curl -- https://example.com",
        // redirects are followed: the URL shown is what the person judges (ADR-047)
        "curl -sSL -o x.tgz https://codeload.github.com/x/y/tar.gz/main",
        "curl --location https://x.test",
        "curl -fsSL https://x.test/a -o /dev/null",
    ] {
        assert!(words_send_nothing(&argv(line), &CURL), "{line}");
    }
    for line in [
        "wget https://x.test/a.tar.gz",
        "wget -q https://x.test/a -O docs/x.md",
        "wget -qO- https://x.test/a",
        "wget --no-config --no-netrc https://x.test/a.tar.gz",
        "wget -nv --tries=3 -P dl https://x.test/a",
        "wget --no-netrc --no-config -qnv https://x.test/",
        "wget --max-redirect=0 https://x.test",
    ] {
        assert!(words_send_nothing(&argv(line), &WGET), "{line}");
    }
}

#[test]
fn netrc_and_trusted_redirects_keep_the_command_net() {
    // curl reads `.netrc` only when told to, and `--location-trusted` sends the
    // credentials on to wherever a redirect leads
    for line in [
        "curl -n https://docs.rs/serde",
        "curl --netrc https://docs.rs/serde",
        "curl --netrc-optional https://docs.rs/serde",
        "curl --location-trusted https://x.test",
    ] {
        assert!(!words_send_nothing(&argv(line), &CURL), "{line}");
    }
}

#[test]
fn requests_that_may_send_data() {
    for line in [
        "curl -d x https://x.test",
        "curl -sd x https://x.test",
        "curl -X POST https://x.test",
        "curl -sXPUT https://x.test",
        "curl -H a:b https://x.test",
        "curl -K cfg https://x.test",
        "curl -u a:b https://x.test",
        "curl -b c.txt https://x.test",
        "curl -A agent https://x.test",
        "curl https://x.test --next https://y.test",
        "curl https://a:b@x.test/",
        "curl @urls",
        "curl -o @x https://x.test",
        "curl --head=x https://x.test",
        "curl -o",
    ] {
        assert!(!words_send_nothing(&argv(line), &CURL), "{line}");
    }
    for line in [
        "wget --post-file=x https://x.test",
        "wget --method=GET https://x.test",
        "wget -i list",
        "wget -e cmd https://x.test",
        "wget --header=a:b https://x.test",
        "wget -nX https://x.test",
    ] {
        assert!(!words_send_nothing(&argv(line), &WGET), "{line}");
    }
}

#[test]
fn writes_the_line_does_not_show_keep_the_command_net() {
    for line in [
        // `%output{FILE}` writes agent-chosen text (curl 8.3)
        "curl -w %{http_code} https://example.com",
        "curl -w %output{.git/hooks/post-commit}x https://x.test",
        "curl --write-out=x https://x.test",
        // the server names the file
        "curl -OJ https://x.test/a",
        "curl -O --remote-header-name https://x.test/a",
        // no name, an escape or a glob in the remote name
        "curl -O https://x.test",
        "curl -O https://x.test/%2ebashrc",
        "curl -O https://x.test/{a,b}",
        "curl -o #1 https://x.test/{a,b}",
    ] {
        assert!(!words_send_nothing(&argv(line), &CURL), "{line}");
    }
    for line in [
        "wget --content-disposition https://x.test/a",
        "wget https://x.test/%2ebashrc",
    ] {
        assert!(!words_send_nothing(&argv(line), &WGET), "{line}");
    }
}

/// Only the words that name the file or directory written may hold a shell
/// expansion: the write is then checked as a path the hook cannot place.
#[test]
fn only_output_words_may_expand() {
    let outputs = |line: &str, client| output_words(&argv(line), client);
    assert_eq!(
        outputs("curl -sSL -o $TMPDIR/x.tgz https://x.test/x", Client::Curl),
        [3]
    );
    assert_eq!(
        outputs("curl -sSLo$TMPDIR/x.tgz https://x.test/x", Client::Curl),
        [1]
    );
    assert_eq!(
        outputs("curl --output=$D/x https://x.test/x", Client::Curl),
        [1]
    );
    assert_eq!(
        outputs("curl --output-dir $D -o x https://x.test/x", Client::Curl),
        [2, 4]
    );
    assert_eq!(
        outputs("wget -q https://x.test/a -O $D/x.md", Client::Wget),
        [4]
    );
    assert_eq!(outputs("wget -P $D https://x.test/a", Client::Wget), [2]);
    // the URL, a flag and `-d`'s value are never output words
    assert!(outputs("curl -sS https://$H/x", Client::Curl).is_empty());
    assert!(outputs("curl $OPTS https://x.test", Client::Curl).is_empty());
    assert!(outputs("curl -d $BODY https://x.test", Client::Curl).is_empty());
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
