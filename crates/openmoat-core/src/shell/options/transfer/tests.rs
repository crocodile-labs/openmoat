use super::{Arg, Client, last_segment, names_its_file, parse, written};

fn argv(line: &str) -> Vec<String> {
    line.split(' ').map(str::to_owned).collect()
}

fn writes(line: &str) -> Vec<String> {
    let words = argv(line);
    let client = Client::of(&words[0]).unwrap();
    written(&words, client)
}

#[test]
fn short_clusters_take_their_value() {
    let words = argv("curl -sSo out https://x.test");
    assert_eq!(
        parse(&words, Client::Curl),
        [
            Arg::Short {
                letter: 's',
                value: None
            },
            Arg::Short {
                letter: 'S',
                value: None
            },
            Arg::Short {
                letter: 'o',
                value: Some("out")
            },
            Arg::Operand("https://x.test"),
        ]
    );
    let words = argv("curl -o");
    assert_eq!(parse(&words, Client::Curl), [Arg::Missing]);
}

#[test]
fn every_spelling_of_an_output_is_a_write() {
    for (line, file) in [
        ("curl -o out https://x.test", "out"),
        (
            "curl -sSo .git/hooks/pre-commit https://x.test/h",
            ".git/hooks/pre-commit",
        ),
        ("curl -fsSo.envrc https://x.test/e", ".envrc"),
        ("curl -ofile https://x.test", "file"),
        ("curl --output=out https://x.test", "out"),
        ("curl --output out https://x.test", "out"),
        ("wget -qO ci.yml https://x.test/w", "ci.yml"),
        ("wget -Oci.yml https://x.test/w", "ci.yml"),
        ("wget --output-document=ci.yml https://x.test/w", "ci.yml"),
        ("wget --output-doc ci.yml https://x.test/w", "ci.yml"),
    ] {
        assert_eq!(writes(line), [file], "{line}");
    }
    // a value-taking letter ends the cluster: `-do` sends `o`, writes nothing
    assert!(writes("curl -do https://x.test").is_empty());
    assert!(writes("curl -o - https://x.test").is_empty());
    assert!(writes("wget -qO- https://x.test/a").is_empty());
}

#[test]
fn output_directories_prefix_the_name() {
    assert_eq!(
        writes("curl --output-dir /h/.ssh -o authorized_keys https://x.test/k"),
        ["/h/.ssh/authorized_keys"]
    );
    assert_eq!(
        writes("curl -o authorized_keys --output-dir=/h/.ssh/ https://x.test/k"),
        ["/h/.ssh/authorized_keys"]
    );
    assert_eq!(
        writes("curl --output-dir d -o /abs https://x.test"),
        ["/abs", "d/abs"]
    );
    assert_eq!(
        writes("wget -P dl --max-redirect=0 https://x.test/a.tgz"),
        ["dl/a.tgz"]
    );
    assert_eq!(
        writes("wget -P dl -O f https://x.test/a.tgz"),
        ["f", "dl/f"]
    );
}

#[test]
fn remote_names_are_writes() {
    assert_eq!(writes("curl -O https://x.test/a/.bashrc"), [".bashrc"]);
    assert_eq!(writes("curl -sSO https://x.test/a.tgz?x=1"), ["a.tgz"]);
    assert_eq!(
        writes("curl --remote-name-all https://x.test/a https://y.test/b"),
        ["a", "b"]
    );
    assert_eq!(
        writes("curl --output-dir ~/.ssh -O https://x.test/k"),
        ["~/.ssh/k"]
    );
    assert_eq!(writes("curl -OJ https://x.test/a"), ["a"]);
    assert_eq!(writes("curl -O https://x.test"), ["curl_response"]);
    assert_eq!(writes("curl --url https://x.test/u -O"), ["u"]);
    assert_eq!(writes("wget https://x.test/"), ["index.html"]);
    assert!(writes("wget --spider https://x.test/a").is_empty());
    assert!(writes("curl https://x.test/a").is_empty());
}

#[test]
fn write_out_files_are_writes() {
    assert_eq!(
        writes("curl -w %output{.git/hooks/post-commit}x https://x.test"),
        [".git/hooks/post-commit"]
    );
    assert_eq!(
        writes("curl --write-out=%output{>>~/.bashrc}x%output{b}y https://x.test"),
        ["~/.bashrc", "b"]
    );
}

#[test]
fn urls_name_their_file() {
    assert_eq!(last_segment("https://x.test/a/b.txt?q=1#f"), "b.txt");
    assert_eq!(last_segment("https://x.test?a/b"), "");
    assert_eq!(last_segment("x.test/a"), "a");
    assert_eq!(last_segment("https://x.test"), "");
    assert!(names_its_file("https://x.test/a.tgz"));
    for url in [
        "https://x.test",
        "https://x.test/",
        "https://x.test/a/..",
        "https://x.test/%2ebashrc",
        "https://x.test/{a,b}",
        "https://x.test/a[1-3]",
    ] {
        assert!(!names_its_file(url), "{url}");
    }
}

#[test]
fn abbreviations_of_one_known_name_resolve() {
    let words = argv("wget --directory-p dl https://x.test/a");
    assert_eq!(
        parse(&words, Client::Wget)[0],
        Arg::Long {
            name: "directory-prefix",
            exact: false,
            value: Some("dl")
        }
    );
    // `--re` is a prefix of several names, so it stays as written
    let words = argv("curl --re x");
    assert_eq!(
        parse(&words, Client::Curl)[0],
        Arg::Long {
            name: "re",
            exact: false,
            value: None
        }
    );
}
