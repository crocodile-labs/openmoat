//! The helper client against a loopback stand-in for the proxy: no network.

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{Ipv4Addr, TcpListener};

use super::{Proxy, answer, git_host};

/// Made at run time: no credential-shaped literal in the source.
fn token() -> String {
    "t".repeat(40)
}

fn env(url: &str) -> impl Fn(&str) -> Option<String> + '_ {
    move |name| (name == "HTTPS_PROXY").then(|| url.to_owned())
}

#[test]
fn git_requests_name_an_https_host() {
    let host = git_host("protocol=https\nhost=github.com\npath=org/repo.git\n").unwrap();
    assert_eq!(host, "github.com");
    assert_eq!(
        git_host("protocol=https\nhost=ghe.example:8443\n").unwrap(),
        "ghe.example:8443"
    );
    for bad in [
        "protocol=http\nhost=github.com\n",
        "host=github.com\n",
        "protocol=https\n",
        "protocol=https\nhost=\n",
        "protocol=https\nhost=a b\n",
    ] {
        assert!(git_host(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_proxy_comes_from_the_runs_variables_and_is_loopback_only() {
    let url = format!("http://run-1-abc:{}@127.0.0.1:4711", token());
    let proxy = Proxy::from_env(&env(&url)).unwrap();
    assert_eq!(proxy.addr.port(), 4711);
    assert_eq!(
        proxy.basic.as_str(),
        crate::secrets::base64(format!("run-1-abc:{}", token()).as_bytes())
    );
    // Never sends the session credential off this machine.
    let far = format!("http://run-1-abc:{}@203.0.113.7:4711", token());
    let err = Proxy::from_env(&env(&far)).err().unwrap().to_string();
    assert!(err.contains("loopback") && !err.contains(&token()), "{err}");
    for bad in [
        "",
        "https://127.0.0.1:1",
        "http://127.0.0.1:1",
        "http://:x@127.0.0.1:1",
    ] {
        assert!(Proxy::from_env(&env(bad)).is_err(), "{bad:?}");
    }
    assert!(
        Proxy::from_env(&|_| None)
            .err()
            .unwrap()
            .to_string()
            .contains("openmoat run")
    );
}

#[test]
fn answers_are_read_and_refusals_are_errors() {
    let given = answer("OK x-access-token v4lue\n").unwrap();
    assert_eq!(given.username.as_deref(), Some("x-access-token"));
    assert_eq!(given.value.as_str(), "v4lue");
    let aws = answer("OK - {\"Version\":1}\n").unwrap();
    assert_eq!(
        (aws.username, aws.value.as_str()),
        (None, "{\"Version\":1}")
    );
    let err = answer("NO only github.com may receive it\n")
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("only github.com"), "{err}");
    for bad in ["", "OK\n", "OK user\n", "OK user \n", "HTTP/1.1 200 OK\n"] {
        assert!(answer(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_helper_sends_one_line_with_the_session_credential() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        (&stream)
            .write_all(b"OK x-access-token minted-value\n")
            .unwrap();
        line
    });
    let url = format!("http://run-1-abc:{}@127.0.0.1:{port}", token());
    let given = Proxy::from_env(&env(&url))
        .unwrap()
        .ask("git", "gh-git", Some("github.com"))
        .unwrap();
    assert_eq!(given.value.as_str(), "minted-value");
    let sent = server.join().unwrap();
    let basic = crate::secrets::base64(format!("run-1-abc:{}", token()).as_bytes());
    assert_eq!(
        sent,
        format!("MOAT-HELPER/1 git gh-git github.com {basic}\n")
    );
}
