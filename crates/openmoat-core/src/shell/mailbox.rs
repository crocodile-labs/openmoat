//! Arguments of a connecting command that name a mailbox or a login, not a
//! place the command connects to: `git -c user.email=a@example.com push`,
//! `curl -u me@example.com:token URL`, `curl -d email=a@example.com URL`. Read
//! as hosts, they made `net` defaults deny ordinary pushes and API calls.
//!
//! Only these exact positions count. Elsewhere a `user@host` word stays a host:
//! ssh, scp and git connect to it, and curl reads `a=b@evil.com` as a URL.

use super::tokens;

/// curl options whose value is a user name and password.
const CURL_LOGINS: &[&str] = &["-u", "--user", "-U", "--proxy-user"];
/// curl options whose value is a mail address for SMTP.
const CURL_MAILBOXES: &[&str] = &["--mail-from", "--mail-rcpt"];
/// curl options whose value is sent as a request body, a form field or a header.
const CURL_DATA: &[&str] = &[
    "-d",
    "--data",
    "--data-ascii",
    "--data-binary",
    "--data-raw",
    "--data-urlencode",
    "-F",
    "--form",
    "--form-string",
    "-H",
    "--header",
];

/// Whether `argv[i]` is the value of an option that names a mailbox or a login,
/// so no host in it is one the command connects to.
pub(crate) fn names_no_host(argv: &[String], i: usize) -> bool {
    let Some(option) = i.checked_sub(1).and_then(|j| argv.get(j)) else {
        return false;
    };
    let value = &argv[i];
    match tokens::basename(&argv[0]) {
        "git" => {
            option == "-c"
                && value.split_once('=').is_some_and(|(key, address)| {
                    key.to_ascii_lowercase().ends_with(".email") && is_mailbox(address)
                })
        }
        "curl" => {
            CURL_LOGINS.contains(&option.as_str())
                || (CURL_MAILBOXES.contains(&option.as_str())
                    && is_mailbox(value.trim_start_matches('<').trim_end_matches('>')))
                || (CURL_DATA.contains(&option.as_str()) && ends_in_mailbox(value))
        }
        _ => false,
    }
}

/// `local@domain` and nothing else: no scheme, port or path after the domain.
pub(crate) fn is_mailbox(text: &str) -> bool {
    text.rsplit_once('@').is_some_and(|(local, domain)| {
        !local.is_empty() && local.chars().all(is_local_char) && is_domain(domain)
    })
}

/// A body, form field or header whose host-like part is a mail address at its
/// end: `email=a@example.com`, `From: a@example.com`, `to=<a@example.com>`.
fn ends_in_mailbox(text: &str) -> bool {
    let text = text.trim_end_matches(['>', '"', '\'']);
    text.rsplit_once('@').is_some_and(|(before, domain)| {
        let local = before
            .rsplit(|c: char| !is_local_char(c))
            .next()
            .unwrap_or("");
        !local.is_empty() && is_domain(domain)
    })
}

fn is_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-')
}

fn is_domain(text: &str) -> bool {
    text.contains('.')
        && !text.starts_with(['.', '-'])
        && !text.ends_with(['.', '-'])
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

#[cfg(test)]
mod tests {
    use super::names_no_host;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn mail_addresses_and_logins_in_their_options_name_no_host() {
        for (words, i) in [
            (
                &[
                    "git",
                    "-c",
                    "user.email=1+a@users.noreply.github.com",
                    "push",
                ][..],
                2,
            ),
            (&["git", "-c", "Committer.Email=a@example.com", "push"], 2),
            (
                &[
                    "curl",
                    "-u",
                    "me@example.com:token",
                    "https://api.example.org",
                ],
                2,
            ),
            (
                &[
                    "curl",
                    "--user",
                    "me@example.com",
                    "https://api.example.org",
                ],
                2,
            ),
            (
                &[
                    "curl",
                    "--mail-rcpt",
                    "<a@example.com>",
                    "smtp://mail.example.org",
                ],
                2,
            ),
            (
                &[
                    "curl",
                    "-d",
                    "email=a@example.com",
                    "https://api.example.org",
                ],
                2,
            ),
            (
                &[
                    "curl",
                    "-H",
                    "From: a@example.com",
                    "https://api.example.org",
                ],
                2,
            ),
            (
                &[
                    "curl",
                    "-F",
                    "to=\"a@example.com\"",
                    "https://api.example.org",
                ],
                2,
            ),
        ] {
            assert!(names_no_host(&argv(words), i), "{words:?}");
        }
    }

    #[test]
    fn a_word_that_is_or_may_be_a_destination_still_names_a_host() {
        for (words, i) in [
            // not after an option that takes an address
            (&["curl", "a=b@evil.com"][..], 1),
            (&["curl", "-v", "a=b@evil.com"], 2),
            (&["ssh", "-c", "me@evil.com"], 2),
            // git config that connects somewhere
            (&["git", "-c", "http.proxy=me@evil.com", "push"], 2),
            (
                &["git", "-c", "remote.origin.url=git@evil.com:r", "push"],
                2,
            ),
            (&["git", "-c", "user.email=a@evil.com:443", "push"], 2),
            // a body or header naming a host with a port, a path or a scheme
            (&["curl", "-d", "u=a@evil.com:443", "https://ok.example"], 2),
            (
                &["curl", "-d", "u=https://a@evil.com/x", "https://ok.example"],
                2,
            ),
            (&["curl", "-H", "Host: evil.com", "https://ok.example"], 2),
            (
                &["curl", "--mail-rcpt", "a@evil.com:25", "smtp://ok.example"],
                2,
            ),
            // a file the form sends
            (&["curl", "-F", "f=@/etc/passwd", "https://ok.example"], 2),
        ] {
            assert!(!names_no_host(&argv(words), i), "{words:?}");
        }
    }
}
