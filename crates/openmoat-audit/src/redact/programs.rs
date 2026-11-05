//! Credentials that well-known programs and formats take in a shape the named
//! patterns do not see: a single-letter flag (`mysql -p<password>`,
//! `sshpass -p`, `redis-cli -a`), a positional argument (`htpasswd -b`,
//! `aws configure set aws_secret_access_key`), an environment name with no
//! separator before its credential word (`PGPASSWORD`, `MYSQL_PWD`,
//! `OPENAI_KEY`), a cookie, a webhook URL or a URL whose user part is a key.
//!
//! Each rule is tied to its program or format, so the same flag elsewhere
//! (`cargo test -p crate`, `ssh -p 2222`, `ps -a`, `wget -P dir`) keeps its value.

use regex::Captures;

use super::judge::{HTTP_CLIENTS, program_before};
use super::{Mask, REPLACEMENT};

/// A flag's value: a double-quoted or single-quoted word, or a bare one up to
/// the next space or shell operator.
macro_rules! value {
    () => {
        r#"(?P<v>\x22(?:\\.|[^\x22\\])*\x22|'[^']*'|[^\s'\x22;&|]+)"#
    };
}

/// The start of `pre` for a rule about the programs `$names` (a regex
/// alternation): the program as a command word (at the start, after a space,
/// an operator, a quote or a directory, not inside `f.zip`), then anything up
/// to `$flag` within the same command, no shell operator or line break between.
macro_rules! program_flag {
    ($names:literal, $flag:literal) => {
        concat!(
            r"(?P<pre>(?:^|[\s;&|(/\x22'])(?:",
            $names,
            r")(?:\s[^;&|\n]*?)?",
            $flag,
            ")",
            value!()
        )
    };
}

pub(super) const RULES: &[(&str, Mask)] = &[
    // An environment name whose last part, or glued tail, is a credential word:
    // `PGPASSWORD`, `MYSQL_PWD`, `OPENAI_KEY`, `REDISCLI_AUTH`. Upper case
    // only, as environment names are written, so `sort_key=` in code and `PWD`
    // or `OLDPWD` keep their values.
    (
        concat!(
            r#"(?P<key>(?:^|[\s;&|(\x22'])(?:[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|_PWD|_PASS|_KEY|_SECRET|_AUTH|_CREDENTIALS?)|PGPASS)=)"#,
            value!()
        ),
        Mask::With(env_value),
    ),
    // The MySQL and MariaDB clients take the password glued to `-p`; a bare
    // `-p` asks for it, and `-P` is the port.
    (
        program_flag!(
            "mysql|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mysqlpump|mysqlslap|mariadb|mariadb-dump|mariadb-admin",
            r"\s-p"
        ),
        Mask::Text("${pre}[redacted]"),
    ),
    // 7-Zip, glued too: `7z a -psecret x.7z`.
    (
        program_flag!("7z|7za|7zz|7zr", r"\s-p"),
        Mask::Text("${pre}[redacted]"),
    ),
    // `sshpass -p <password>` (or glued).
    (
        program_flag!("sshpass", r"\s-p\s*"),
        Mask::Text("${pre}[redacted]"),
    ),
    // A registry login's `-p <password>` (`--password` is a named flag).
    (
        program_flag!(
            r"(?:docker|podman|buildah|skopeo|nerdctl|oras)\s+login|helm\s+registry\s+login|crane\s+auth\s+login",
            r"\s-p\s+"
        ),
        Mask::Text("${pre}[redacted]"),
    ),
    // `redis-cli -a <password>` and `--pass <password>`.
    (
        program_flag!("redis-cli", r"\s(?:-a|--pass)\s+"),
        Mask::Text("${pre}[redacted]"),
    ),
    // `openssl enc -k <password>`; `-kfile` names a file.
    (
        program_flag!("openssl", r"\s-k\s+"),
        Mask::Text("${pre}[redacted]"),
    ),
    // OpenSSL's `-pass`, `-passin` and `-passout` with a `pass:` value; `env:`,
    // `file:`, `fd:` and `stdin` name where the password is and are kept.
    (
        r"(?P<pre>\s-pass(?:in|out)?\s+['\x22]?pass:)(?P<v>[^\s'\x22]+)",
        Mask::Text("${pre}[redacted]"),
    ),
    // `zip -P <password>`, `unzip -P`, `zipcloak -P`.
    (
        program_flag!("zip|unzip|zipcloak", r"\s-P\s+"),
        Mask::Text("${pre}[redacted]"),
    ),
    // `htpasswd -b[c] file user password`, `htpasswd -nb user password`.
    (
        r"(?P<pre>(?:^|[\s;&|(/\x22'])htpasswd)(?P<args>(?:\s+[^\s;&|]+)+)",
        Mask::With(htpasswd),
    ),
    // `aws configure set [profile.]aws_secret_access_key <value>`, and the
    // session token.
    (
        concat!(
            r"(?P<pre>\baws\s+configure\s+set\s+(?:--profile\s+\S+\s+)?(?:\S+\.)?(?:aws_secret_access_key|aws_session_token)\s+)",
            value!()
        ),
        Mask::Text("${pre}[redacted]"),
    ),
    // A `Cookie:` or `Set-Cookie:` header with a `name=value`: its whole value,
    // to the end of the header (a quote or a line break). Prose such as
    // `fix cookie: expiry` has no `=` and is kept.
    (
        r"(?i)(?P<pre>(?:^|[\s'\x22])(?:set-)?cookie\s*:[ \t]*)(?P<v>[^\s'\x22=;]+=[^\r\n'\x22]*)",
        Mask::Text("${pre}[redacted]"),
    ),
    // An HTTP client's `-b`/`--cookie name=value`; a value without `=` is a
    // cookie file and is kept, and so is another program's `-b`.
    (
        r"(?P<pre>\s(?:-b|--cookie)(?:=|\s+)['\x22]?)(?P<v>[^\s'\x22=;]+=[^\s'\x22]*)",
        Mask::With(cookie_flag),
    ),
    // Slack and Discord webhook URLs: the path is the credential.
    (
        r"(?P<pre>https?://hooks\.slack\.com/(?:services|workflows|triggers)/)[A-Za-z0-9/_-]+",
        Mask::Text("${pre}[redacted]"),
    ),
    (
        r"(?P<pre>https?://(?:[a-z]+\.)?discord(?:app)?\.com/api/webhooks/)[0-9]+/[A-Za-z0-9_-]+",
        Mask::Text("${pre}[redacted]"),
    ),
    // A URL whose user part is a key and has no password (a Sentry DSN
    // `https://<key>@o1.ingest.sentry.io/1`, a token given as the user to git
    // over HTTPS). A short or digitless user (`ssh://git@host`) is kept.
    (
        r"(?P<pre>://)(?P<v>[A-Za-z0-9_.~-]{20,})@",
        Mask::With(url_user),
    ),
];

fn group<'h>(caps: &Captures<'h>, name: &str) -> &'h str {
    caps.name(name).map_or("", |m| m.as_str())
}

fn whole<'h>(caps: &Captures<'h>) -> &'h str {
    caps.get(0).map_or("", |m| m.as_str())
}

/// `NAME=value`: the value is masked, the name and its quotes kept. A bare
/// value that refers to one elsewhere (`$VAR`, `$(cat f)`) or is a path
/// (`/…`, `~/…`, `./…`) holds no secret and is kept.
fn env_value(caps: &Captures<'_>, _: &str) -> String {
    let key = group(caps, "key");
    let value = group(caps, "v");
    match value.chars().next() {
        Some(q @ ('\'' | '"')) if value.len() >= 2 && value.ends_with(q) => {
            format!("{key}{q}{REPLACEMENT}{q}")
        }
        _ if value.starts_with(['$', '/'])
            || value.starts_with("~/")
            || value.starts_with("./") =>
        {
            whole(caps).to_owned()
        }
        _ => format!("{key}{REPLACEMENT}"),
    }
}

/// `htpasswd` with `-b` takes the password as its last argument: the third
/// after the flags, or the second with `-n` (no file). Everything from it to
/// the end of the command is masked, so a quoted password with spaces goes
/// whole. Without `-b` the password is asked for, and nothing is masked.
fn htpasswd(caps: &Captures<'_>, _: &str) -> String {
    let args = group(caps, "args");
    let mut flags = String::new();
    let mut positional = Vec::new();
    let mut offset = 0;
    for word in args.split_whitespace() {
        let at = args
            .get(offset..)
            .and_then(|rest| rest.find(word))
            .map_or(offset, |i| offset + i);
        offset = at + word.len();
        match word.strip_prefix('-') {
            Some(cluster) if positional.is_empty() && !cluster.is_empty() => {
                flags.push_str(cluster);
            }
            _ => positional.push(at),
        }
    }
    if !flags.contains('b') {
        return whole(caps).to_owned();
    }
    let index = if flags.contains('n') { 1 } else { 2 };
    match positional.get(index).and_then(|&at| args.get(..at)) {
        Some(before) => format!("{}{before}{REPLACEMENT}", group(caps, "pre")),
        None => whole(caps).to_owned(),
    }
}

/// `-b name=value` of an HTTP client; any other program's `-b` is kept.
fn cookie_flag(caps: &Captures<'_>, text: &str) -> String {
    let start = caps.get(0).map_or(0, |m| m.start());
    let program = program_before(text.get(..start).unwrap_or_default());
    if !HTTP_CLIENTS.contains(&program.as_str()) {
        return whole(caps).to_owned();
    }
    format!("{}{REPLACEMENT}", group(caps, "pre"))
}

/// A user part of a URL that holds a digit: a key, not a name.
fn url_user(caps: &Captures<'_>, _: &str) -> String {
    if !group(caps, "v").chars().any(|c| c.is_ascii_digit()) {
        return whole(caps).to_owned();
    }
    format!("{}{REPLACEMENT}@", group(caps, "pre"))
}
