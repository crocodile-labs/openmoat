//! Credentials with no vendor prefix that a precise shape still finds in what
//! leaves the machine (POLICY.md §3, `token-egress` and `credential-egress`).
//!
//! [`super::SHAPES`] are prefixed formats, kept in step with the audit log's
//! patterns and the push check. These are found only in context, so they stay
//! out of that list:
//!
//! - an AWS secret access key: 40 characters of its alphabet as the value of a
//!   name ending in `secret_access_key` (`aws_secret_access_key=…`,
//!   `"SecretAccessKey": "…"`). Its service is AWS's hosts.
//! - a private key in PEM form: a `-----BEGIN … PRIVATE KEY-----` line (also
//!   `PGP PRIVATE KEY BLOCK`). No host owns it.
//! - a JSON web token: three base64url parts, the first two `eyJ` (a JSON
//!   object). No host owns it.
//! - a database URL with a password (`postgres://user:pass@db/…`, `mysql`,
//!   `mongodb+srv`, `redis`, …). Its own host owns it.
//!
//! The first two are tokens `token-egress` denies; a JWT and a database URL
//! are often sent to the service they belong to, which their shape does not
//! name, so they are `@credential-egress` atoms `credential-egress` holds for
//! review. No value is ever put in an atom.

/// One credential found in a text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    /// Short id used in atoms and reasons (`jwt`).
    pub id: &'static str,
    /// Whether it is a token `token-egress` denies; otherwise it is held for
    /// review (`credential-egress`).
    pub denied: bool,
    owner: Owner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Owner {
    /// Host names (and their subdomains) of the service it is for.
    Hosts(&'static [&'static str]),
    /// The host the credential itself names (a database URL's).
    Named(String),
    /// No host: it should leave the machine for none.
    Nobody,
}

impl Credential {
    /// Whether `host` is where this credential belongs.
    #[must_use]
    pub fn owns(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        match &self.owner {
            Owner::Hosts(hosts) => hosts.iter().any(|own| {
                host == *own
                    || host
                        .strip_suffix(own)
                        .is_some_and(|rest| rest.ends_with('.'))
            }),
            Owner::Named(own) => host == *own,
            Owner::Nobody => false,
        }
    }
}

const AWS_HOSTS: &[&str] = &["amazonaws.com", "amazonaws.com.cn", "aws.amazon.com"];

/// Names whose value is an AWS secret access key, compared lowercase.
const AWS_SECRET_NAMES: &[&str] = &["secret_access_key", "secret-access-key", "secretaccesskey"];

/// Length of an AWS secret access key.
const AWS_SECRET_LEN: usize = 40;

/// Schemes of database URLs that carry a login.
const DATABASE_SCHEMES: &[&str] = &[
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "mongodb",
    "mongodb+srv",
    "redis",
    "rediss",
    "amqp",
    "amqps",
    "mssql",
    "sqlserver",
    "cockroachdb",
];

/// Shortest part of a JSON web token this module counts.
const JWT_PART_MIN: usize = 10;

/// Every credential found in `text`, each kind once (a database URL once per host).
#[must_use]
pub fn in_text(text: &str) -> Vec<Credential> {
    let mut found = Vec::new();
    if aws_secret(text) {
        found.push(Credential {
            id: "aws-secret",
            denied: true,
            owner: Owner::Hosts(AWS_HOSTS),
        });
    }
    if private_key(text) {
        found.push(Credential {
            id: "private-key",
            denied: true,
            owner: Owner::Nobody,
        });
    }
    if jwt(text) {
        found.push(Credential {
            id: "jwt",
            denied: false,
            owner: Owner::Nobody,
        });
    }
    for host in database_hosts(text) {
        let credential = Credential {
            id: "database-url",
            denied: false,
            owner: Owner::Named(host),
        };
        if !found.contains(&credential) {
            found.push(credential);
        }
    }
    found
}

fn aws_alphabet(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'/' || b == b'+'
}

/// `…secret_access_key` then optional quotes and spaces, `=` or `:`, an
/// optional quote and exactly 40 characters of the key's alphabet.
fn aws_secret(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let raw = text.as_bytes();
    AWS_SECRET_NAMES.iter().any(|name| {
        lower.match_indices(name).any(|(at, _)| {
            let mut i = at + name.len();
            let skip = |i: &mut usize, set: &[u8]| {
                while bytes.get(*i).is_some_and(|b| set.contains(b)) {
                    *i += 1;
                }
            };
            skip(&mut i, b"\"' \t");
            if !matches!(bytes.get(i), Some(b'=' | b':')) {
                return false;
            }
            i += 1;
            skip(&mut i, b" \t\"'");
            let run = raw[i..].iter().take_while(|b| aws_alphabet(**b)).count();
            run == AWS_SECRET_LEN && raw.get(i + run) != Some(&b'=')
        })
    })
}

/// A `-----BEGIN <label> PRIVATE KEY-----` or `… PRIVATE KEY BLOCK-----` line.
fn private_key(text: &str) -> bool {
    const BEGIN: &str = "-----BEGIN ";
    text.match_indices(BEGIN).any(|(at, _)| {
        let rest = &text[at + BEGIN.len()..];
        let label: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == ' ')
            .collect();
        let after = &rest[label.len()..];
        after.starts_with("-----")
            && (label.ends_with("PRIVATE KEY") || label.ends_with("PRIVATE KEY BLOCK"))
    })
}

fn base64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Three base64url parts of [`JWT_PART_MIN`] or more joined by `.`, the
/// header and the payload each a JSON object (`eyJ`), at word boundaries.
fn jwt(text: &str) -> bool {
    let bytes = text.as_bytes();
    text.match_indices("eyJ").any(|(at, _)| {
        if at > 0 && base64url(bytes[at - 1]) {
            return false;
        }
        let part = |from: usize| bytes[from..].iter().take_while(|b| base64url(**b)).count();
        let header = part(at);
        let payload_at = at + header + 1;
        if header < JWT_PART_MIN
            || bytes.get(at + header) != Some(&b'.')
            || !text[payload_at..].starts_with("eyJ")
        {
            return false;
        }
        let payload = part(payload_at);
        let signature_at = payload_at + payload + 1;
        payload >= JWT_PART_MIN
            && bytes.get(payload_at + payload) == Some(&b'.')
            && part(signature_at) >= JWT_PART_MIN
    })
}

/// The hosts of the database URLs in `text` that carry a literal password:
/// `<scheme>://<user>:<password>@<host>`, the password not a variable.
fn database_hosts(text: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for (at, _) in text.match_indices("://") {
        let scheme_start = text[..at]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || "+.-".contains(c)))
            .map_or(0, |i| i + 1);
        let scheme = text[scheme_start..at].to_ascii_lowercase();
        if !DATABASE_SCHEMES.contains(&scheme.as_str()) {
            continue;
        }
        let rest = &text[at + 3..];
        let end = rest
            .find(|c: char| "/?#\"'` \t\n".contains(c))
            .unwrap_or(rest.len());
        let authority = &rest[..end];
        let Some((login, host)) = authority.rsplit_once('@') else {
            continue;
        };
        let Some((_, password)) = login.split_once(':') else {
            continue;
        };
        if password.is_empty() || password.starts_with(['$', '*', '<', '{']) {
            continue;
        }
        // the first host of a list (`h1:27017,h2:27017`), without its port
        let host = host.split(',').next().unwrap_or(host);
        let host = host
            .rsplit_once(':')
            .filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit()))
            .map_or(host, |(name, _)| name);
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        if !host.is_empty() && !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

#[cfg(test)]
mod tests;
