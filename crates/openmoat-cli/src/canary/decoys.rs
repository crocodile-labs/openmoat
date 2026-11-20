//! Where decoys go and what they hold (ADR-106 §1).
//!
//! Each target is a backup name beside a credential file that tools scanning a
//! home directory look for: no program loads it on its own (npm reads
//! `~/.npmrc`, git's store helper `~/.git-credentials`, the AWS tools
//! `~/.aws/credentials`, never their `.bak`), so a decoy there changes nothing
//! a person's tools do. Each value has the shape a key scanner looks for
//! (`AKIA` and sixteen capitals, `ghp_` and thirty-six letters, `npm_` and
//! thirty-six), and carries `OpenMoatDecoy`, so a person who finds one knows
//! whose it is. The rest is random, so this machine's decoys are its own.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

/// One place a decoy can go.
#[derive(Debug)]
pub struct Target {
    /// The file, as the policy spells a path.
    pub path: &'static str,
    /// What it looks like, in a few words.
    pub what: &'static str,
    /// Each value: a prefix, then [`MARK`], then random letters and digits up
    /// to this many characters in all.
    shapes: &'static [Shape],
    /// The file's text around the values.
    render: fn(&[String]) -> String,
}

/// A value's look: its prefix, its length and its letters.
#[derive(Debug)]
struct Shape {
    prefix: &'static str,
    len: usize,
    upper_only: bool,
}

/// What every decoy value holds, so a person reading one knows whose it is.
pub const MARK: &str = "OpenMoatDecoy";

/// Every place a decoy can go, in the order `init` names them.
pub static TARGETS: [Target; 3] = [
    Target {
        path: "~/.aws/credentials.bak",
        what: "an AWS access key",
        shapes: &[
            Shape {
                prefix: "AKIA",
                len: 20,
                upper_only: true,
            },
            Shape {
                prefix: "",
                len: 40,
                upper_only: false,
            },
        ],
        render: aws,
    },
    Target {
        path: "~/.git-credentials.bak",
        what: "a GitHub token",
        shapes: &[Shape {
            prefix: "ghp_",
            len: 40,
            upper_only: false,
        }],
        render: git,
    },
    Target {
        path: "~/.npmrc.bak",
        what: "an npm token",
        shapes: &[Shape {
            prefix: "npm_",
            len: 40,
            upper_only: false,
        }],
        render: npm,
    },
];

impl Target {
    /// The file under `user`, the home directory.
    pub fn file(&self, user: &Path) -> PathBuf {
        user.join(self.path.trim_start_matches("~/"))
    }

    /// New values for this decoy.
    pub fn values(&self) -> Result<Vec<String>> {
        self.shapes.iter().map(Shape::value).collect()
    }

    /// The file's text with `values`.
    pub fn content(&self, values: &[String]) -> String {
        (self.render)(values)
    }
}

impl Shape {
    fn value(&self) -> Result<String> {
        let mark = if self.upper_only {
            MARK.to_ascii_uppercase()
        } else {
            MARK.to_owned()
        };
        let fixed = self.prefix.len() + mark.len();
        let rest = random(self.len.saturating_sub(fixed), self.upper_only)?;
        Ok(format!("{}{mark}{rest}", self.prefix))
    }
}

/// `n` random letters and digits; capitals and digits only when `upper_only`.
fn random(n: usize, upper_only: bool) -> Result<String> {
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const MIXED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let alphabet = if upper_only { UPPER } else { MIXED };
    let mut out = String::with_capacity(n);
    // A byte past the last whole multiple of the alphabet's size is drawn
    // again, so every character is as likely as every other.
    let limit = 256 - 256 % alphabet.len();
    let mut byte = [0u8; 1];
    while out.len() < n {
        getrandom::fill(&mut byte).context("reading random bytes for a decoy key")?;
        let b = usize::from(byte[0]);
        if b < limit {
            out.push(char::from(alphabet[b % alphabet.len()]));
        }
    }
    Ok(out)
}

fn value(values: &[String], n: usize) -> &str {
    values.get(n).map_or("", String::as_str)
}

fn aws(values: &[String]) -> String {
    format!(
        "[default]\naws_access_key_id = {}\naws_secret_access_key = {}\n",
        value(values, 0),
        value(values, 1)
    )
}

fn git(values: &[String]) -> String {
    format!("https://openmoat-decoy:{}@github.com\n", value(values, 0))
}

fn npm(values: &[String]) -> String {
    format!("//registry.npmjs.org/:_authToken={}\n", value(values, 0))
}
