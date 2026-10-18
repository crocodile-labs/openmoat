//! Well-known token formats with a vendor prefix, and the services they belong to.
//!
//! The same shapes as `openmoat_audit::redact::TOKEN_SHAPES`, which masks them
//! with regular expressions before anything is stored; core has no regex
//! engine, so each shape is matched here by hand with the same rules (a test
//! in `openmoat-audit` keeps the two in step). Only prefixed formats: no
//! entropy guessing, so a commit SHA, a UUID or a base64 blob is never one.

/// One token format: `\b<prefix><body>{min,max}\b` in regex terms.
#[derive(Debug)]
pub struct Shape {
    /// Short id used in atoms and reasons (`github`).
    pub id: &'static str,
    /// What the token is, as `openmoat_audit::redact::token_shape` names it.
    pub description: &'static str,
    /// Host names (and their subdomains) of the service the token is for.
    pub hosts: &'static [&'static str],
    prefixes: &'static [&'static str],
    /// Optional `[a-z]+-` between prefix and body (`sk-proj-…`).
    lower_label: bool,
    body: fn(char) -> bool,
    min: usize,
    max: usize,
}

fn alnum(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

fn alnum_underscore(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn alnum_dash(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-'
}

fn alnum_underscore_dash(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn upper_digit(c: char) -> bool {
    c.is_ascii_uppercase() || c.is_ascii_digit()
}

const GITHUB_HOSTS: &[&str] = &["github.com", "githubusercontent.com", "ghcr.io"];

/// Every shape, in the order of `TOKEN_SHAPES`.
pub const SHAPES: &[Shape] = &[
    Shape {
        id: "github",
        description: "a GitHub token",
        hosts: GITHUB_HOSTS,
        prefixes: &["ghp_", "gho_", "ghu_", "ghs_", "ghr_"],
        lower_label: false,
        body: alnum,
        min: 20,
        max: usize::MAX,
    },
    Shape {
        id: "github",
        description: "a GitHub token",
        hosts: GITHUB_HOSTS,
        prefixes: &["github_pat_"],
        lower_label: false,
        body: alnum_underscore,
        min: 20,
        max: usize::MAX,
    },
    Shape {
        id: "openai-or-anthropic",
        description: "an OpenAI or Anthropic key",
        hosts: &["openai.com", "anthropic.com"],
        prefixes: &["sk-"],
        lower_label: true,
        body: alnum,
        min: 16,
        max: usize::MAX,
    },
    // Anthropic (`sk-ant-api03-…`) and OpenAI project, service-account and
    // admin keys, whose body also holds `-` and `_`.
    Shape {
        id: "openai-or-anthropic",
        description: "an OpenAI or Anthropic key",
        hosts: &["openai.com", "anthropic.com"],
        prefixes: &["sk-ant-", "sk-proj-", "sk-svcacct-", "sk-admin-"],
        lower_label: false,
        body: alnum_underscore_dash,
        min: 16,
        max: usize::MAX,
    },
    Shape {
        id: "aws",
        description: "an AWS access key id",
        hosts: &["amazonaws.com", "amazonaws.com.cn", "aws.amazon.com"],
        prefixes: &["AKIA"],
        lower_label: false,
        body: upper_digit,
        min: 16,
        max: 16,
    },
    Shape {
        id: "slack",
        description: "a Slack token",
        hosts: &["slack.com"],
        prefixes: &["xoxa-", "xoxb-", "xoxp-", "xoxr-", "xoxs-"],
        lower_label: false,
        body: alnum_dash,
        min: 10,
        max: usize::MAX,
    },
    Shape {
        id: "google",
        description: "a Google API key",
        hosts: &["googleapis.com", "google.com"],
        prefixes: &["AIza"],
        lower_label: false,
        body: alnum_underscore_dash,
        min: 30,
        max: usize::MAX,
    },
    Shape {
        id: "npm",
        description: "an npm token",
        hosts: &["npmjs.org", "npmjs.com"],
        prefixes: &["npm_"],
        lower_label: false,
        body: alnum,
        min: 30,
        max: usize::MAX,
    },
    Shape {
        id: "gitlab",
        description: "a GitLab token",
        hosts: &["gitlab.com"],
        prefixes: &["glpat-"],
        lower_label: false,
        body: alnum_underscore_dash,
        min: 20,
        max: usize::MAX,
    },
];

/// The first shape, in [`SHAPES`] order, that occurs in `text`.
#[must_use]
pub fn find(text: &str) -> Option<&'static Shape> {
    shapes_in(text).next()
}

/// Every shape that occurs in `text`.
pub fn shapes_in(text: &str) -> impl Iterator<Item = &'static Shape> {
    let chars: Vec<char> = text.chars().collect();
    SHAPES.iter().filter(move |shape| shape.occurs_in(&chars))
}

impl Shape {
    /// Whether `host` is one of the service's hosts or below one.
    #[must_use]
    pub fn owns(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.hosts.iter().any(|own| {
            host == *own
                || host
                    .strip_suffix(own)
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    }

    fn occurs_in(&self, chars: &[char]) -> bool {
        (0..chars.len()).any(|start| {
            (start == 0 || !is_word(chars[start - 1]))
                && self.prefixes.iter().any(|prefix| {
                    starts_with(&chars[start..], prefix)
                        && self.body_at(chars, start + prefix.chars().count())
                })
        })
    }

    /// Whether the body, after the optional lowercase label, starts at `at`
    /// and ends at a word boundary.
    fn body_at(&self, chars: &[char], at: usize) -> bool {
        let label_end = chars[at..]
            .iter()
            .take_while(|c| c.is_ascii_lowercase())
            .count()
            + at;
        let labelled = (self.lower_label && label_end > at && chars.get(label_end) == Some(&'-'))
            .then_some(label_end + 1);
        labelled
            .into_iter()
            .chain(std::iter::once(at))
            .any(|start| self.run_at(chars, start))
    }

    fn run_at(&self, chars: &[char], start: usize) -> bool {
        let run = chars
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take_while(|c| (self.body)(**c))
            .count();
        (self.min..=run.min(self.max)).any(|len| boundary(chars, start + len))
    }
}

/// Regex `\b`: a word character on exactly one side of `at`.
fn boundary(chars: &[char], at: usize) -> bool {
    let before = at.checked_sub(1).and_then(|i| chars.get(i)).copied();
    before.is_some_and(is_word) != chars.get(at).copied().is_some_and(is_word)
}

/// A word character as the `regex` crate's Unicode `\b` sees one, near enough:
/// letters, digits and `_`.
fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn starts_with(chars: &[char], prefix: &str) -> bool {
    let mut rest = chars.iter();
    prefix.chars().all(|p| rest.next() == Some(&p))
}

#[cfg(test)]
mod tests;
