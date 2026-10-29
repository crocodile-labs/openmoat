//! A brokered secret's method and path rules (`allow:`, ADR-043): which
//! requests may receive its value, and the request path in the form they are
//! matched against.
//!
//! A rule is `METHOD /path`: the method in capitals, compared exactly, and a
//! path of `/`-separated segments, each a literal, `*` (exactly one non-empty
//! segment) or `**` (any number of segments, none included). The query is not
//! matched.
//!
//! The path a request names is matched as the server reads it: each segment
//! percent-decoded once. A path the server could read as another one is
//! refused instead of matched ([`PathRefusal`]): a `.` or `..` segment in any
//! spelling, an encoded `/` or `\`, a second layer of encoding, a `;` (matrix
//! parameters, Tomcat's `..;`), an empty segment, a byte outside visible
//! ASCII. A request that asks the server to run another method than its own
//! (a [`METHOD_OVERRIDE_HEADERS`] header, a `_method` query parameter) is
//! refused too.

use std::fmt;

/// Most rules one secret may list, and most segments one rule may have: the
/// match costs at most rules × segments × request segments steps.
pub const MAX_ROUTES: usize = 64;
const MAX_SEGMENTS: usize = 64;

/// Headers some frameworks read as the request's real method. A request that
/// carries one is refused for a secret with rules: the server would run a
/// method the rules never saw.
pub const METHOD_OVERRIDE_HEADERS: &[&str] = &[
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// Methods no rule may name.
const ECHOING: &[&str] = &["TRACE", "TRACK", "CONNECT"];

/// The query parameter Rails, Laravel and others read as the real method.
const METHOD_OVERRIDE_PARAMETER: &str = "_method";

/// One `METHOD /path` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    method: String,
    segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    /// `*`: exactly one non-empty segment.
    One,
    /// `**`: zero or more segments.
    Any,
}

impl Route {
    /// Parse `METHOD /path`; the error says what is wrong.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (method, path) = text
            .split_once(' ')
            .ok_or_else(|| format!("rule `{text}` must be `METHOD /path`"))?;
        if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err(format!(
                "rule `{text}`: the method must be capital letters (`GET`, `POST`)"
            ));
        }
        // The answer to `TRACE` is the request as the server got it, value
        // included; `CONNECT` opens a tunnel nothing reads.
        if ECHOING.contains(&method) {
            return Err(format!(
                "rule `{text}`: {method} is never given a secret: the server would send it back \
                 or the proxy could not read what follows"
            ));
        }
        let Some(rest) = path.strip_prefix('/') else {
            return Err(format!("rule `{text}`: the path must start with `/`"));
        };
        let mut segments = Vec::new();
        let parts: Vec<&str> = if rest.is_empty() {
            Vec::new()
        } else {
            rest.split('/').collect()
        };
        for (n, part) in parts.iter().enumerate() {
            let last = n + 1 == parts.len();
            segments.push(match *part {
                "*" => Segment::One,
                "**" => Segment::Any,
                // A rule ending in `/` names the path with its trailing slash.
                "" if last => Segment::Literal(String::new()),
                "" => return Err(format!("rule `{text}`: the path has an empty segment")),
                "." | ".." => return Err(format!("rule `{text}`: `.` and `..` are not segments")),
                literal if literal.bytes().all(is_literal_byte) => {
                    Segment::Literal(literal.to_owned())
                }
                _ => {
                    return Err(format!(
                        "rule `{text}`: a segment is a literal of letters, digits and \
                         `-._~!$&'()+,=:@`, `*` or `**`"
                    ));
                }
            });
        }
        if segments.len() > MAX_SEGMENTS {
            return Err(format!(
                "rule `{text}` has more than {MAX_SEGMENTS} segments"
            ));
        }
        Ok(Self {
            method: method.to_owned(),
            segments,
        })
    }

    /// Whether a `method` request for `path` matches this rule.
    #[must_use]
    pub fn matches(&self, method: &str, path: &RequestPath) -> bool {
        self.method == method && matches(&self.segments, &path.segments)
    }
}

/// Whether `rule` matches `path`: `matched[j]` is true when the first `i`
/// rule segments match the first `j` path segments, one row per rule segment.
fn matches(rule: &[Segment], path: &[String]) -> bool {
    let mut matched = vec![false; path.len() + 1];
    matched[0] = true;
    for segment in rule {
        let mut next = vec![false; path.len() + 1];
        for j in 0..=path.len() {
            next[j] = match segment {
                Segment::Any => matched[j] || (j > 0 && next[j - 1]),
                Segment::One => j > 0 && matched[j - 1] && !path[j - 1].is_empty(),
                Segment::Literal(literal) => j > 0 && matched[j - 1] && path[j - 1] == *literal,
            };
        }
        matched = next;
    }
    matched[path.len()]
}

/// RFC 3986 `pchar` without `%` and `;`: a rule's literal is written decoded.
fn is_literal_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~!$&'()+,=:@".contains(&b)
}

/// The path of a request, decoded segment by segment, and whether its query
/// names a method override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPath {
    segments: Vec<String>,
    overrides_method: bool,
}

/// Why a request's path is refused rather than matched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathRefusal {
    /// Not an origin-form path (`/…`): absolute form, `*`, or empty.
    NotOriginForm,
    /// A byte outside visible ASCII, a `\`, a `#`, or a malformed `%XX`.
    Malformed,
    /// A segment that is, or decodes to, `.` or `..`.
    DotSegment,
    /// A segment that decodes to `/`, `\`, `%`, `;`, a control byte or
    /// invalid UTF-8, or holds a `;`.
    AmbiguousSegment,
    /// `//`: an empty segment before the end.
    EmptySegment,
}

impl fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotOriginForm => "the request target is not a path starting with `/`",
            Self::Malformed => {
                "the path holds a byte outside visible ASCII, a `\\`, a `#` or a malformed `%` \
                 escape"
            }
            Self::DotSegment => "the path holds a `.` or `..` segment, in some spelling",
            Self::AmbiguousSegment => {
                "a path segment holds `;` or decodes to `/`, `\\`, `%`, `;` or a control byte"
            }
            Self::EmptySegment => "the path holds an empty segment (`//`)",
        })
    }
}

impl RequestPath {
    /// The path of `target`, a request line's target, as the server would read
    /// it; refused when the server could read it as another path.
    pub fn parse(target: &str) -> Result<Self, PathRefusal> {
        let Some(rest) = target.strip_prefix('/') else {
            return Err(PathRefusal::NotOriginForm);
        };
        if !target.bytes().all(|b| b.is_ascii_graphic()) || target.contains(['\\', '#']) {
            return Err(PathRefusal::Malformed);
        }
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let parts: Vec<&str> = if path.is_empty() {
            Vec::new()
        } else {
            path.split('/').collect()
        };
        let mut segments = Vec::with_capacity(parts.len());
        for (n, part) in parts.iter().enumerate() {
            if part.is_empty() && n + 1 < parts.len() {
                return Err(PathRefusal::EmptySegment);
            }
            if part.contains(';') {
                return Err(PathRefusal::AmbiguousSegment);
            }
            let decoded = decode(part).ok_or(PathRefusal::Malformed)?;
            let decoded = String::from_utf8(decoded).map_err(|_| PathRefusal::AmbiguousSegment)?;
            if decoded == "." || decoded == ".." {
                return Err(PathRefusal::DotSegment);
            }
            if decoded
                .chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\' | '%' | ';'))
            {
                return Err(PathRefusal::AmbiguousSegment);
            }
            segments.push(decoded);
        }
        let overrides_method = query.split('&').any(|pair| {
            let name = pair.split_once('=').map_or(pair, |(name, _)| name);
            decode(name)
                .is_none_or(|n| n.eq_ignore_ascii_case(METHOD_OVERRIDE_PARAMETER.as_bytes()))
        });
        Ok(Self {
            segments,
            overrides_method,
        })
    }

    /// Whether the query names a `_method` parameter (in any letter case or
    /// encoding), or a parameter name that does not decode.
    #[must_use]
    pub fn overrides_method(&self) -> bool {
        self.overrides_method
    }
}

/// `text` with each `%XX` replaced by its byte; `None` for a malformed escape.
fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Two hex digits exactly: `from_str_radix` would also take `+1`.
            let hex = bytes
                .get(i + 1..i + 3)
                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests;
