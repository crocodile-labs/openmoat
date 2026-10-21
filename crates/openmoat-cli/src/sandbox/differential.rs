//! The OS backends against the IR's reference semantics.
//!
//! For a set of policies (the default, and ones with braces, classes, `?`,
//! `**` inside braces and `!` exceptions), each backend's output is evaluated
//! on sample paths drawn from the policy's own patterns and compared with
//! [`Checker::check_os`]. Where a backend is wider than the IR, its report must
//! name the place (an allowance whose pattern matches the path); where it is
//! narrower, it must report a loss. A translation that drifts, as the Seatbelt
//! brace translation once did, fails here.

use openmoat_core::ir::{Checker, Effect, Enforcement};
use openmoat_core::{AtomicAction, DEFAULT_POLICY, EvalContext, Kind, Policy};

use super::patterns::Spot;
use super::{Grants, Report, landlock, seatbelt};

const HOME: &str = "/home/me";
const PROJECT: &str = "/home/me/proj";

/// Policies whose patterns use every glob form the backends translate.
const GLOBS: &str = r#"
version: 1
defaults: { "*": deny }
deny:
  - id: keys
    fs.read: ["~/{.ssh/**,.aws/**}", "~/vault/secret-[0-9].txt", "~/notes?.md",
              "${project}/**/*.{pem,key}", "**/.env", "/opt/{a,b/**}/c?[xy]"]
    fs.write: ["${project}/dist/**", "~/.config/{git,fish}/**", "${project}/[!a-z]*.lock"]
allow:
  - id: work
    fs.read: ["${project}/**", "~/src/**", "!~/src/private/**", "/usr/**"]
    fs.write: ["${project}/**", "!${project}/.git/**", "~/out/*.log"]
"#;

const READ_ALL: &str = r#"
version: 1
defaults: { "*": deny, fs.read: allow }
deny:
  - id: secrets
    fs.read: ["~/.ssh/**", "/etc/shadow", "~/{.aws,.azure}/**", "~/.config/*/token?"]
allow:
  - id: work
    fs.write: ["${project}/**", "!${project}/{.git,.github}/**"]
"#;

fn policies() -> [&'static str; 3] {
    [DEFAULT_POLICY, GLOBS, READ_ALL]
}

fn ir(yaml: &str) -> Enforcement {
    let policy = Policy::parse(yaml).expect("test policy lints");
    let ctx = EvalContext {
        home: HOME.into(),
        project: Some(PROJECT.into()),
        real_home: None,
        real_project: None,
        moved_dirs: Vec::new(),
        cwd: PROJECT.into(),
        case_insensitive_paths: false,
    };
    openmoat_core::ir::lower(&policy, &ctx).expect("lowers")
}

fn grants() -> Grants {
    Grants {
        proxy_port: Some(18080),
        tmpdir: Some("/tmp/session".into()),
        program: Some("/home/me/.local/bin/agent".into()),
        writes: vec!["/home/me/.agent".into()],
    }
}

/// `pattern` with each brace group expanded, nested ones too.
fn braces(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('{') else {
        return vec![pattern.to_owned()];
    };
    let (mut depth, mut start, mut options) = (0, open + 1, Vec::new());
    for (i, c) in pattern[open..].char_indices().map(|(i, c)| (i + open, c)) {
        match c {
            '{' => depth += 1,
            ',' if depth == 1 => {
                options.push(&pattern[start..i]);
                start = i + 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    options.push(&pattern[start..i]);
                    let tail = &pattern[i + 1..];
                    return options
                        .iter()
                        .flat_map(|o| braces(&format!("{}{o}{tail}", &pattern[..open])))
                        .collect();
                }
            }
            _ => {}
        }
    }
    vec![pattern.to_owned()]
}

/// Paths a brace-free glob matches and paths just beside it.
fn concrete(glob: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (deep, any) in [("d1/d2", "f"), ("d1", "file.txt")] {
        let mut path = String::new();
        let mut chars = glob.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '*' if chars.peek() == Some(&'*') => {
                    chars.next();
                    path.push_str(deep);
                }
                '*' => path.push_str(any),
                '?' => path.push('q'),
                '[' => {
                    let negated = chars.next_if(|c| matches!(c, '!' | '^')).is_some();
                    let first = chars.next().unwrap_or('x');
                    for c in chars.by_ref() {
                        if c == ']' {
                            break;
                        }
                    }
                    path.push(if negated { '0' } else { first });
                }
                '\\' => path.extend(chars.next()),
                other => path.push(other),
            }
        }
        if !path.starts_with('/') {
            path = format!("{PROJECT}/{path}");
        }
        let parent = path.rsplit_once('/').map(|(p, _)| p.to_owned());
        out.extend([format!("{path}x"), format!("{path}/inner"), path]);
        out.extend(parent.filter(|p| !p.is_empty()));
    }
    out
}

fn samples(ir: &Enforcement) -> Vec<String> {
    let rules = [&ir.fs.read, &ir.fs.write]
        .into_iter()
        .flat_map(|a| a.deny.iter().chain(&a.allow));
    let mut out: Vec<String> = [
        "/",
        "/etc/passwd",
        "/home/me/.ssh/id_rsa",
        "/home/me/.sshx",
        "/home/me/proj/src/main.rs",
        "/home/me/proj/.git/config",
        "/tmp/session/x",
        "/tmp/other",
    ]
    .map(str::to_owned)
    .to_vec();
    for pattern in rules.flat_map(|r| &r.patterns) {
        for glob in braces(pattern.trim_start_matches('!')) {
            out.extend(concrete(&glob));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The engine's reading of one allowance pattern: `*` stops at `/`, and
/// `dir/**` also matches `dir`.
fn allowance_matches(pattern: &str, path: &str) -> bool {
    let glob = |g: &str| {
        globset::GlobBuilder::new(g)
            .literal_separator(true)
            .build()
            .is_ok_and(|g| g.compile_matcher().is_match(path))
    };
    glob(pattern) || pattern.strip_suffix("/**").is_some_and(glob)
}

/// Whether `report` names `path` as a place the backend is wider. Landlock
/// grants trees, so for it (`trees`) a path an allowance lists covers what is
/// below it too.
fn reported_wider(report: &Report, kind: Kind, path: &str, trees: bool) -> bool {
    let kinds = |k: Kind| k == kind || (kind == Kind::FsRead && k == Kind::FsWrite);
    let covers = |p: &str| {
        allowance_matches(p, path)
            || (trees
                && !super::patterns::has_glob(p)
                && allowance_matches(&format!("{p}/**"), path))
    };
    report
        .allowances
        .iter()
        .filter(|a| kinds(a.kind))
        .any(|a| a.patterns.iter().any(|p| covers(p)))
}

fn atom(kind: Kind, path: &str) -> AtomicAction {
    let path = path.to_owned();
    match kind {
        Kind::FsWrite => AtomicAction::FsWrite { path },
        _ => AtomicAction::FsRead { path },
    }
}

/// Every sample on which `backend` and the checker differ, unreported.
fn unreported(
    checker: &Checker,
    report: &Report,
    paths: &[String],
    trees: bool,
    backend: impl Fn(Kind, &str) -> Effect,
) -> Vec<String> {
    let mut out = Vec::new();
    for kind in [Kind::FsRead, Kind::FsWrite] {
        for path in paths {
            let want = checker.check_os(&atom(kind, path));
            let got = backend(kind, path);
            let fine = match (want, got) {
                (Some(w), g) if w == g => true,
                (Some(Effect::Deny), Effect::Allow) => reported_wider(report, kind, path, trees),
                (Some(Effect::Allow), Effect::Deny) => report.losses.iter().any(|l| l.kind == kind),
                _ => false,
            };
            if !fine {
                out.push(format!(
                    "{kind:?} {path}: checker {want:?}, backend {got:?}"
                ));
            }
        }
    }
    out
}

#[test]
fn seatbelt_profiles_decide_as_the_checker() {
    for yaml in policies() {
        let ir = ir(yaml);
        let generated = seatbelt::generate(&ir, &grants());
        let profile = sbpl::parse(&generated.profile);
        let checker = ir.checker().expect("compiles");
        let wrong = unreported(
            &checker,
            &generated.report,
            &samples(&ir),
            false,
            |kind, path| sbpl::effect(&profile, kind, path),
        );
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}

#[test]
fn landlock_grants_are_wider_than_the_checker_only_where_reported() {
    for yaml in policies() {
        let ir = ir(yaml);
        let generated = landlock::generate(&ir, &grants()).expect("generates");
        let rules = &generated.rules;
        let below = |list: &[String], path: &str| {
            list.iter().any(|g| {
                g == "/" || path == g || path.starts_with(&format!("{}/", g.trim_end_matches('/')))
            })
        };
        let checker = ir.checker().expect("compiles");
        let wrong = unreported(
            &checker,
            &generated.report,
            &samples(&ir),
            true,
            |kind, path| {
                let granted = match kind {
                    Kind::FsWrite => below(&rules.write, path),
                    _ => below(&rules.read, path) || below(&rules.write, path),
                };
                if granted { Effect::Allow } else { Effect::Deny }
            },
        );
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }
}

/// The braces in `GLOBS` must reach the samples, or the test checks nothing.
#[test]
fn samples_cover_the_brace_alternatives() {
    let paths = samples(&ir(GLOBS));
    for path in [
        "/home/me/.aws/d1/d2",
        "/home/me/.config/fish/d1",
        "/opt/b/d1/d2/cqx",
        "/home/me/vault/secret-0.txt",
    ] {
        assert!(paths.iter().any(|p| p == path), "{path} not sampled");
    }
}

/// Just enough of SBPL to evaluate the profiles `seatbelt` writes.
mod sbpl {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use openmoat_core::Kind;
    use openmoat_core::ir::Effect;

    thread_local! {
        static REGEXES: RefCell<HashMap<String, regex::Regex>> = RefCell::new(HashMap::new());
    }

    #[derive(Debug)]
    pub enum Node {
        Atom(String),
        Text(String),
        List(Vec<Node>),
    }

    pub fn parse(text: &str) -> Vec<Node> {
        let mut stack: Vec<Vec<Node>> = vec![Vec::new()];
        let mut chars = text.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                ';' => {
                    for c in chars.by_ref() {
                        if c == '\n' {
                            break;
                        }
                    }
                }
                '(' => stack.push(Vec::new()),
                ')' => {
                    let list = stack.pop().expect("balanced");
                    stack.last_mut().expect("balanced").push(Node::List(list));
                }
                '"' => {
                    let mut s = String::new();
                    while let Some(c) = chars.next() {
                        match c {
                            '\\' => s.extend(chars.next()),
                            '"' => break,
                            other => s.push(other),
                        }
                    }
                    stack.last_mut().expect("balanced").push(Node::Text(s));
                }
                c if c.is_whitespace() => {}
                c => {
                    let mut s = String::from(c);
                    while let Some(c) =
                        chars.next_if(|c| !c.is_whitespace() && !"()\";".contains(*c))
                    {
                        s.push(c);
                    }
                    stack.last_mut().expect("balanced").push(Node::Atom(s));
                }
            }
        }
        stack.pop().expect("balanced")
    }

    /// The last rule for `kind`'s operation that matches `path` decides;
    /// `(deny default)` comes first.
    pub fn effect(profile: &[Node], kind: Kind, path: &str) -> Effect {
        let ops: &[&str] = match kind {
            Kind::FsWrite => &["file-write*", "file-write-data"],
            _ => &["file-read*", "file-read-data"],
        };
        let mut effect = Effect::Deny;
        for node in profile {
            let Node::List(items) = node else { continue };
            let Some(Node::Atom(verb)) = items.first() else {
                continue;
            };
            let operations: Vec<&str> = items[1..]
                .iter()
                .filter_map(|n| match n {
                    Node::Atom(a) => Some(a.as_str()),
                    _ => None,
                })
                .collect();
            if !operations.iter().any(|o| ops.contains(o)) {
                continue;
            }
            let filters: Vec<&Node> = items[1..]
                .iter()
                .filter(|n| matches!(n, Node::List(_)))
                .collect();
            if filters.is_empty() || filters.iter().any(|f| matches(f, path)) {
                effect = if verb == "allow" {
                    Effect::Allow
                } else {
                    Effect::Deny
                };
            }
        }
        effect
    }

    fn matches(node: &Node, path: &str) -> bool {
        let Node::List(items) = node else {
            return false;
        };
        let (Some(Node::Atom(head)), rest) = (items.first(), &items[1..]) else {
            return false;
        };
        let text = || match rest.first() {
            Some(Node::Text(t)) => t.as_str(),
            _ => "",
        };
        match head.as_str() {
            "subpath" => {
                let dir = text();
                dir == "/" || path == dir || path.starts_with(&format!("{dir}/"))
            }
            "literal" => path == text(),
            "regex" => REGEXES.with_borrow_mut(|cache| {
                cache
                    .entry(text().to_owned())
                    .or_insert_with(|| {
                        regex::Regex::new(text()).expect("the profile's regex compiles")
                    })
                    .is_match(path)
            }),
            "require-all" => rest.iter().all(|n| matches(n, path)),
            "require-any" => rest.iter().any(|n| matches(n, path)),
            "require-not" => !rest.iter().any(|n| matches(n, path)),
            _ => false,
        }
    }
}

/// Each deny pattern of the IR is in Claude Code's `denyRead`/`denyWrite`
/// (macOS, globs kept), or the report names it.
#[test]
fn claude_code_settings_deny_every_pattern_the_ir_denies_or_report_it() {
    for yaml in policies() {
        let policy = Policy::parse(yaml).expect("test policy lints");
        let ir = super::lower_for_hosts(&policy, HOME, None, Vec::new(), false).expect("lowers");
        let generated = super::claude::generate(&ir, None, false).expect("generates");
        let list = |key: &str| -> Vec<String> {
            generated.sandbox["filesystem"][key]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut missing = Vec::new();
        for (access, key, kind) in [
            (&ir.fs.read, "denyRead", Kind::FsRead),
            (&ir.fs.write, "denyWrite", Kind::FsWrite),
        ] {
            let listed = list(key);
            for rule in &access.deny {
                for pattern in super::patterns::split(&rule.patterns).0 {
                    // `**/x` is written `/**/x`: a relative path would resolve
                    // against `~/.claude`. User settings cannot name the
                    // project, so a project path is denied in every directory.
                    let absolute = match super::patterns::spot(pattern) {
                        Spot::Project("" | "**") => "/".to_owned(),
                        Spot::Project(rest) | Spot::Anywhere(rest) => format!("/**/{rest}"),
                        Spot::Absolute(path) => path.to_owned(),
                    };
                    let bare = absolute.strip_suffix("/**").unwrap_or(&absolute);
                    let named =
                        listed.iter().any(|l| l == &absolute || l == bare)
                            || generated.report.allowances.iter().any(|a| {
                                a.kind == kind && a.patterns.iter().any(|p| p == &absolute)
                            })
                            || generated
                                .report
                                .losses
                                .iter()
                                .any(|l| l.kind == kind && l.rule == rule.id);
                    if !named {
                        missing.push(format!("{key} {} {pattern}", rule.id));
                    }
                }
            }
        }
        assert!(missing.is_empty(), "{}", missing.join("\n"));
    }
}
