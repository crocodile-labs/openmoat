//! The `// protection:` marks of the end-to-end tests in
//! `crates/openmoat-cli/tests/e2e/`: what each marked test is evidence of in
//! `docs/PROTECTION.md` (ADR-079 decision 5), as `// coverage: ASI<nn>` marks
//! are for the OWASP table (decision 4).
//!
//! A mark is one line above a `#[test]`:
//!
//! ```text
//! // protection: <claim> <agents> <oses>
//! ```
//!
//! `<claim>` is one of [`Claim::EVERY`]; `<agents>` is `every` (every agent),
//! `installed` (every agent `openmoat init` sets up), `no-own-sandbox` (those
//! of them OpenMoat writes no OS sandbox for) or agent ids joined by commas;
//! `<oses>` is `every` or `linux`, `macos`, `windows` joined by commas. A mark
//! that names an unknown claim, agent or OS, is not followed by a test, or
//! claims an OS the test's `#[cfg]` (or its module's) compiles it out of, is a
//! problem the docs test fails on.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use openmoat_hosts::Host;

use crate::cfg::{Os, Oses, oses_of};

/// The marker a test is tagged with.
pub const MARKER: &str = "// protection:";

/// What a marked test is evidence of: one per column of the matrix that a
/// test can back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Claim {
    /// The real agent ran OpenMoat's hook for a call and the decision held.
    Hook,
    /// The agent's hook payloads, sent to `openmoat guard`, get the verdict in
    /// the agent's own reply format: the adapter, not the agent.
    Payloads,
    /// The real agent did what its hook-failure facts say with a failing hook.
    HookFailure,
    /// The agent's own sandbox, as `openmoat init` writes it, holds against
    /// commands it runs.
    Sandbox,
    /// The agent, or `openmoat run` with its launch shape, holds under the
    /// tier `openmoat run` starts.
    Run,
    /// The agent's MCP servers are pinned or wrapped and checked.
    Mcp,
    /// What a command can read inside `openmoat run`: the logins and the
    /// inherited variables.
    Credentials,
}

impl Claim {
    pub const EVERY: [Claim; 7] = [
        Claim::Hook,
        Claim::Payloads,
        Claim::HookFailure,
        Claim::Sandbox,
        Claim::Run,
        Claim::Mcp,
        Claim::Credentials,
    ];

    /// The name a mark and the weekly job's records (`proves`) spell it with.
    pub fn id(self) -> &'static str {
        match self {
            Claim::Hook => "hook",
            Claim::Payloads => "payloads",
            Claim::HookFailure => "hook-failure",
            Claim::Sandbox => "sandbox",
            Claim::Run => "run",
            Claim::Mcp => "mcp",
            Claim::Credentials => "credentials",
        }
    }

    pub fn of(id: &str) -> Option<Claim> {
        Claim::EVERY.into_iter().find(|c| c.id() == id)
    }
}

/// One marked test: the claim it backs, for which agents on which OSes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    pub claim: Claim,
    pub hosts: Vec<Host>,
    pub oses: Vec<Os>,
    /// `module::test`, from the file's path under `e2e/` and any inline
    /// module.
    pub test: String,
}

/// The agents `spec` names.
fn hosts_of(spec: &str) -> Result<Vec<Host>, String> {
    match spec {
        "every" => Ok(Host::EVERY.to_vec()),
        "installed" => Ok(Host::ALL.to_vec()),
        "no-own-sandbox" => Ok(Host::ALL
            .into_iter()
            .filter(|h| h.spec().sandbox.is_none())
            .collect()),
        list => list
            .split(',')
            .map(|id| {
                Host::EVERY
                    .into_iter()
                    .find(|h| h.id() == id)
                    .ok_or(format!("unknown agent `{id}`"))
            })
            .collect(),
    }
}

/// The OSes `spec` names.
fn oses_of_spec(spec: &str) -> Result<Vec<Os>, String> {
    if spec == "every" {
        return Ok(Os::EVERY.to_vec());
    }
    spec.split(',')
        .map(|id| Os::of(id).ok_or(format!("unknown OS `{id}`")))
        .collect()
}

/// The claim, agents and OSes of a mark's text after [`MARKER`].
fn parse(spec: &str) -> Result<(Claim, Vec<Host>, Vec<Os>), String> {
    let fields: Vec<&str> = spec.split_whitespace().collect();
    let [claim, hosts, oses] = fields[..] else {
        return Err(format!(
            "`{MARKER}` needs `<claim> <agents> <oses>`, got `{}`",
            spec.trim()
        ));
    };
    let claim = Claim::of(claim).ok_or(format!("unknown claim `{claim}`"))?;
    Ok((claim, hosts_of(hosts)?, oses_of_spec(oses)?))
}

/// The OSes in `attrs` (attribute lines) together.
fn oses_of_attrs(attrs: &[String]) -> Oses {
    attrs
        .iter()
        .fold(Oses::ALL, |set, line| set.and(oses_of(line)))
}

/// The name of an inline module a line opens (`pub mod executing {`).
fn inline_module(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    rest.strip_prefix("mod ")?.strip_suffix(" {")
}

/// The name of a module a line declares from another file (`mod run;`).
fn declared_module(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    rest.strip_prefix("mod ")?.strip_suffix(';')
}

/// The name of the function a line starts.
fn function(line: &str) -> Option<&str> {
    let rest = line
        .strip_prefix("pub(crate) ")
        .or_else(|| line.strip_prefix("pub "))
        .unwrap_or(line);
    let rest = rest.strip_prefix("fn ")?;
    rest.split(['(', '<']).next()
}

/// A mark read, waiting for the test below it.
struct Pending {
    line: usize,
    spec: Result<(Claim, Vec<Host>, Vec<Os>), String>,
    is_test: bool,
}

/// The marks of one file's `text`, whose module path is `module` and which
/// compiles on `file_oses`, or why a mark is wrong.
pub fn file_marks(text: &str, module: &str, file_oses: Oses) -> (Vec<Mark>, Vec<String>) {
    let (mut found, mut problems) = (Vec::new(), Vec::new());
    let mut attrs: Vec<String> = Vec::new();
    let mut inline: Vec<(usize, String, Oses)> = Vec::new();
    let mut pending: Option<Pending> = None;
    // A file's own `#![cfg(...)]` narrows all of it.
    let file_oses = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("#![cfg("))
        .fold(file_oses, |set, rest| {
            set.and(oses_of(&format!("#[cfg({rest}")))
        });
    let not_followed = |problems: &mut Vec<String>, at: usize| {
        problems.push(format!(
            "{module}:{at}: `{MARKER}` is not followed by a test"
        ));
    };
    for (n, raw) in (1..).zip(text.lines()) {
        let line = raw.trim();
        let indent = raw.len() - raw.trim_start().len();
        if let Some(spec) = line.strip_prefix(MARKER) {
            if let Some(p) = pending.take() {
                not_followed(&mut problems, p.line);
            }
            pending = Some(Pending {
                line: n,
                spec: parse(spec),
                is_test: false,
            });
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if line.starts_with("#[") {
            if line == "#[test]"
                && let Some(p) = pending.as_mut()
            {
                p.is_test = true;
            }
            attrs.push(line.to_owned());
            continue;
        }
        if let Some(name) = inline_module(line) {
            inline.push((indent, name.to_owned(), oses_of_attrs(&attrs)));
        } else if line == "}" && inline.last().is_some_and(|(at, ..)| *at == indent) {
            inline.pop();
        } else if let (Some(name), Some(p)) = (function(line), pending.as_ref()) {
            let path: Vec<&str> = std::iter::once(module)
                .chain(inline.iter().map(|(_, m, _)| m.as_str()))
                .chain(std::iter::once(name))
                .collect();
            let qualified = path.join("::");
            match (&p.spec, p.is_test) {
                (Err(why), _) => problems.push(format!("{module}:{}: {why}", p.line)),
                (Ok(_), false) => problems.push(format!(
                    "{module}:{}: `{MARKER}` is above `fn {name}`, not a test",
                    p.line
                )),
                (Ok((claim, hosts, oses)), true) => {
                    let compiled = inline
                        .iter()
                        .fold(file_oses.and(oses_of_attrs(&attrs)), |set, (_, _, m)| {
                            set.and(*m)
                        });
                    let out: Vec<&str> = oses
                        .iter()
                        .filter(|os| !compiled.contains(**os))
                        .map(|os| os.id())
                        .collect();
                    if out.is_empty() {
                        found.push(Mark {
                            claim: *claim,
                            hosts: hosts.clone(),
                            oses: oses.clone(),
                            test: qualified,
                        });
                    } else {
                        problems.push(format!(
                            "{qualified}: marked for {} but its `#[cfg]` leaves it out there",
                            out.join(", ")
                        ));
                    }
                }
            }
            pending = None;
        } else if let Some(p) = pending.take() {
            not_followed(&mut problems, p.line);
        }
        attrs.clear();
    }
    if let Some(p) = pending {
        not_followed(&mut problems, p.line);
    }
    (found, problems)
}

/// Every `.rs` file under `dir`, sorted.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
}

/// `e2e/run/strict.rs` as `run::strict`; `e2e/main.rs`, the crate root, as
/// the empty path.
fn module_of(file: &Path, e2e: &Path) -> String {
    let relative = file.strip_prefix(e2e).unwrap().with_extension("");
    let parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    if parts == ["main"] {
        String::new()
    } else {
        parts.join("::")
    }
}

/// `parent::name`, or `name` under the crate root.
fn child(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}::{name}")
    }
}

/// The OSes each module of another file is compiled on, from the `#[cfg]`
/// above its `mod name;` in its parent, the parent's own included.
fn module_oses(files: &[(String, String)]) -> BTreeMap<String, Oses> {
    let mut own = BTreeMap::new();
    for (module, text) in files {
        let mut attrs: Vec<String> = Vec::new();
        for raw in text.lines() {
            if raw.starts_with(char::is_whitespace) {
                attrs.clear();
                continue;
            }
            let line = raw.trim();
            if line.starts_with("#[") {
                attrs.push(line.to_owned());
            } else if !line.starts_with("//") {
                if let Some(name) = declared_module(line) {
                    own.insert(child(module, name), oses_of_attrs(&attrs));
                }
                attrs.clear();
            }
        }
    }
    let mut out = BTreeMap::new();
    for (module, _) in files {
        let mut set = Oses::ALL;
        let mut prefix = String::new();
        for part in module.split("::").filter(|p| !p.is_empty()) {
            prefix = child(&prefix, part);
            set = set.and(own.get(&prefix).copied().unwrap_or(Oses::ALL));
        }
        out.insert(module.clone(), set);
    }
    out
}

/// Every marked end-to-end test under `e2e`, or the problems found.
pub fn marks(e2e: &Path) -> Result<Vec<Mark>, Vec<String>> {
    let mut paths = Vec::new();
    rust_files(e2e, &mut paths);
    assert!(
        !paths.is_empty(),
        "no end-to-end tests in {}",
        e2e.display()
    );
    let files: Vec<(String, String)> = paths
        .iter()
        .map(|p| {
            let text = fs::read_to_string(p).unwrap().replace("\r\n", "\n");
            (module_of(p, e2e), text)
        })
        .collect();
    let compiled = module_oses(&files);
    let (mut found, mut problems) = (Vec::new(), Vec::new());
    for (module, text) in &files {
        let (marks, wrong) = file_marks(text, module, compiled[module]);
        found.extend(marks);
        problems.extend(wrong);
    }
    if problems.is_empty() {
        Ok(found)
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mark_above_a_test_names_its_claim_agents_and_oses() {
        let text = "// protection: sandbox codex linux,macos\n/// Doc.\n#[test]\nfn t() {}\n";
        let (found, problems) = file_marks(text, "differential::codex", Oses::ALL);
        assert_eq!(problems, Vec::<String>::new());
        assert_eq!(
            found,
            [Mark {
                claim: Claim::Sandbox,
                hosts: hosts_of("codex").unwrap(),
                oses: vec![Os::Linux, Os::Mac],
                test: "differential::codex::t".to_owned(),
            }]
        );
    }

    #[test]
    fn a_mark_inside_an_inline_module_carries_its_name_and_cfg() {
        let text = "#[cfg(unix)]\npub mod inner {\n    // protection: run every linux,macos\n    \
                    #[test]\n    fn t() {}\n}\n// protection: run every windows\n#[test]\nfn w() {}\n";
        let (found, problems) = file_marks(text, "m", Oses::ALL);
        assert_eq!(problems, Vec::<String>::new());
        let tests: Vec<&str> = found.iter().map(|m| m.test.as_str()).collect();
        assert_eq!(tests, ["m::inner::t", "m::w"]);
    }

    #[test]
    fn a_mark_cannot_claim_an_os_its_test_is_compiled_out_of() {
        for (text, file) in [
            (
                "// protection: run every every\n#[cfg(target_os = \"linux\")]\n#[test]\nfn t() {}\n",
                Oses::ALL,
            ),
            (
                "// protection: run every windows\n#[test]\nfn t() {}\n",
                oses_of("#[cfg(unix)]"),
            ),
            (
                "#[cfg(unix)]\nmod inner {\n    // protection: run every windows\n    #[test]\n    \
                 fn t() {}\n}\n",
                Oses::ALL,
            ),
        ] {
            let (found, problems) = file_marks(text, "m", file);
            assert_eq!(found, Vec::new(), "{text}");
            assert_eq!(problems.len(), 1, "{text}: {problems:?}");
            assert!(problems[0].contains("leaves it out"), "{problems:?}");
        }
    }

    #[test]
    fn a_wrong_mark_is_a_problem() {
        for text in [
            "// protection: hook codex linux\nfn helper() {}\n",
            "// protection: hook codex linux\nconst X: u8 = 1;\n#[test]\nfn t() {}\n",
            "// protection: hook codex linux\n",
            "// protection: hook codex\n#[test]\nfn t() {}\n",
            "// protection: guesses codex linux\n#[test]\nfn t() {}\n",
            "// protection: hook nobody linux\n#[test]\nfn t() {}\n",
            "// protection: hook codex plan9\n#[test]\nfn t() {}\n",
        ] {
            let (found, problems) = file_marks(text, "m", Oses::ALL);
            assert_eq!(found, Vec::new(), "{text}");
            assert_eq!(problems.len(), 1, "{text:?}: {problems:?}");
        }
    }

    #[test]
    fn a_modules_cfg_comes_from_the_mod_line_in_its_parent() {
        let files = vec![
            (
                String::new(),
                "#[cfg(unix)]\nmod run;\nmod hosts;\n".to_owned(),
            ),
            (
                "run".to_owned(),
                "#[cfg(target_os = \"linux\")]\nmod network;\nmod strict;\n".to_owned(),
            ),
            ("run::network".to_owned(), String::new()),
            ("run::strict".to_owned(), String::new()),
            ("hosts".to_owned(), String::new()),
        ];
        let compiled = module_oses(&files);
        let on = |m: &str| {
            Os::EVERY
                .into_iter()
                .filter(|os| compiled[m].contains(*os))
                .map(Os::id)
                .collect::<Vec<_>>()
        };
        assert_eq!(on("run::network"), ["linux"]);
        assert_eq!(on("run::strict"), ["linux", "macos"]);
        assert_eq!(on("hosts"), ["linux", "macos", "windows"]);
    }
}
