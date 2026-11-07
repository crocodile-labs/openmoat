//! Staging (ADR-061, proposed): what a session collected outside the project
//! and packed, and the `@staging-egress <host>` atom a later send of data
//! carries.
//!
//! The caller keeps the session's history (the CLI folds it from the audit log
//! with session taint) and folds [`CompiledPolicy::collection`] over the calls
//! that ran. [`CompiledPolicy::with_staging`] then adds, for each host a send
//! of this call goes to, the atom's decision where a rule of the policy names
//! it, and otherwise only a reason that records it: no default rule names the
//! atom yet, so a policy without one decides exactly as before.

use serde::{Deserialize, Serialize};

use super::{CompiledPolicy, EvalContext, checked_atoms, egress};
use crate::action::{Action, AtomicAction};
use crate::pattern::{GlobPattern, any_match};
use crate::policy::{Policy, PolicyError};
use crate::realpath::PathResolver;
use crate::staging::StagingSettings;
use crate::verdict::{Decision, Verdict};
use crate::{host, paths, shell};

/// First word of the atom a send carries after the session collected or
/// packed files outside the project.
pub const STAGING_ATOM: &str = "@staging-egress";

/// Distinct outside reads kept; a threshold above it is never reached.
const READS_KEPT: usize = 256;
/// Outside folders and staged files kept.
const KEPT: usize = 64;

/// Programs that pack or encode what they read into one file, and how to tell
/// the mode that does (`tar c…`, `gzip -c`, `7z a`).
const PACKERS: &[&str] = &[
    "tar", "bsdtar", "gtar", "zip", "7z", "7za", "7zz", "gzip", "pigz", "xz", "bzip2", "zstd",
    "base64", "base32", "xxd", "openssl", "gpg",
];

/// Words in a tool's name that make an MCP call act rather than read.
const ACTING: &[&str] = &[
    "send", "post", "upload", "create", "write", "put", "publish", "share", "comment", "message",
];

/// What one session collected outside the project, folded from its calls.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Staging {
    /// Distinct files read outside the project, oldest first, at most 256.
    pub reads: Vec<String>,
    /// Distinct folders read outside the project, oldest first, at most 64.
    pub folders: Vec<String>,
    /// Files a packing or encoding command wrote from outside reads, newest
    /// last, at most 64.
    pub staged: Vec<String>,
}

impl Staging {
    /// Add what another call collected.
    pub fn absorb(&mut self, other: Staging) {
        keep(&mut self.reads, other.reads, READS_KEPT, false);
        keep(&mut self.folders, other.folders, KEPT, false);
        keep(&mut self.staged, other.staged, KEPT, true);
    }

    /// The counts a reason ends with, which `openmoat report` reads back.
    fn counts(&self) -> String {
        format!(
            "[outside reads {}, folders {}, staged {}]",
            self.reads.len(),
            self.folders.len(),
            self.staged.len()
        )
    }
}

/// `new` added to `list`, each once, up to `cap`: past it the oldest goes when
/// `newest` (staged files), otherwise the new one is left out (counts only
/// need to reach a threshold).
fn keep(list: &mut Vec<String>, new: Vec<String>, cap: usize, newest: bool) {
    for item in new {
        if let Some(at) = list.iter().position(|known| *known == item) {
            if newest {
                list.remove(at);
                list.push(item);
            }
            continue;
        }
        if list.len() >= cap {
            if !newest {
                continue;
            }
            list.remove(0);
        }
        list.push(item);
    }
}

/// Where a read is not collection: the project, `sandbox.read_roots`, the
/// built-in caches and temporary folders, and `staging.ignore`, compiled for `ctx`.
pub(super) fn compile_inside(
    policy: &Policy,
    ctx: &EvalContext,
) -> Result<Vec<GlobPattern>, PolicyError> {
    let homes: Vec<&str> = [Some(&ctx.home), ctx.real_home.as_ref()]
        .into_iter()
        .flatten()
        .map(|h| h.trim_end_matches('/'))
        .collect();
    // A read root that holds the home directory (a home below `/tmp` in a test
    // sandbox or on a CI runner) would make no read in the home count.
    let holds_home = |root: &str| {
        let root = root.trim_end_matches('/');
        homes
            .iter()
            .any(|h| *h == root || h.starts_with(&format!("{root}/")))
    };
    let roots: Vec<String> = policy
        .sandbox
        .iter()
        .flat_map(|s| &s.read_roots)
        .flat_map(|root| ctx.spellings(root))
        .filter(|root| !holds_home(root.as_str()))
        .flat_map(|root| [format!("{}/**", root.trim_end_matches('/')), root])
        .collect();
    ["${project}".to_owned(), "${project}/**".to_owned()]
        .into_iter()
        .chain(roots)
        .chain(crate::staging::ignored(policy.staging.as_ref()).map(str::to_owned))
        .flat_map(|p| ctx.spellings(&p))
        .map(|p| GlobPattern::compile(&p, ctx.case_insensitive_paths))
        .collect()
}

impl CompiledPolicy<'_> {
    /// What running `action` in `cwd` collected outside the project
    /// (ADR-061): its reads outside it, as files or folders (`is_dir` tells
    /// them apart; the core does no I/O), and, when it read any, the files a
    /// packing or encoding command of it wrote. The caller passes only calls
    /// that ran.
    #[must_use]
    pub fn collection(
        &self,
        action: &Action,
        cwd: &str,
        paths: &dyn PathResolver,
        is_dir: &dyn Fn(&str) -> bool,
    ) -> Staging {
        let ctx = EvalContext {
            cwd: cwd.to_owned(),
            ..self.ctx.clone()
        };
        let (atoms, _) = checked_atoms(action, &ctx, self.opens_as(), paths);
        self.collected(&atoms, &ctx, paths, is_dir)
    }

    /// Each read is kept as the file it resolves to: the checked atoms carry a
    /// path through a symlink both as written and as its target (`/var/…` and
    /// `/private/var/…` on macOS, a short and a long name on Windows), which is
    /// one file read, not two.
    fn collected(
        &self,
        atoms: &[AtomicAction],
        ctx: &EvalContext,
        paths: &dyn PathResolver,
        is_dir: &dyn Fn(&str) -> bool,
    ) -> Staging {
        let mut out = Staging::default();
        for atom in atoms {
            if let AtomicAction::FsRead { path } = atom
                && !any_match(&self.inside, path.as_str())
            {
                let list = if is_dir(path.as_str()) {
                    &mut out.folders
                } else {
                    &mut out.reads
                };
                let file = paths.resolve(path).unwrap_or_else(|| path.clone());
                if !list.contains(&file) {
                    list.push(file);
                }
            }
        }
        if out.reads.is_empty() && out.folders.is_empty() {
            return out;
        }
        let packers: Vec<&[String]> = atoms
            .iter()
            .filter_map(|atom| match atom {
                AtomicAction::Shell { argv } if packs(argv) => Some(argv.as_slice()),
                _ => None,
            })
            .collect();
        if packers.is_empty() {
            return out;
        }
        // what the packer names as its archive, and what the command writes
        // (`base64 x > /tmp/e.txt`, `gzip -c x > x.gz`)
        let named = packers
            .iter()
            .filter_map(|argv| archive_of(argv))
            .map(|archive| paths::normalise(archive, &ctx.home, ctx.project.as_deref(), &ctx.cwd));
        let written = atoms.iter().filter_map(|atom| match atom {
            AtomicAction::FsWrite { path } => Some(path.clone()),
            _ => None,
        });
        for path in named.chain(written) {
            if !out.staged.contains(&path) {
                out.staged.push(path);
            }
        }
        out
    }

    /// `decision` for `action` with the `@staging-egress <host>` atom of each
    /// host a send of it goes to, once `staging` (with what this call itself
    /// collects, when the session already collected any) reached a threshold of the policy's `staging:` section and the
    /// send carries a body, or the send names a staged file. Where a deny or
    /// review rule names the atom, its decision is merged (strictest wins);
    /// otherwise a reason records it and the verdict stays as it was.
    #[must_use]
    pub fn with_staging(
        &self,
        decision: Decision,
        action: &Action,
        paths: &dyn PathResolver,
        staging: &Staging,
        is_dir: &dyn Fn(&str) -> bool,
    ) -> Decision {
        // A session that read nothing outside the project sends nothing it
        // collected; skip classifying the call a second time.
        if staging.reads.is_empty() && staging.folders.is_empty() {
            return decision;
        }
        let (atoms, _) = checked_atoms(action, &self.ctx, self.opens_as(), paths);
        let mut state = staging.clone();
        state.absorb(self.collected(&atoms, &self.ctx, paths, is_dir));
        if state.reads.is_empty() && state.folders.is_empty() {
            return decision;
        }
        let settings = self.policy.staging.as_ref();
        let reached = |count: usize, threshold: u32| {
            threshold > 0 && count >= usize::try_from(threshold).unwrap_or(usize::MAX)
        };
        let collected = reached(
            state.reads.len(),
            StagingSettings::outside_reads_under(settings),
        ) || reached(
            state.folders.len(),
            StagingSettings::outside_folders_under(settings),
        );
        let mut out = decision;
        let mut done: Vec<String> = Vec::new();
        for (hosts, texts, body) in sends(action, &atoms) {
            let staged = self.names_staged(&state, &texts, &atoms);
            if staged.is_none() && !(collected && body) {
                continue;
            }
            for host in hosts {
                if host::is_loopback(&host) || done.contains(&host) {
                    continue;
                }
                let detail = detail(&state, &host, staged.as_deref());
                let atom = AtomicAction::Shell {
                    argv: vec![STAGING_ATOM.to_owned(), host.clone()],
                };
                match self.matched_rules(&atom) {
                    Some(hit) if matches!(hit.verdict, Verdict::Deny | Verdict::Review) => {
                        let mut named = Decision::new(hit.verdict);
                        for rule in &hit.rules {
                            named.push(rule, detail.clone());
                        }
                        out.merge(named);
                    }
                    _ => out
                        .reasons
                        .push(format!("{detail}; recorded only, no rule decides it")),
                }
                done.push(host);
            }
        }
        out
    }

    /// The staged file a send names: a path it reads, or a word of what it
    /// sends (`@/tmp/a.tgz`, `f=@/tmp/a.tgz`, `/tmp/a.tgz`) that is one.
    fn names_staged(
        &self,
        state: &Staging,
        texts: &[&str],
        atoms: &[AtomicAction],
    ) -> Option<String> {
        if state.staged.is_empty() {
            return None;
        }
        let ci = self.ctx.case_insensitive_paths;
        let known = |path: &str| {
            state
                .staged
                .iter()
                .find(|s| {
                    if ci {
                        s.eq_ignore_ascii_case(path)
                    } else {
                        *s == path
                    }
                })
                .cloned()
        };
        let read = atoms.iter().find_map(|atom| match atom {
            AtomicAction::FsRead { path } => known(path.as_str()),
            _ => None,
        });
        read.or_else(|| {
            texts.iter().copied().find_map(|text| {
                let tail = |sep: char| text.rsplit(sep).next().unwrap_or(text);
                [text, tail('@'), tail('=')]
                    .into_iter()
                    .filter(|word| !word.is_empty() && !word.contains("://"))
                    .find_map(|word| {
                        known(
                            paths::normalise(
                                word,
                                &self.ctx.home,
                                self.ctx.project.as_deref(),
                                &self.ctx.cwd,
                            )
                            .as_str(),
                        )
                    })
            })
        })
    }
}

/// Each send of `action`: the hosts it goes to, the text it carries, and
/// whether it carries a body. An MCP call goes to its server
/// (`mcp:<server>`), with the paths it names, and carries a body when it
/// writes or its name acts (`post_message`, `upload_file`).
fn sends<'a>(
    action: &'a Action,
    atoms: &'a [AtomicAction],
) -> Vec<(Vec<String>, Vec<&'a str>, bool)> {
    let mut out: Vec<(Vec<String>, Vec<&'a str>, bool)> = egress::sends(action, atoms)
        .into_iter()
        .filter(|s| !s.hosts.is_empty())
        .map(|s| (s.hosts, s.texts, s.body))
        .collect();
    if let Action::McpTool {
        name,
        reads,
        writes,
        ..
    } = action.shown()
    {
        let server = name.split("__").nth(1).unwrap_or(name);
        let tool = name
            .rsplit("__")
            .next()
            .unwrap_or(name)
            .to_ascii_lowercase();
        let acts = !writes.is_empty() || ACTING.iter().any(|w| tool.contains(w));
        let texts = reads.iter().chain(writes).map(String::as_str).collect();
        out.push((vec![format!("mcp:{server}")], texts, acts));
    }
    out
}

/// The reason for one host: what was sent, what led there, and the counts.
fn detail(state: &Staging, host: &str, staged: Option<&str>) -> String {
    let what = if let Some(file) = staged {
        format!("sends {file}, which this session packed from files outside the project")
    } else {
        let examples: Vec<&str> = state
            .folders
            .iter()
            .chain(&state.reads)
            .take(2)
            .map(String::as_str)
            .collect();
        format!(
            "sends data after this session read {} files and {} folders outside the project, \
             e.g. {}",
            state.reads.len(),
            state.folders.len(),
            examples.join(", ")
        )
    };
    format!("{STAGING_ATOM} {host}: {what} {}", state.counts())
}

/// Whether `argv` packs or encodes into one file: `tar` and its kin in create
/// mode, `zip`, `7z a`, a compressor writing to its output or keeping its
/// input, `base64`, `base32`, `xxd`, `openssl enc` and `gpg -c`.
fn packs(argv: &[String]) -> bool {
    let program = shell::program_name(argv);
    if !PACKERS.contains(&program) {
        return false;
    }
    let words: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    let short = |w: &str, letter: char| {
        w.strip_prefix('-')
            .is_some_and(|rest| !rest.starts_with('-') && rest.contains(letter))
    };
    match program {
        "tar" | "bsdtar" | "gtar" => words.iter().copied().enumerate().any(|(i, w)| {
            w == "--create" || short(w, 'c') || (i == 0 && !w.starts_with('-') && w.contains('c'))
        }),
        "7z" | "7za" | "7zz" => words.first().copied() == Some("a"),
        "gzip" | "pigz" | "xz" | "bzip2" | "zstd" => words.iter().copied().any(|w| {
            matches!(w, "--stdout" | "--keep" | "--to-stdout") || short(w, 'c') || short(w, 'k')
        }),
        "openssl" => words.first().copied() == Some("enc"),
        "gpg" => words
            .iter()
            .copied()
            .any(|w| w == "--symmetric" || short(w, 'c')),
        _ => true,
    }
}

/// The archive a packer writes, when its arguments name it: `tar`'s `-f`
/// (`-czf a.tgz`, `czf a.tgz`, `--file=a.tgz`), `zip`'s first operand, `7z a`'s.
fn archive_of(argv: &[String]) -> Option<&str> {
    let program = shell::program_name(argv);
    let words: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    match program {
        "tar" | "bsdtar" | "gtar" => words.iter().copied().enumerate().find_map(|(i, w)| {
            if let Some(file) = w.strip_prefix("--file=") {
                return Some(file);
            }
            let cluster =
                (w.starts_with('-') && !w.starts_with("--")) || (i == 0 && !w.starts_with('-'));
            if w == "--file" || (cluster && w.ends_with('f')) {
                return words.get(i + 1).copied();
            }
            None
        }),
        "zip" => words.iter().copied().find(|w| !w.starts_with('-')),
        "7z" | "7za" | "7zz" => words.iter().skip(1).copied().find(|w| !w.starts_with('-')),
        _ => None,
    }
}
