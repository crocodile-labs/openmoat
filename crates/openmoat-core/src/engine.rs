//! The decision engine (docs/POLICY.md §4, docs/ARCHITECTURE.md §4).
//!
//! Per atomic action: `deny → allow → review → defaults`. Across the atomic
//! actions of one tool call: strictest verdict wins. Deny rules are absolute;
//! an allow rule can never override a deny, so "deny by default with holes"
//! is expressed through per-kind `defaults`, never through a deny rule.

use std::borrow::Cow;
use std::sync::Arc;

use crate::action::{Action, AtomicAction};
use crate::kind::Kind;
use crate::pattern::{Built, GlobPattern, ShellPattern, Unbuilt, any_match};
use crate::policy::{Policy, PolicyError, RuleGroup};
use crate::programs::{self, NoResolver, ProgramResolver};
use crate::realpath::PathResolver;
use crate::verdict::{Decision, Verdict};

mod aliases;
mod arguments;
mod atoms;
mod contents;
mod context;
mod egress;
mod injection;
mod labels;
mod packages;
mod sections;
mod staging;
mod taint;
mod trifecta;
mod unbuilt;

use atoms::{checked_atoms, value_read_atoms};
#[cfg(test)]
pub(crate) use context::sample_contexts;
pub use labels::{DATA_FLOW_ATOM, Label};
pub(crate) use sections::Section;
pub use staging::{STAGING_ATOM, Staging};
pub use taint::{Secret, Taint, UntrustedKind};
pub use unbuilt::GlobBuilds;

/// Everything the engine needs from the environment. Supplied by the caller.
#[derive(Debug, Clone)]
pub struct EvalContext {
    /// The user's home directory, for `~` and `$HOME`.
    pub home: String,
    /// The trusted project root, for `${project}`. `None` when the session has
    /// no project the caller is willing to trust (it would be the home directory,
    /// one of its ancestors or a filesystem root): every pattern naming
    /// `${project}` then matches nothing, so project-scoped allows do not apply.
    pub project: Option<String>,
    /// `home` with its symlinks resolved, when that differs (a home on a linked
    /// volume, a Windows 8.3 short name). Patterns naming `~` match under both
    /// spellings, since the caller's [`PathResolver`] reports paths in this one.
    pub real_home: Option<String>,
    /// `project` with its symlinks resolved, when that differs (macOS `/tmp` →
    /// `/private/tmp`, `~/code` → `/Volumes/dev/code`). Patterns naming
    /// `${project}` match under both spellings, exclusions included, so a file
    /// in the project is the project's however its path is written. A link
    /// *inside* the project changes nothing here: its target is checked as is.
    pub real_project: Option<String>,
    /// Directories an environment variable moved out of the home directory
    /// (`MOAT_HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `CURSOR_CONFIG_DIR`), as
    /// `(default, moved)` pairs such as `("~/.claude", "/srv/claude")`. A
    /// pattern naming `default` or a path below it also matches the same path
    /// under `moved`, so rules about a host's directory follow it when it moves.
    pub moved_dirs: Vec<(String, String)>,
    /// The directory relative paths are taken from.
    pub cwd: String,
    /// Whether file paths compare case-insensitively, as on the default macOS
    /// and Windows file systems. Host names always do; names never do.
    pub case_insensitive_paths: bool,
}

/// A policy with all patterns compiled for one evaluation context.
///
/// Compile once per process (or per policy reload) and reuse for every tool
/// call; compilation dominates the cost of a single decision. It borrows the
/// policy ([`Self::compile`]) or owns it ([`Self::compile_owned`], for a caller
/// such as `openmoat-sdk` that keeps one engine for as long as it likes).
#[derive(Debug)]
pub struct CompiledPolicy<'p> {
    policy: Cow<'p, Policy>,
    ctx: EvalContext,
    deny: Vec<CompiledGroup>,
    repo_review: Vec<CompiledGroup>,
    allow: Vec<CompiledGroup>,
    review: Vec<CompiledGroup>,
    defer: Vec<CompiledGroup>,
    /// Paths whose writes need review once the session read untrusted content (`taint`).
    protected: Vec<GlobPattern>,
    /// The folders deny rules' paths lie in, which reading or writing needs review for.
    folders: contents::ProtectedFolders,
    /// Where a read is not collection (ADR-061, proposed): the project, read
    /// roots, caches, temporary folders and `staging.ignore`.
    inside: Vec<GlobPattern>,
    /// Every `requests:` entry, for the requests commands send (ADR-062).
    requests: crate::requests::RequestRules,
    /// Paths `taint.private_paths` names, whose reads are private data (ADR-113).
    private: Vec<GlobPattern>,
    /// Set when a glob built on first use did not build (`engine/unbuilt.rs`).
    unbuilt: Arc<Unbuilt>,
}

#[derive(Debug)]
pub(crate) struct CompiledGroup {
    /// The group's id, as decisions name it.
    id: String,
    /// The group's `reason`, which prefixes each of its reasons.
    reason: Option<String>,
    shell: Vec<ShellPattern>,
    /// Glob patterns per kind, indexed by `Kind as usize`; the shell slot is empty.
    globs: [Vec<GlobPattern>; Kind::ALL.len()],
    /// For an allow group, its `net` and `fetch` patterns without the
    /// `host:port` ones ([`crate::host::port_pattern`]), which a host without a
    /// port is matched against: `*:8443` allows port 8443 of every host to the
    /// proxy, and must not also match an IPv6 address whose text ends in
    /// `:8443`. Deny and review rules keep them: there they only refuse more.
    bare_hosts: Option<[Vec<GlobPattern>; Kind::ALL.len()]>,
    /// The group's `when` conditions (ADR-113): such a group matches no atom
    /// on its own, only a call in [`CompiledPolicy::with_arguments`].
    when: Option<arguments::CompiledWhen>,
}

/// Whether `pattern` is a `net` or `fetch` pattern written `host:port`, not an
/// exclusion.
fn names_port(pattern: &str) -> bool {
    !pattern.starts_with('!') && crate::host::port_pattern(pattern).is_some()
}

impl<'p> CompiledPolicy<'p> {
    /// Compile every pattern of `policy` for `ctx`. Fails on a pattern that does
    /// not compile, and on a `moved_dirs` entry whose `default` could alias every
    /// pattern (empty, bare `/`, or not an absolute or `~/`-rooted directory).
    ///
    /// A glob whose text cannot fail to parse is built when a call first needs
    /// it (ADR-132); every other is built here, so every compile error comes
    /// from here as before.
    pub fn compile(policy: &'p Policy, ctx: &EvalContext) -> Result<Self, PolicyError> {
        Self::build(Cow::Borrowed(policy), ctx, GlobBuilds::OnFirstUse)
    }

    /// [`Self::compile`] for a policy the result keeps, so it borrows nothing.
    pub fn compile_owned(
        policy: Policy,
        ctx: &EvalContext,
    ) -> Result<CompiledPolicy<'static>, PolicyError> {
        CompiledPolicy::build(Cow::Owned(policy), ctx, GlobBuilds::OnFirstUse)
    }

    fn build(
        policy: Cow<'p, Policy>,
        ctx: &EvalContext,
        builds: GlobBuilds,
    ) -> Result<Self, PolicyError> {
        ctx.validate_moved_dirs()?;
        // Each text the policy names is built once (`pattern/built.rs`).
        let unbuilt = Arc::<Unbuilt>::default();
        let mut built = builds.store(&unbuilt);
        let mut compile_list = |groups: &[RuleGroup], allow: bool| {
            groups
                .iter()
                .map(|g| CompiledGroup::compile(g, ctx, allow, &mut built))
                .collect::<Result<Vec<_>, _>>()
        };
        let deny = compile_list(&policy.deny, false)?;
        let repo_review = compile_list(&policy.repo_review, false)?;
        let allow = compile_list(&policy.allow, true)?;
        let review = compile_list(&policy.review, false)?;
        let defer = compile_list(&policy.defer, false)?;
        // From the spellings the deny groups were compiled with.
        let folders = contents::ProtectedFolders::compile(&deny, ctx);
        Ok(Self {
            ctx: ctx.clone(),
            deny,
            repo_review,
            allow,
            review,
            defer,
            protected: taint::compile_protected(&policy, ctx, &mut built)?,
            folders,
            inside: staging::compile_inside(&policy, ctx, &mut built)?,
            requests: crate::requests::RequestRules::for_hook(&policy.requests)?,
            private: taint::compile_private(&policy, ctx, &mut built)?,
            policy,
            unbuilt,
        })
    }

    /// The policy this was compiled from.
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The context this was compiled for.
    #[must_use]
    pub fn context(&self) -> &EvalContext {
        &self.ctx
    }

    /// Evaluate one atomic action: deny → allow → review → defer → default, with a
    /// repository policy's review rules ([`Policy::repo_review`]) tried before allow.
    ///
    /// A repository review never softens what the user's policy alone decides
    /// for the atom: per atom the result is the stricter of the two (ADR-022),
    /// so a repository's `review: [{net: ['*']}]` leaves a host the `net: deny`
    /// default refuses denied.
    ///
    /// Returns `None` for a whole-pipeline atom that no rule mentions: pipelines
    /// are only there so rules like `curl * | sh` can see across `|`; the
    /// per-sub-command atoms carry the default verdict.
    ///
    /// Once a glob of this compile did not build, the `kernel-error` deny
    /// (`engine/unbuilt.rs`).
    #[must_use]
    pub fn evaluate_atomic(&self, action: &AtomicAction) -> Option<Decision> {
        let decided = self.atomic(action);
        self.failed().or(decided)
    }

    /// [`Self::evaluate_atomic`] before the failure mark is read.
    fn atomic(&self, action: &AtomicAction) -> Option<Decision> {
        if let Some(deny) = Self::hit(&self.deny, Verdict::Deny, action) {
            return Some(deny);
        }
        let own = self.own_rules(action).or_else(|| {
            (!matches!(action, AtomicAction::Pipeline { .. })).then(|| {
                let (verdict, rule_id) = self.policy.defaults.for_atom(action);
                Decision::single(
                    verdict,
                    &rule_id,
                    format!("no rule matched {}", action.describe()),
                )
            })
        });
        match Self::hit(&self.repo_review, Verdict::Review, action) {
            Some(repo) => Some(match own {
                Some(own) if own.verdict > repo.verdict => own,
                _ => repo,
            }),
            None => own,
        }
    }

    /// The first of deny, repository review, allow, review and defer whose rules
    /// match `action`, with every matching rule; `None` when no rule does.
    fn matched_rules(&self, action: &AtomicAction) -> Option<Decision> {
        Self::hit(&self.deny, Verdict::Deny, action)
            .or_else(|| Self::hit(&self.repo_review, Verdict::Review, action))
            .or_else(|| self.own_rules(action))
    }

    /// The first of the user's allow, review and defer lists whose rules match.
    fn own_rules(&self, action: &AtomicAction) -> Option<Decision> {
        Self::hit(&self.allow, Verdict::Allow, action)
            .or_else(|| Self::hit(&self.review, Verdict::Review, action))
            .or_else(|| Self::hit(&self.defer, Verdict::Defer, action))
    }

    /// `verdict` with every group of `groups` that matches `action`; `None`
    /// when none does.
    fn hit(groups: &[CompiledGroup], verdict: Verdict, action: &AtomicAction) -> Option<Decision> {
        let mut hit = Decision::new(verdict);
        for g in groups.iter().filter(|g| g.matches(action)) {
            let why = g.reason.as_ref().map_or_else(
                || action.describe(),
                |r| format!("{r}: {}", action.describe()),
            );
            hit.push(&g.id, why);
        }
        (!hit.rules.is_empty()).then_some(hit)
    }
}

impl CompiledGroup {
    /// `allow` says whether the group is an allow rule ([`Self::bare_hosts`]);
    /// `built`, the globs this compile built so far.
    fn compile(
        group: &RuleGroup,
        ctx: &EvalContext,
        allow: bool,
        built: &mut Built,
    ) -> Result<Self, PolicyError> {
        let shell = group
            .shell
            .iter()
            .map(|p| ShellPattern::compile_in(p, built))
            .collect::<Result<_, _>>()?;
        let mut globs: [Vec<GlobPattern>; Kind::ALL.len()] = Default::default();
        let mut bare: [Vec<GlobPattern>; Kind::ALL.len()] = Default::default();
        for kind in Kind::ALL.into_iter().filter(|k| *k != Kind::Shell) {
            let case_insensitive = match kind {
                Kind::FsRead | Kind::FsWrite => ctx.case_insensitive_paths,
                Kind::Net | Kind::Fetch => true,
                _ => false,
            };
            let mut compile = |patterns: &mut dyn Iterator<Item = &String>| {
                patterns
                    .flat_map(|p| ctx.spellings(p))
                    .map(|p| GlobPattern::compile_in(&p, case_insensitive, built))
                    .collect::<Result<Vec<_>, _>>()
            };
            let patterns = group.patterns(kind);
            globs[kind as usize] = compile(&mut patterns.iter())?;
            if matches!(kind, Kind::Net | Kind::Fetch) {
                bare[kind as usize] = compile(&mut patterns.iter().filter(|p| !names_port(p)))?;
            }
        }
        Ok(Self {
            id: group.id.clone(),
            reason: group.reason.clone(),
            shell,
            globs,
            bare_hosts: allow.then_some(bare),
            when: arguments::CompiledWhen::compile(&group.when, ctx, built)?,
        })
    }

    /// Whether the group matches `action` on its own: never for a group with
    /// `when` conditions, which only a whole call can satisfy.
    fn matches(&self, action: &AtomicAction) -> bool {
        self.when.is_none() && self.matches_patterns(action)
    }

    /// Whether one of the group's patterns matches `action`.
    fn matches_patterns(&self, action: &AtomicAction) -> bool {
        match (action, action.subject()) {
            (AtomicAction::Shell { argv } | AtomicAction::Pipeline { argv }, _) => {
                any_match(&self.shell, argv.as_slice())
            }
            (_, Some(subject)) => {
                let globs = match &self.bare_hosts {
                    Some(bare)
                        if matches!(
                            action,
                            AtomicAction::Net { .. } | AtomicAction::Fetch { .. }
                        ) && crate::host::port_pattern(subject).is_none() =>
                    {
                        bare
                    }
                    _ => &self.globs,
                };
                action
                    .kind()
                    .rule_kinds()
                    .iter()
                    .any(|k| any_match(&globs[*k as usize], subject))
            }
            (_, None) => false,
        }
    }
}

impl CompiledPolicy<'_> {
    /// Decide one host action without executable resolution.
    ///
    /// Unparseable input yields the policy's catch-all verdict (`review` or
    /// `defer`) with the parser's reason, never `allow`.
    #[must_use]
    pub fn decide(&self, action: &Action) -> Decision {
        self.decide_with(action, &NoResolver, &NoResolver)
    }

    /// The atomic actions [`Self::decide_with`] evaluates for `action`, with an
    /// extra atom for every path an unquoted glob operand names in the
    /// directories `paths` lists, and for every read or write `paths` resolves
    /// through a symlink; and the reason when part of the action cannot be
    /// classified or a glob not expanded in full (`review`).
    #[must_use]
    pub fn atoms(
        &self,
        action: &Action,
        paths: &dyn PathResolver,
    ) -> (Vec<AtomicAction>, Option<String>) {
        let (atoms, unparsed) = self.all_atoms(action, paths);
        (atoms, unparsed.map(|u| u.reason))
    }

    /// [`checked_atoms`] and the atoms of any token or placeholder they send
    /// where it does not belong ([`egress`]), and of personal data and
    /// unprefixed credentials they send that a rule of this policy names (ADR-052).
    fn all_atoms(
        &self,
        action: &Action,
        paths: &dyn PathResolver,
    ) -> (Vec<AtomicAction>, Option<crate::shell::Unparsed>) {
        let (mut atoms, unparsed) = checked_atoms(action, &self.ctx, self.opens_as(), paths);
        let egress = egress::atoms(action, &atoms, &self.policy.secrets)
            .into_iter()
            .filter(|atom| !egress::counts_where_named(atom) || self.matched_rules(atom).is_some())
            // data in a host name counts only on its way to a host no rule allows (ADR-123)
            .filter(|atom| egress::host_data(atom).is_none_or(|host| !self.allows_host(host)));
        atoms.extend(egress);
        (atoms, unparsed)
    }

    /// Whether an allow rule of the policy lists `host` for a connection.
    fn allows_host(&self, host: &str) -> bool {
        let net = AtomicAction::Net {
            host: host.to_owned(),
        };
        self.matched_rules(&net)
            .is_some_and(|d| d.verdict == Verdict::Allow)
    }

    /// How a read-only page open is decided under this policy (ADR-047).
    fn opens_as(&self) -> atoms::Opens {
        atoms::Opens {
            as_fetch: self.policy.browser_open_is_fetch(),
        }
    }

    /// The commands of `action` that publish local commits (`git push`, `gh pr
    /// create`), each with the directories it may run in. Only a shell command
    /// has any.
    #[must_use]
    pub fn pushes(&self, action: &Action) -> Vec<crate::shell::push::Push> {
        let Action::Shell { command } = action.shown() else {
            return Vec::new();
        };
        crate::shell::push::pushes(
            command,
            &crate::shell::ShellContext {
                home: &self.ctx.home,
                cwd: &[Some(self.ctx.cwd.clone())],
            },
        )
    }

    /// The files `action` runs as code (ADR-039): a script an interpreter or a
    /// shell runs (`python3 x.py`, `bash x.sh`, `source x`), a file it loads
    /// first (`node -r ./x.js`) and a program named by a path (`./x`), through
    /// every wrapper the classifier unwraps (`env`, `time`, `bash -c '…'`), as
    /// canonical paths, each also as `paths` resolves it through a symlink.
    /// Only a shell command runs any; a test runner, build tool or package
    /// script (`pytest`, `npm test`, `go run .`) names none.
    #[must_use]
    pub fn executed(&self, action: &Action, paths: &dyn PathResolver) -> Vec<String> {
        let Action::Shell { command } = action.shown() else {
            return Vec::new();
        };
        atoms::executed_files(command, &self.ctx, paths)
    }

    /// Decide one host action, resolving shell programs through `resolver` so
    /// that `executables` pins and installation pins are enforced, and paths
    /// through `paths` so a symlink cannot move a read or write past a rule.
    #[must_use]
    pub fn decide_with(
        &self,
        action: &Action,
        resolver: &dyn ProgramResolver,
        paths: &dyn PathResolver,
    ) -> Decision {
        let (atoms, unparsed) = self.all_atoms(action, paths);
        // a runner's package the project installed or declared (ADR-102)
        let atoms = packages::on_hand(atoms, &self.ctx, resolver);
        let pins = atoms.iter().filter_map(|atom| match atom {
            AtomicAction::Shell { argv } => {
                programs::check(&argv[0], &self.policy.executables, resolver)
            }
            _ => None,
        });
        // Another spelling of a command (OpenMoat's binary under another name
        // or case) adds the deny or review its rules give, and nothing else.
        let aliased = aliases::aliases(&atoms, &self.ctx, resolver, paths)
            .into_iter()
            .filter_map(|atom| self.matched_rules(&atom))
            .filter(|hit| matches!(hit.verdict, Verdict::Deny | Verdict::Review));
        // A path only an MCP argument's value looks like, under a key the
        // adapter does not know, adds the deny its read would get and nothing
        // else: no new review or defer for a value that is not a path.
        let value_reads = value_read_atoms(action, &self.ctx, paths)
            .into_iter()
            .filter_map(|atom| Self::hit(&self.deny, Verdict::Deny, &atom));
        // A part that could not be parsed, or arguments the adapter did not
        // search, may name anything: never allow (defer or review, ADR-025), and let
        // a deny on the rest still win. A line not read in full, or one past a
        // classifier limit, needs review: a deny in what was not read must not defer.
        let verdict = self.policy.defaults.unclassified();
        let unparsed = unparsed.map(|u| {
            let verdict = if u.needs_review {
                Verdict::Review
            } else {
                verdict
            };
            unparseable(
                verdict,
                format!("could not parse action safely: {}", u.reason),
            )
        });
        let unchecked = match action.shown() {
            Action::McpTool {
                unchecked: Some(limit),
                ..
            } => Some(unparseable(
                verdict,
                format!("mcp arguments not fully checked: {limit}"),
            )),
            _ => None,
        };
        // What the payload does not show may be anything: at least `review`.
        let partial = match action {
            Action::Unchecked { reason, .. } => Some(Decision::single(
                Verdict::Review,
                crate::rule_id::UNCHECKED,
                reason.clone(),
            )),
            _ => None,
        };
        // A folder holding paths a deny rule names needs review, whatever allows it (ADR-038).
        let folders = atoms.iter().filter_map(|atom| self.folders.decide(atom));
        // The requests a command or fetch tool sends to a `requests:` host
        // (ADR-062): a deny or a review, never an allow.
        let requests = crate::requests::hook::decisions(&self.requests, action, &atoms);
        let decided = atoms
            .iter()
            .filter_map(|atom| self.atomic(atom))
            .chain(folders)
            .chain(requests)
            .chain(aliased)
            .chain(value_reads)
            .chain(pins)
            .chain(unparsed)
            .chain(unchecked)
            .chain(partial)
            .reduce(|mut acc, next| {
                acc.merge(next);
                acc
            })
            .unwrap_or_else(|| unparseable(verdict, "action has no evaluable parts".to_owned()));
        // Last, once every glob the decision needed was asked (ADR-132).
        self.checked(decided)
    }
}

/// Input that cannot be classified: the policy's catch-all, never `allow` (ADR-025).
fn unparseable(verdict: Verdict, reason: String) -> Decision {
    Decision::single(verdict, crate::rule_id::UNPARSEABLE, reason)
}

/// Compile `policy` for `ctx` and decide a single action.
///
/// Convenience for one-shot callers; long-lived callers should keep a
/// [`CompiledPolicy`] instead.
pub fn evaluate(
    policy: &Policy,
    ctx: &EvalContext,
    action: &Action,
) -> Result<Decision, PolicyError> {
    Ok(CompiledPolicy::compile(policy, ctx)?.decide(action))
}

#[cfg(test)]
mod tests;
