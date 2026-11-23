//! The symbolic half of the never-widen check (ADR-111): for each atom kind a
//! glob decides (file reads and writes, hosts, fetches, environment names,
//! MCP tools), search every string for one the new policy decides less
//! strictly than the old one.
//!
//! Each pattern of both policies is read as an automaton over bytes
//! (`nfa.rs`); the search walks their product breadth first, one byte class
//! at a time, and at every state computes both policies' verdict exactly as
//! `CompiledPolicy::evaluate_atomic` does (deny, repository review, allow,
//! review, defer, default; strictest of own and repository review). The walk
//! is finite: when it ends without such a state, no subject of that kind
//! widens, for this evaluation context. A state that widens gives the
//! shortest string reaching it, which the real engine then decides: only a
//! confirmed string is reported as a widening.
//!
//! One part is approximated on the safe side: an allow rule's `host:port`
//! patterns apply to a host only when it is written with a port. The search
//! lets the new policy's allow rules use them always and the old policy's
//! never, so it can only find more; a string the engine does not confirm
//! leaves the kind not proven instead of reported. Groups with `when`
//! conditions (ADR-113) are read the same way: the old policy's as if their
//! conditions held, the new policy's as absent (`conditional.rs`), so a
//! proven kind holds whatever arguments a call passes.

use std::collections::{BTreeSet, HashMap, VecDeque};

use super::nfa::{Bytes, Nfa, Unsupported};
use super::{Outcome, Widening, WideningSource};
use crate::action::AtomicAction;
use crate::engine::{CompiledPolicy, Section};
use crate::kind::Kind;
use crate::verdict::Verdict;
use conditional::{Role, Shared};

mod conditional;
mod differing;

/// Most product states one search visits before it gives up unproven.
const MAX_STATES: usize = 250_000;
/// Most widenings one search reports: one per distinct pair of deciding rules.
const MAX_FOUND: usize = 16;
/// Once a widening is found, at most this many more states are visited for
/// widenings with other rules: the kind widens either way.
const MORE_AFTER_FOUND: usize = 20_000;
/// Most states of one pattern's automaton visited to tell whether it accepts
/// every continuation; past it, it is taken as not doing so (no pruning).
const MAX_UNIVERSAL_STATES: usize = 64;

/// The atoms whose subject a glob decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Target {
    Read,
    Write,
    Net,
    NetWord,
    Fetch,
    EnvRead,
    EnvSet,
    Mcp,
}

impl Target {
    pub(super) const ALL: [Self; 8] = [
        Self::Read,
        Self::Write,
        Self::Net,
        Self::NetWord,
        Self::Fetch,
        Self::EnvRead,
        Self::EnvSet,
        Self::Mcp,
    ];

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Read => "fs.read",
            Self::Write => "fs.write",
            Self::Net => "net",
            Self::NetWord => "net (a word that looks like a host)",
            Self::Fetch => "fetch",
            Self::EnvRead => "env.read",
            Self::EnvSet => "env.set",
            Self::Mcp => "mcp",
        }
    }

    pub(super) fn atom(self, subject: String) -> AtomicAction {
        match self {
            Self::Read => AtomicAction::FsRead { path: subject },
            Self::Write => AtomicAction::FsWrite { path: subject },
            Self::Net => AtomicAction::Net { host: subject },
            Self::NetWord => AtomicAction::NetWord { host: subject },
            Self::Fetch => AtomicAction::Fetch { host: subject },
            Self::EnvRead => AtomicAction::EnvRead { name: subject },
            Self::EnvSet => AtomicAction::EnvSet { name: subject },
            Self::Mcp => AtomicAction::McpTool { name: subject },
        }
    }

    fn kind(self) -> Kind {
        self.atom(String::new()).kind()
    }

    /// Whether allow rules match this atom with their port-less patterns.
    fn bare(self) -> bool {
        matches!(self, Self::Net | Self::Fetch)
    }
}

/// One pattern list of a group for one rule kind: matches when a positive
/// pattern does and no exclusion does.
struct List {
    pos: Vec<usize>,
    neg: Vec<usize>,
}

struct Group {
    id: String,
    lists: Vec<List>,
    bare: Option<Vec<List>>,
}

/// A policy's lists for one target, as matcher indices.
struct Side {
    sections: Vec<(Section, Vec<Group>)>,
    default: Verdict,
}

/// Every distinct pattern of both policies, as automata.
#[derive(Default)]
struct Matchers {
    nfas: Vec<Nfa>,
    index: HashMap<String, usize>,
}

impl Matchers {
    fn list(&mut self, globs: &[crate::pattern::GlobPattern]) -> Result<List, Unsupported> {
        let mut list = List {
            pos: Vec::new(),
            neg: Vec::new(),
        };
        for glob in globs {
            let key: Vec<&str> = glob.regexes().collect();
            let key = key.join("\0");
            let at = if let Some(&at) = self.index.get(&key) {
                at
            } else {
                self.nfas.push(Nfa::union(glob.regexes())?);
                self.index.insert(key, self.nfas.len() - 1);
                self.nfas.len() - 1
            };
            if glob.negated {
                list.neg.push(at);
            } else {
                list.pos.push(at);
            }
        }
        Ok(list)
    }

    /// `policy`'s lists for `target`, its `when` groups placed for `role`
    /// (`conditional.rs`).
    fn side(
        &mut self,
        policy: &CompiledPolicy<'_>,
        target: Target,
        role: Role,
        shared: &Shared,
    ) -> Result<Side, Unsupported> {
        let kind = target.kind();
        let mut sections: Vec<(Section, Vec<Group>)> =
            Section::ALL.iter().map(|s| (*s, Vec::new())).collect();
        for section in Section::ALL {
            for g in policy.section(section) {
                let Some(place) = shared.place(role, section, g) else {
                    continue;
                };
                let lists = kind
                    .rule_kinds()
                    .iter()
                    .map(|k| self.list(g.globs(*k)))
                    .collect::<Result<_, _>>()?;
                let bare = match (target.bare(), place) {
                    (true, Section::Allow) => Some(
                        kind.rule_kinds()
                            .iter()
                            .map(|k| self.list(g.bare_globs(*k).unwrap_or_default()))
                            .collect::<Result<_, _>>()?,
                    ),
                    _ => None,
                };
                let group = Group {
                    id: g.id().to_owned(),
                    lists,
                    bare,
                };
                if let Some((_, groups)) = sections.iter_mut().find(|(s, _)| *s == place) {
                    groups.push(group);
                }
            }
        }
        let probe = target.atom("\u{0}".to_owned());
        Ok(Side {
            sections,
            default: policy.policy().defaults.for_atom(&probe).0,
        })
    }
}

/// Where one matcher stands at a product state: it can no longer match,
/// it may, or it matches whatever follows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Live {
    Dead,
    Alive,
    Always,
}

impl Side {
    fn groups(&self, section: Section) -> impl Iterator<Item = &Group> {
        self.sections
            .iter()
            .filter(move |(s, _)| *s == section)
            .flat_map(|(_, groups)| groups)
    }

    /// Whether `g` may still match some continuation.
    fn alive(g: &Group, live: &dyn Fn(usize) -> Live) -> bool {
        g.lists
            .iter()
            .chain(g.bare.iter().flatten())
            .any(|l| l.pos.iter().any(|m| live(*m) != Live::Dead))
    }

    /// Whether `g` matches every continuation (never for a group whose
    /// `host:port` patterns are approximated).
    fn always(g: &Group, live: &dyn Fn(usize) -> Live) -> bool {
        g.bare.is_none()
            && g.lists.iter().any(|l| {
                l.pos.iter().any(|m| live(*m) == Live::Always)
                    && l.neg.iter().all(|m| live(*m) == Live::Dead)
            })
    }

    /// The least verdict any continuation can get.
    fn lowest(&self, live: &dyn Fn(usize) -> Live) -> Verdict {
        let always = |s| self.groups(s).any(|g| Self::always(g, live));
        let alive = |s| self.groups(s).any(|g| Self::alive(g, live));
        if always(Section::Deny) {
            Verdict::Deny
        } else if always(Section::RepoReview) || (!alive(Section::Allow) && always(Section::Review))
        {
            Verdict::Review
        } else {
            Verdict::Allow
        }
    }

    /// The greatest verdict any continuation can get.
    fn highest(&self, live: &dyn Fn(usize) -> Live) -> Verdict {
        let alive = |s| self.groups(s).any(|g| Self::alive(g, live));
        if alive(Section::Deny) || alive(Section::RepoReview) {
            return Verdict::Deny;
        }
        if self.groups(Section::Allow).any(|g| Self::always(g, live)) {
            return Verdict::Allow;
        }
        let mut most = self.default;
        if alive(Section::Review) {
            most = most.max(Verdict::Review);
        }
        if alive(Section::Defer) {
            most = most.max(Verdict::Defer);
        }
        most
    }

    /// The verdict for a subject the matchers in `accepted` match, and the
    /// ids of the groups that decided it. `wide` reads an allow rule's
    /// `host:port` patterns as matching (the new policy), else as not.
    fn verdict(&self, accepted: &BTreeSet<usize>, wide: bool) -> (Verdict, Vec<String>) {
        let list = |l: &List| {
            l.pos.iter().any(|m| accepted.contains(m))
                && !l.neg.iter().any(|m| accepted.contains(m))
        };
        let hits = |section: Section| -> Vec<String> {
            self.sections
                .iter()
                .filter(|(s, _)| *s == section)
                .flat_map(|(_, groups)| groups)
                .filter(|g| {
                    let full = g.lists.iter().any(list);
                    match &g.bare {
                        None => full,
                        Some(bare) if wide => full || bare.iter().any(list),
                        Some(bare) => full && bare.iter().any(list),
                    }
                })
                .map(|g| g.id.clone())
                .collect()
        };
        let deny = hits(Section::Deny);
        if !deny.is_empty() {
            return (Verdict::Deny, deny);
        }
        let own = [
            (Section::Allow, Verdict::Allow),
            (Section::Review, Verdict::Review),
            (Section::Defer, Verdict::Defer),
        ]
        .into_iter()
        .map(|(s, v)| (v, hits(s)))
        .find(|(_, ids)| !ids.is_empty())
        .unwrap_or((self.default, vec!["default".to_owned()]));
        let repo = hits(Section::RepoReview);
        if !repo.is_empty() && own.0 <= Verdict::Review {
            return (Verdict::Review, repo);
        }
        own
    }
}

/// Each matcher's automaton made deterministic as the search reaches its
/// states. State 0 is the empty set: the matcher can no longer match.
struct Local {
    sets: Vec<Vec<usize>>,
    ids: HashMap<Vec<usize>, u32>,
    next: Vec<Vec<u32>>,
    accept: Vec<bool>,
}

impl Local {
    fn new(nfa: &Nfa, classes: usize) -> Self {
        let mut local = Self {
            sets: Vec::new(),
            ids: HashMap::new(),
            next: Vec::new(),
            accept: Vec::new(),
        };
        local.id(nfa, Vec::new(), classes);
        let mut start = vec![0];
        nfa.closure(&mut start);
        local.id(nfa, start, classes);
        local
    }

    fn id(&mut self, nfa: &Nfa, set: Vec<usize>, classes: usize) -> u32 {
        if let Some(&id) = self.ids.get(&set) {
            return id;
        }
        let id = u32::try_from(self.sets.len()).unwrap_or(u32::MAX);
        self.accept.push(set.contains(&nfa.accept));
        self.ids.insert(set.clone(), id);
        self.sets.push(set);
        self.next.push(vec![u32::MAX; classes]);
        id
    }

    /// Whether `state` and every state after it accepts: the pattern matches
    /// whatever follows. Undecided past [`MAX_UNIVERSAL_STATES`] states: no.
    fn universal(&mut self, nfa: &Nfa, state: u32, reps: &[u8]) -> bool {
        let mut seen = vec![state];
        let mut todo = vec![state];
        while let Some(s) = todo.pop() {
            if !self.accept[s as usize] {
                return false;
            }
            for (class, &byte) in reps.iter().enumerate() {
                let next = self.step(nfa, s, class, byte);
                if !seen.contains(&next) {
                    if seen.len() >= MAX_UNIVERSAL_STATES {
                        return false;
                    }
                    seen.push(next);
                    todo.push(next);
                }
            }
        }
        true
    }

    fn step(&mut self, nfa: &Nfa, state: u32, class: usize, byte: u8) -> u32 {
        let at = state as usize;
        let known = self.next[at][class];
        if known != u32::MAX {
            return known;
        }
        let mut set: Vec<usize> = self.sets[at]
            .iter()
            .flat_map(|&s| &nfa.edges[s])
            .filter(|(bytes, _)| bytes.contains(byte))
            .map(|&(_, t)| t)
            .collect();
        nfa.closure(&mut set);
        let classes = self.next[at].len();
        let id = self.id(nfa, set, classes);
        self.next[at][class] = id;
        id
    }
}

/// The byte classes no automaton tells apart, by a representative each:
/// a lowercase letter, digit or other printable ASCII byte where the class
/// has one, so a witness reads as text.
fn classes(nfas: &[Nfa]) -> Vec<u8> {
    let sets: std::collections::HashSet<Bytes> = nfas
        .iter()
        .flat_map(|n| n.edges.iter().flatten())
        .map(|(b, _)| *b)
        .collect();
    let sets: Vec<Bytes> = sets.into_iter().collect();
    let mut by_signature: HashMap<Vec<bool>, u8> = HashMap::new();
    let rank = |b: u8| match b {
        b'a'..=b'z' => 0,
        b'0'..=b'9' => 1,
        b'!'..=b'~' => 2,
        _ => 3,
    };
    for b in 0..=u8::MAX {
        let signature: Vec<bool> = sets.iter().map(|s| s.contains(b)).collect();
        let best = by_signature.entry(signature).or_insert(b);
        if rank(b) < rank(*best) {
            *best = b;
        }
    }
    let mut reps: Vec<u8> = by_signature.into_values().collect();
    reps.sort_unstable();
    reps
}

/// Search `target`'s subjects for one `new` decides less strictly than `old`.
pub(super) fn search(
    old: &CompiledPolicy<'_>,
    new: &CompiledPolicy<'_>,
    target: Target,
    found: &mut Vec<Widening>,
) -> Outcome {
    let mut matchers = Matchers::default();
    let shared = Shared::new(old, new);
    let sides = matchers
        .side(old, target, Role::Old, &shared)
        .and_then(|o| Ok((o, matchers.side(new, target, Role::New, &shared)?)));
    let (old_side, new_side) = match sides {
        Ok(sides) => sides,
        Err(Unsupported(why)) => return Outcome::NotProven(format!("a pattern reads as {why}")),
    };
    let reps = classes(&matchers.nfas);
    let mut locals: Vec<Local> = matchers
        .nfas
        .iter()
        .map(|n| Local::new(n, reps.len()))
        .collect();
    let start: Vec<(u32, u32)> = (0..locals.len())
        .filter_map(|m| u32::try_from(m).ok().map(|m| (m, 1)))
        .collect();
    let mut states: HashMap<Vec<(u32, u32)>, usize> = HashMap::from([(start.clone(), 0)]);
    let mut parents: Vec<(usize, u8)> = vec![(0, 0)];
    let mut queue = VecDeque::from([(start, 0)]);
    let mut seen_pairs = BTreeSet::new();
    let mut unconfirmed = None;
    let before = found.len();
    let mut universal: HashMap<(u32, u32), bool> = HashMap::new();
    let mut stop_at = MAX_STATES;
    let differing = old_side.differing(&new_side);
    while let Some((state, at)) = queue.pop_front() {
        let accepted: BTreeSet<usize> = state
            .iter()
            .filter(|(m, l)| locals[*m as usize].accept[*l as usize])
            .map(|(m, _)| *m as usize)
            .collect();
        let was = old_side.verdict(&accepted, false);
        let now = new_side.verdict(&accepted, true);
        if now.0 < was.0 && seen_pairs.insert((was.clone(), now.clone())) {
            let witness = witness(&parents, at);
            match confirm(old, new, target, witness) {
                Ok(widening) => found.push(widening),
                Err(why) => unconfirmed = unconfirmed.or(Some(why)),
            }
            if found.len() - before >= MAX_FOUND {
                break;
            }
            if found.len() > before {
                stop_at = stop_at.min(states.len() + MORE_AFTER_FOUND);
            }
        }
        // No continuation can be decided less strictly: every changed
        // pattern that may lower a verdict can no longer match (`differing.rs`).
        if differing
            .as_ref()
            .is_some_and(|d| !state.iter().any(|(m, _)| d.contains(&(*m as usize))))
        {
            continue;
        }
        // No continuation can widen: the new policy holds at least what the
        // old one gives any of them at most.
        let mut liveness: HashMap<usize, Live> = HashMap::with_capacity(state.len());
        for &(m, l) in &state {
            let always = *universal.entry((m, l)).or_insert_with(|| {
                locals[m as usize].universal(&matchers.nfas[m as usize], l, &reps)
            });
            liveness.insert(m as usize, if always { Live::Always } else { Live::Alive });
        }
        let live = |m: usize| liveness.get(&m).copied().unwrap_or(Live::Dead);
        if new_side.lowest(&live) >= old_side.highest(&live) {
            continue;
        }
        for (class, &byte) in reps.iter().enumerate() {
            let next: Vec<(u32, u32)> = state
                .iter()
                .map(|&(m, l)| {
                    (
                        m,
                        locals[m as usize].step(&matchers.nfas[m as usize], l, class, byte),
                    )
                })
                .filter(|&(_, l)| l != 0)
                .collect();
            if !states.contains_key(&next) {
                if states.len() >= stop_at && found.len() > before {
                    return Outcome::Widens;
                }
                if states.len() >= MAX_STATES {
                    return Outcome::NotProven(format!(
                        "the search passed {MAX_STATES} states; checked over samples only"
                    ));
                }
                states.insert(next.clone(), parents.len());
                parents.push((at, byte));
                queue.push_back((next, parents.len() - 1));
            }
        }
    }
    match (found.len() > before, unconfirmed) {
        (true, _) => Outcome::Widens,
        (false, Some(why)) => Outcome::NotProven(why),
        (false, None) => Outcome::Proven,
    }
}

/// The bytes the search read to reach state `at`.
fn witness(parents: &[(usize, u8)], mut at: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    while at != 0 {
        let (parent, byte) = parents[at];
        bytes.push(byte);
        at = parent;
    }
    bytes.reverse();
    bytes
}

/// The engine's own verdicts for `witness`: a widening when they agree with
/// the search, else why the kind is not proven.
fn confirm(
    old: &CompiledPolicy<'_>,
    new: &CompiledPolicy<'_>,
    target: Target,
    witness: Vec<u8>,
) -> Result<Widening, String> {
    let text = String::from_utf8(witness).map_err(|e| {
        format!(
            "a possible widening for bytes that are not text ({:?})",
            String::from_utf8_lossy(e.as_bytes())
        )
    })?;
    let atom = target.atom(text.clone());
    let decide = |p: &CompiledPolicy<'_>| {
        p.evaluate_atomic(&atom)
            .map_or((Verdict::Allow, Vec::new()), |d| (d.verdict, d.rules))
    };
    let (was, now) = (decide(old), decide(new));
    if now.0 < was.0 {
        Ok(Widening::new(
            atom.describe(),
            WideningSource::Proof(target.name()),
            was,
            now,
        ))
    } else {
        Err(format!(
            "a possible widening the engine does not confirm ({} {text:?})",
            target.name()
        ))
    }
}
