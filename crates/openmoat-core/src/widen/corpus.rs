//! The calls the never-widen check decides under both policies: fixtures
//! read from conformance files (`tests/conformance/*.yaml`, whose format
//! AGENTS.md describes) and any a caller adds, such as the bundled `MoatBench`
//! steps (ADR-111).

use serde::{Deserialize, Serialize};

use crate::action::{Action, AtomicAction};

/// Where a case comes from, as a widening names it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "from", content = "name", rename_all = "lowercase")]
pub enum WideningSource {
    /// A fixture or scenario step, by its id.
    Fixture(String),
    /// A case generated from a rule of either policy, by the rule's id
    /// (`defaults` for the cases no rule names).
    Generated(String),
    /// Found by the symbolic search over one kind.
    Proof(&'static str),
}

/// What is decided: a whole call, as a host reports it, or one atomic action,
/// as a rule matches it.
#[derive(Debug, Clone)]
pub enum Case {
    /// Decided with [`crate::CompiledPolicy::decide`]: every layer of a call.
    Call(Action),
    /// Decided with [`crate::CompiledPolicy::evaluate_atomic`]: the rules alone.
    Atom(AtomicAction),
}

/// One case and where it comes from.
#[derive(Debug, Clone)]
pub struct Probe {
    /// Named in a widening.
    pub source: WideningSource,
    /// What is decided.
    pub case: Case,
}

impl Probe {
    /// A call from a fixture or a scenario named `id`.
    #[must_use]
    pub fn fixture(id: impl Into<String>, action: Action) -> Self {
        Self {
            source: WideningSource::Fixture(id.into()),
            case: Case::Call(action),
        }
    }
}

#[derive(Deserialize)]
struct Fixture {
    id: String,
    action: FixtureAction,
}

#[derive(Deserialize)]
struct FixtureAction {
    shell: Option<String>,
    fs_read: Option<String>,
    fs_write: Option<String>,
    net: Option<String>,
    fetch: Option<String>,
    web_search: Option<String>,
    patch: Option<Vec<String>>,
    mcp_tool: Option<McpTool>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum McpTool {
    Name(String),
    Call { name: String },
}

impl FixtureAction {
    fn into_action(self) -> Option<Action> {
        [
            self.shell.map(|command| Action::Shell { command }),
            self.fs_read.map(|path| Action::FsRead { path }),
            self.fs_write.map(|path| Action::FsWrite { path }),
            self.net.map(|url| Action::Net { url }),
            self.fetch.map(|url| Action::Fetch { url }),
            self.web_search.map(|query| Action::WebSearch { query }),
            self.patch.map(|writes| Action::Patch { writes }),
            self.mcp_tool.map(|m| match m {
                McpTool::Name(name) | McpTool::Call { name } => Action::mcp(name),
            }),
        ]
        .into_iter()
        .flatten()
        .next()
    }
}

/// The calls of a conformance fixture file. A fixture of a kind not read here
/// (an unknown host tool, a foreign shell, a call with unchecked arguments)
/// is left out; the context, session and repository keys are ignored, since
/// both policies decide the call in the same context.
///
/// # Errors
/// When the text is not a list of fixtures with an `id` and an `action`.
pub fn fixtures(yaml: &str) -> Result<Vec<Probe>, crate::yaml::Error> {
    let list: Vec<Fixture> = crate::yaml::from_str(yaml)?;
    Ok(list
        .into_iter()
        .filter_map(|f| {
            let id = f.id;
            f.action.into_action().map(|a| Probe::fixture(id, a))
        })
        .collect())
}
