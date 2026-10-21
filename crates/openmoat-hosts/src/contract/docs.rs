//! What the generated host tables in the docs say about a host beyond the
//! other spec facts (`tests/docs.rs` writes and checks them).

/// A host's lines in the generated tables of `README.md` ("Supported agents")
/// and `docs/ARCHITECTURE.md` §3 ("Host tool mapping").
#[derive(Debug)]
#[non_exhaustive]
pub struct HostDocs {
    /// How OpenMoat is hooked into the host: the events and the file, or the
    /// plugin or extension that runs `openmoat guard`.
    pub hooked_by: &'static str,
    /// What checks the host's tool calls: `hook + OS sandbox` when OpenMoat
    /// writes the host's sandbox ([`HostSpec::sandbox`](super::HostSpec::sandbox)),
    /// with the platforms it runs on when it is not written on native Windows,
    /// else `hook only` (`tests/docs.rs` checks the two agree).
    pub protection: &'static str,
    /// How each tool the adapter maps becomes an action, one row per tool or
    /// group of tools, and which tools it leaves ungoverned. Every tool name
    /// the adapter's code matches appears in these rows (`tests/docs.rs`).
    pub tools: &'static [ToolRow],
}

impl HostDocs {
    /// No documentation: what a spec takes when it names none.
    pub const BASE: HostDocs = HostDocs {
        hooked_by: "",
        protection: "",
        tools: &[],
    };
}

/// One row of the "Host tool mapping" table: Markdown cells.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ToolRow {
    /// The tool or tools, as the host names them.
    pub tool: &'static str,
    /// The fields of the input read, and how.
    pub reads: &'static str,
    /// The `Action` (or `none: ungoverned`) the call becomes.
    pub action: &'static str,
}

impl ToolRow {
    /// The row for `tool`, which reads `reads` and becomes `action`.
    #[must_use]
    pub const fn new(tool: &'static str, reads: &'static str, action: &'static str) -> Self {
        Self {
            tool,
            reads,
            action,
        }
    }
}
