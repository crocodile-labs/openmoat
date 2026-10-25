//! One module per host: its [`HostSpec`](crate::HostSpec) and the quirks a
//! fact cannot say. A host that sends a shared format reads it through
//! [`crate::wire`]; no host module imports another.
//!
//! The list below is the one place that names every host. A line
//! `Variant => module` declares `host/<module>.rs`, which holds the host's
//! `SPEC` and its `ADAPTER`; `speaks Other` marks a host that sends another
//! host's hook format and so has no adapter of its own. The list gives the
//! [`Host`] variants (with the doc comment above each line), [`Host::EVERY`] in
//! this order, [`Host::ALL`] and the registry's lookups ([`crate::registry`]).

crate::registry::hosts! {
    /// Anthropic's Claude Code (`PreToolUse`, `ConfigChange`).
    ClaudeCode => claude_code,
    /// The Codex CLI (`PreToolUse`).
    Codex => codex,
    /// Cursor (`beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `preToolUse`).
    Cursor => cursor,
    /// The Continue CLI (`cn`), which runs the Claude Code hooks. It has no hook
    /// of its own to install, so it is not in [`Host::ALL`]; `guard` recognises
    /// it with [`Host::sender`].
    Continue => continue_cli speaks ClaudeCode,
    /// OpenClaw, through OpenMoat's plugin and its `before_tool_call` hook.
    OpenClaw => openclaw,
    /// GitHub Copilot CLI (`preToolUse`).
    CopilotCli => copilot_cli,
    /// pi, through OpenMoat's extension and its `tool_call` event.
    Pi => pi,
    /// Google's Gemini CLI (`BeforeTool`).
    GeminiCli => gemini_cli,
    /// OpenCode 1, through OpenMoat's plugin and its `tool.execute.before` hook.
    OpenCode => opencode,
}
