//! The tools of the editor servers Claude Code connects to by itself: the `ide`
//! server the VS Code extension and the JetBrains plugin run, and the
//! `claude-vscode` server of the VS Code chat panel (Claude Code 2.1.285 or
//! later). Hooks see them as MCP tools (<https://code.claude.com/docs/en/vs-code>,
//! "The built-in IDE MCP server"; <https://code.claude.com/docs/en/jetbrains>):
//!
//! - `getDiagnostics` returns the editor's errors and warnings for one file,
//!   the file named by its `uri` argument, or, without one, for the active
//!   file (JetBrains) or every file the editor has diagnostics for (VS Code).
//!   The docs say a `Read` deny rule covers neither name; here the file is a
//!   read, so the path rules (`secrets-paths`) apply to it as to `Read`.
//! - `executeCode` (VS Code only) runs Python code in the active Jupyter
//!   notebook's kernel. OpenMoat does not read Python, so the call is held for
//!   review whatever else decides it; the editor's own Execute or Cancel
//!   question still follows.
//!
//! Both stay MCP calls by name, so a policy's `mcp` rules for them still
//! apply. The argument names (`uri`, `code`) are the tools' input schema as
//! Claude Code shows it to the model; the docs do not list them, so any other
//! argument falls back to the generic MCP reading, which checks every path
//! and URL by key.

use openmoat_core::Action;
use serde_json::Value;

use crate::HostError;

/// The diagnostics tool under both server names.
const DIAGNOSTICS: &[&str] = &[
    "mcp__ide__getDiagnostics",
    "mcp__claude-vscode__getDiagnostics",
];

/// The notebook tool of the VS Code extension.
const EXECUTE_CODE: &str = "mcp__ide__executeCode";

/// Why an `executeCode` call needs review ([`Action::Unchecked`]).
pub(super) const EXECUTE_CODE_UNCHECKED: &str =
    "runs Python code in the notebook's kernel, which OpenMoat does not read";

/// The action of one of the editor servers' tools; `None` for any other tool.
pub(super) fn action(
    tool: &str,
    input: &Value,
    cwd: Option<&str>,
) -> Option<Result<Action, HostError>> {
    if DIAGNOSTICS.contains(&tool) {
        return diagnostics(tool, input, cwd);
    }
    (tool == EXECUTE_CODE).then(|| {
        Ok(Action::unchecked(
            crate::wire::mcp::action(tool, input)?,
            EXECUTE_CODE_UNCHECKED,
        ))
    })
}

/// `getDiagnostics` reads the file its `uri` names; without one, the project.
/// Input with any other argument is left to the generic MCP reading (`None`).
fn diagnostics(tool: &str, input: &Value, cwd: Option<&str>) -> Option<Result<Action, HostError>> {
    let reading = |path: String| Action::McpTool {
        name: tool.to_owned(),
        reads: vec![path],
        writes: Vec::new(),
        hosts: Vec::new(),
        opens: Vec::new(),
        commands: Vec::new(),
        unchecked: None,
    };
    let map = match input {
        Value::Null => {
            return Some(Ok(
                cwd.map_or_else(|| Action::mcp(tool), |d| reading(d.to_owned()))
            ));
        }
        Value::Object(map) => map,
        _ => return None,
    };
    if map.keys().any(|key| key != "uri") {
        return None;
    }
    let Some(uri) = map.get("uri") else {
        return Some(Ok(
            cwd.map_or_else(|| Action::mcp(tool), |d| reading(d.to_owned()))
        ));
    };
    let Some(uri) = uri.as_str() else {
        return Some(Err(malformed(tool, "`uri` is not a string")));
    };
    if let Some(path) = openmoat_core::file_url_path(uri) {
        return Some(Ok(reading(path)));
    }
    // An editor-only scheme (`untitled:`, a notebook cell) names no file on
    // disk; a `file:` URI without an absolute path names none that can be
    // checked, so it is refused; a path without a scheme, absolute or
    // relative (`.env`, `../.aws/credentials`), is read as written, a relative
    // one from the session's directory, as the model may write either.
    if uri
        .get(..5)
        .is_some_and(|s| s.eq_ignore_ascii_case("file:"))
    {
        return Some(Err(malformed(tool, "a file URI without an absolute path")));
    }
    if is_windows_path(uri) || !has_scheme(uri) {
        return Some(Ok(reading(uri.to_owned())));
    }
    Some(Ok(Action::mcp(tool)))
}

/// `untitled:Untitled-1`, `vscode-notebook-cell:…`: a URI scheme of two
/// characters or more, so a drive letter (`C:`) is not one.
fn has_scheme(text: &str) -> bool {
    text.split_once(':').is_some_and(|(scheme, _)| {
        scheme.len() > 1
            && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    })
}

/// `C:\…` or `C:/…`.
fn is_windows_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() > 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}

fn malformed(tool: &str, problem: &str) -> HostError {
    HostError::MalformedArguments {
        tool: tool.to_owned(),
        problem: problem.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn reads(action: &Action) -> Vec<String> {
        match action {
            Action::McpTool { reads, .. } => reads.clone(),
            _ => panic!("not an MCP action"),
        }
    }

    #[test]
    fn diagnostics_read_the_file_their_uri_names_under_both_servers() {
        for tool in DIAGNOSTICS {
            let input = json!({"uri": "file:///Users/me/.aws/credentials"});
            let secret = action(tool, &input, Some("/p")).unwrap().unwrap();
            assert_eq!(reads(&secret), ["/Users/me/.aws/credentials"], "{tool}");
            let percent = json!({"uri": "file:///p/src/my%20file.rs"});
            let spaced = action(tool, &percent, Some("/p")).unwrap().unwrap();
            assert_eq!(reads(&spaced), ["/p/src/my file.rs"], "{tool}");
        }
    }

    #[test]
    fn diagnostics_without_a_uri_read_the_project() {
        let tool = DIAGNOSTICS[0];
        for input in [json!({}), Value::Null] {
            let project = action(tool, &input, Some("/p")).unwrap().unwrap();
            assert_eq!(reads(&project), ["/p"]);
            let nowhere = action(tool, &input, None).unwrap().unwrap();
            assert_eq!(nowhere, Action::mcp(tool));
        }
    }

    #[test]
    fn other_uris_and_arguments() {
        let tool = DIAGNOSTICS[1];
        let at = |input: Value| action(tool, &input, Some("/p"));
        assert_eq!(
            at(json!({"uri": "untitled:Untitled-1"})).unwrap().unwrap(),
            Action::mcp(tool),
            "an editor-only scheme names no file"
        );
        assert_eq!(
            reads(&at(json!({"uri": "/etc/passwd"})).unwrap().unwrap()),
            ["/etc/passwd"]
        );
        for relative in [".env", "../.aws/credentials", "src/main.rs"] {
            assert_eq!(
                reads(&at(json!({"uri": relative})).unwrap().unwrap()),
                [relative],
                "a path without a scheme is a read, relative ones too"
            );
        }
        assert!(at(json!({"uri": "file:relative.rs"})).unwrap().is_err());
        assert!(at(json!({"uri": 7})).unwrap().is_err());
        assert!(
            at(json!({"uri": "file:///p/a", "path": "/p/b"})).is_none(),
            "an unknown argument is read the generic way"
        );
        assert!(at(json!("text")).is_none());
        assert!(is_windows_path("C:\\Users\\me\\a.rs"));
        assert!(!is_windows_path("C:"));
    }

    #[test]
    fn execute_code_needs_review_and_stays_an_mcp_call() {
        let input = json!({"code": "import os; os.system('id')"});
        let held = action(EXECUTE_CODE, &input, Some("/p")).unwrap().unwrap();
        let Action::Unchecked {
            action: shown,
            reason,
        } = held
        else {
            panic!("not unchecked")
        };
        assert_eq!(reason, EXECUTE_CODE_UNCHECKED);
        assert!(matches!(*shown, Action::McpTool { ref name, .. } if name == EXECUTE_CODE));
        assert!(action("mcp__ide__openDiff", &input, None).is_none());
    }
}
