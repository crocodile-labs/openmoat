//! Reading and writing the program a server definition starts, in the host's
//! own form ([`McpCommandForm`]).
//!
//! A definition OpenMoat rewrites is read in the form its host's reader names.
//! Questions about one already written (is it wrapped, does it start a process)
//! read its shape from the entry, and an entry with both a `command` and a
//! `cmd` has none: which of them runs depends on the host.

use openmoat_hosts::McpCommandForm;
use serde_json::Value;

/// The `type` of an entry, when it has a string one.
fn kind(entry: &Value) -> Option<&str> {
    entry.get("type").and_then(Value::as_str)
}

/// `value` when it is a list of strings.
fn strings(value: &Value) -> Option<Vec<String>> {
    value
        .as_array()?
        .iter()
        .map(|item| item.as_str().map(str::to_owned))
        .collect()
}

/// The `args` of `entry`: none when it has no list.
fn args_of(entry: &Value) -> Option<Vec<String>> {
    match entry.get("args") {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(args) => strings(args),
    }
}

/// `entry`'s program and arguments when it is a local server in `form`.
pub(super) fn parts(entry: &Value, form: McpCommandForm) -> Option<(String, Vec<String>)> {
    match form {
        McpCommandForm::CommandArgs => {
            // `local` is GitHub Copilot CLI's word for a stdio server.
            if kind(entry).is_some_and(|t| t != "stdio" && t != "local") {
                return None;
            }
            let command = entry.get("command")?.as_str()?.to_owned();
            Some((command, args_of(entry)?))
        }
        McpCommandForm::CommandList => {
            if kind(entry) != Some("local") || entry.get("cmd").is_some() {
                return None;
            }
            let mut line = strings(entry.get("command")?)?;
            if line.is_empty() {
                return None;
            }
            let program = line.remove(0);
            Some((program, line))
        }
        McpCommandForm::CmdArgs => {
            if kind(entry) != Some("stdio") || entry.get("command").is_some() {
                return None;
            }
            let command = entry.get("cmd")?.as_str()?.to_owned();
            Some((command, args_of(entry)?))
        }
    }
}

/// The form `entry` is written in, from its own keys; `None` when it has no
/// program, or both a `command` and a `cmd`.
fn form_of(entry: &Value) -> Option<McpCommandForm> {
    match (entry.get("command"), entry.get("cmd")) {
        (Some(_), Some(_)) | (None, None) => None,
        (None, Some(_)) => Some(McpCommandForm::CmdArgs),
        (Some(Value::Array(_)), None) => Some(McpCommandForm::CommandList),
        (Some(_), None) => Some(McpCommandForm::CommandArgs),
    }
}

/// The form of `entry`, its program and its arguments, read from the entry.
pub(super) fn read(entry: &Value) -> Option<(McpCommandForm, String, Vec<String>)> {
    let form = form_of(entry)?;
    let (program, args) = parts(entry, form)?;
    Some((form, program, args))
}

/// `entry` starting `program` with `args` in `form`; the rest stays as it was.
pub(super) fn written(
    entry: &Value,
    form: McpCommandForm,
    program: String,
    args: Vec<String>,
) -> Value {
    let mut out = entry.clone();
    match form {
        McpCommandForm::CommandArgs => {
            out["command"] = Value::String(program);
            out["args"] = Value::from(args);
        }
        McpCommandForm::CommandList => {
            let mut line = vec![program];
            line.extend(args);
            out["command"] = Value::from(line);
        }
        McpCommandForm::CmdArgs => {
            out["cmd"] = Value::String(program);
            out["args"] = Value::from(args);
        }
    }
    out
}

/// Why `entry`, a definition in `form` that runs something on this machine,
/// cannot be rewritten; `None` for one that can be, and for a remote server,
/// which runs no command here.
pub fn not_wrappable(entry: &Value, form: McpCommandForm) -> Option<&'static str> {
    if parts(entry, form).is_some() {
        return None;
    }
    match (form, kind(entry)) {
        (McpCommandForm::CommandList, Some("remote")) | (McpCommandForm::CommandArgs, _) => None,
        (McpCommandForm::CommandList, _) => {
            Some("its `command` is not a list of strings under `type: local`")
        }
        (McpCommandForm::CmdArgs, Some("stdio")) => {
            Some("its `cmd` and `args` are not one program and a list of strings")
        }
        (McpCommandForm::CmdArgs, Some("inline_python")) => {
            Some("it is inline Python, which has no command to run through the proxy")
        }
        (McpCommandForm::CmdArgs, _) => None,
    }
}

/// The key `entry` names its program under, for a person setting it by hand.
pub(super) fn program_key(entry: &Value) -> &'static str {
    if entry.get("cmd").is_some() {
        "cmd"
    } else {
        "command"
    }
}

#[cfg(test)]
mod tests;
