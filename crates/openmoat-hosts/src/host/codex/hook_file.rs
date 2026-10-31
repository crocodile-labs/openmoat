//! Codex 0.160.1 and 0.166.0 execute a shell string, ignoring `args`.
//! `commandWindows` replaces `command` on Windows (upstream discovery.rs).

use serde_json::{Value, json};

use crate::{HookFile, HookSpec};

#[derive(Debug)]
pub(super) struct Codex;

impl HookFile for Codex {
    fn refresh_on_upgrade(&self) -> bool {
        true
    }

    fn entry(&self, spec: &HookSpec, id: &str, binary: &str, _block: bool) -> Value {
        json!({"matcher": spec.matcher, "hooks": [{
            "type": "command",
            "command": format!("'{}' guard --host {id}", binary.replace('\'', r"'\''")),
            "commandWindows": windows_command(binary, id),
            "timeout": spec.timeout,
            "statusMessage": "OpenMoat",
        }]})
    }

    fn is_ours(&self, entry: &Value, id: &str) -> bool {
        crate::wire::hook_file::nested::Nested.is_ours(entry, id)
            || self.binary(entry, id).is_some()
    }

    fn binary(&self, entry: &Value, id: &str) -> Option<String> {
        let hook = entry.pointer("/hooks/0")?;
        let command = hook.get("command")?.as_str()?;
        if crate::wire::hook_file::nested::Nested.is_ours(entry, id) {
            return Some(command.to_owned());
        }
        let quoted = command.strip_suffix(&format!(" guard --host {id}"))?;
        let inner = quoted.strip_prefix('\'')?.strip_suffix('\'')?;
        Some(inner.replace(r"'\''", "'"))
    }
}

fn windows_command(binary: &str, id: &str) -> String {
    // Codex defaults to cmd.exe /C. An encoded PowerShell command keeps cmd's
    // percent expansion and metacharacters out of the path, and also works
    // with a PowerShell command shell. Propagate guard's blocking exit code.
    let script = format!(
        "& '{}' guard --host {id}; if ($null -eq $LASTEXITCODE) {{ exit 2 }}; exit $LASTEXITCODE",
        binary.replace('\'', "''")
    );
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    format!(
        "powershell.exe -NoProfile -NonInteractive -EncodedCommand {}",
        base64(&bytes)
    )
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        for index in [a >> 2, ((a & 3) << 4) | (b >> 4)] {
            out.push(char::from(ALPHABET[usize::from(index)]));
        }
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((b & 15) << 2) | (c >> 6))])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(c & 63)])
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests;
