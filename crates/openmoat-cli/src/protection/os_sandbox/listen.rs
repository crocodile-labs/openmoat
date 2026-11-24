//! The port an agent that serves one listens on (OpenClaw's Gateway), found
//! as the agent finds it (ADR-108 §7): its variable, then its hook file's key,
//! then its default. `openmoat status` prints it as `--listen PORT` and a
//! sandboxed-start shim carries it.

use std::path::Path;

use openmoat_hosts::RunListen;
use serde_json::Value;

/// The port `listen` names here, reading `settings` (the agent's hook file)
/// and the environment through `var`; or why no port can be named.
pub(crate) fn port(
    listen: &RunListen,
    settings: &Path,
    var: impl Fn(&str) -> Option<String>,
) -> Result<u16, String> {
    if let Some(text) = var(listen.variable) {
        return parsed(text.trim()).ok_or_else(|| {
            format!(
                "{} is `{text}`, not a port from 1024 to 65535",
                listen.variable
            )
        });
    }
    let key = listen.key.join(".");
    match in_file(settings, listen.key) {
        InFile::Port(port) => return Ok(port),
        InFile::NotAPort => {
            return Err(format!(
                "`{key}` in {} is not a port from 1024 to 65535",
                settings.display()
            ));
        }
        InFile::Absent => {}
    }
    if var(listen.moved_by).is_some() {
        return Err(format!(
            "{} is set, which changes {}'s default port; set `{key}` or {} so that OpenMoat \
             knows the port to allow",
            listen.moved_by, listen.what, listen.variable
        ));
    }
    Ok(listen.default_port)
}

/// What the hook file says of the port.
enum InFile {
    /// The file or the key is not there, or the file does not parse (which
    /// the agent reports).
    Absent,
    /// A port OpenMoat would allow.
    Port(u16),
    /// The key holds no port OpenMoat would allow.
    NotAPort,
}

/// The port at `key` in the JSON5 file `path`.
fn in_file(path: &Path, key: &[&str]) -> InFile {
    let Ok(text) = std::fs::read_to_string(path) else {
        return InFile::Absent;
    };
    let Ok(parsed_file) = crate::json5::parse(&text) else {
        return InFile::Absent;
    };
    let mut value = &parsed_file.value;
    for part in key {
        match value.get(part) {
            Some(inner) => value = inner,
            None => return InFile::Absent,
        }
    }
    let port = match value {
        Value::Number(n) => n.as_u64().and_then(|n| parsed(&n.to_string())),
        Value::String(s) => parsed(s.trim()),
        _ => None,
    };
    port.map_or(InFile::NotAPort, InFile::Port)
}

/// `text` as an unprivileged port.
fn parsed(text: &str) -> Option<u16> {
    text.parse::<u16>().ok().filter(|p| *p >= 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATEWAY: RunListen = RunListen {
        what: "its Gateway",
        default_port: 18789,
        variable: "PORT_VAR",
        key: &["gateway", "port"],
        moved_by: "PROFILE_VAR",
    };

    fn none(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn the_variable_then_the_file_then_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("openclaw.json");
        assert_eq!(port(&GATEWAY, &file, none), Ok(18789));
        std::fs::write(&file, "// mine\n{ gateway: { port: 19000, }, }\n").unwrap();
        assert_eq!(port(&GATEWAY, &file, none), Ok(19000));
        let var = |name: &str| (name == "PORT_VAR").then(|| "19100".to_owned());
        assert_eq!(port(&GATEWAY, &file, var), Ok(19100));
    }

    /// A privileged port, a word or a number too large is never allowed;
    /// the reason names where it came from.
    #[test]
    fn no_port_outside_the_unprivileged_range() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("openclaw.json");
        for bad in ["80", "0", "70000", "x"] {
            let var = |name: &str| (name == "PORT_VAR").then(|| bad.to_owned());
            let why = port(&GATEWAY, &file, var).unwrap_err();
            assert!(why.contains("PORT_VAR"), "{why}");
        }
        std::fs::write(&file, "{\"gateway\": {\"port\": 22}}").unwrap();
        let why = port(&GATEWAY, &file, none).unwrap_err();
        assert!(why.contains("gateway.port"), "{why}");
    }

    /// A named profile derives its own port: none is assumed unless one is set.
    #[test]
    fn a_profile_without_a_port_names_none() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("openclaw.json");
        let profile = |name: &str| (name == "PROFILE_VAR").then(|| "dev".to_owned());
        let why = port(&GATEWAY, &file, profile).unwrap_err();
        assert!(why.contains("PROFILE_VAR is set"), "{why}");
        std::fs::write(&file, "{ gateway: { port: 19001 } }").unwrap();
        assert_eq!(port(&GATEWAY, &file, profile), Ok(19001));
    }
}
