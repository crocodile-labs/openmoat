//! Copies of the hook payloads real agents send, for the adapters' captured
//! fixtures (`host/<id>/fixtures/captured-*.json`). Only a build with the
//! `capture-payloads` feature reads `OPENMOAT_CAPTURE_DIR`: the weekly
//! latest-agents job builds one to run each agent's latest release in a
//! throwaway home; a release build has none of it, so an agent or a project
//! that sets the variable cannot make the guard write anything.
//!
//! A copy is written as it arrived, before it is parsed, into a new file of
//! that directory; it never changes the decision, and a directory that is
//! missing, relative or not writable is skipped.

#[cfg(any(feature = "capture-payloads", test))]
use std::path::Path;

use openmoat_hosts::Host;

/// The variable naming the directory copies go in.
#[cfg(any(feature = "capture-payloads", test))]
const DIR: &str = "OPENMOAT_CAPTURE_DIR";

/// Copy `payload`, sent by `host`, where `OPENMOAT_CAPTURE_DIR` says.
#[cfg(feature = "capture-payloads")]
pub(super) fn keep(host: Host, payload: &str) {
    if let Some(dir) = std::env::var_os(DIR) {
        keep_in(Path::new(&dir), host, payload);
    }
}

/// Without the feature, nothing is copied.
#[cfg(not(feature = "capture-payloads"))]
pub(super) fn keep(_host: Host, _payload: &str) {}

/// Copy `payload` into a new file of `dir`, named after `host`, the time and
/// this process; nothing when `dir` is relative or the file cannot be made.
#[cfg(any(feature = "capture-payloads", test))]
fn keep_in(dir: &Path, host: Host, payload: &str) {
    use std::io::Write as _;
    if !dir.is_absolute() || !dir.is_dir() {
        return;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = dir.join(format!("{}-{nanos}-{}.json", host.id(), std::process::id()));
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        let _ = file.write_all(payload.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payload_is_copied_as_it_arrived_into_a_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let host = Host::ALL[0];
        keep_in(dir.path(), host, "{\"tool\": \"bash\"}\n");
        let files: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert_eq!(files.len(), 1);
        let name = files[0].file_name().to_string_lossy().into_owned();
        assert!(
            name.starts_with(&format!("{}-", host.id()))
                && files[0].path().extension().is_some_and(|e| e == "json"),
            "{name}"
        );
        let text = std::fs::read_to_string(files[0].path()).unwrap();
        assert_eq!(text, "{\"tool\": \"bash\"}\n");
    }

    #[test]
    fn a_relative_or_missing_directory_gets_nothing() {
        keep_in(Path::new("captured"), Host::ALL[0], "{}");
        assert!(!Path::new("captured").exists());
        let dir = tempfile::tempdir().unwrap();
        keep_in(&dir.path().join("missing"), Host::ALL[0], "{}");
        assert!(!dir.path().join("missing").exists());
    }

    /// The variable is read only by a build with the feature, which no release
    /// is (`dist-workspace.toml` builds the default features).
    #[test]
    fn only_the_capture_build_reads_the_variable() {
        assert_eq!(DIR, "OPENMOAT_CAPTURE_DIR");
        let manifest = include_str!("../../../Cargo.toml");
        assert!(
            manifest.contains("capture-payloads = []"),
            "the feature is declared"
        );
        assert!(
            !manifest.contains("default = [\"capture-payloads\""),
            "never on by default"
        );
    }
}
