//! One sandboxed-start shim: what it runs and its text.

use std::path::{Path, PathBuf};

use anyhow::Result;
use openmoat_hosts::Host;

use super::run_words;
use crate::protection::os_sandbox::RunCommand;

/// A shim `init` would write for one agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shim {
    pub host: Host,
    /// The command a person types, and the shim's file name.
    pub name: &'static str,
    /// The real program it starts.
    pub program: PathBuf,
    /// The script.
    pub text: String,
}

impl Shim {
    /// The shim that starts `program` (the real one, found outside the shim
    /// directory) for `host` with `run`'s command, through `binary`.
    pub fn new(host: Host, binary: &Path, program: &Path, run: &RunCommand) -> Self {
        let mut words = vec![quote(&binary.display().to_string())];
        words.extend(run_words(run).into_iter().map(str::to_owned));
        for write in &run.writes {
            words.push("--write".to_owned());
            words.push(quote(&write.display().to_string()));
        }
        words.push("--".to_owned());
        words.push(quote(&program.display().to_string()));
        words.extend(run.args.iter().map(|a| quote(a)));
        words.push("\"$@\"".to_owned());
        let text = format!(
            "#!/bin/sh\n\
             # OpenMoat: `{name}` starts {agent} in `openmoat run`'s sandbox (ADR-106).\n\
             # Written by `openmoat init`; `openmoat uninstall` removes it.\n\
             exec {}\n",
            words.join(" "),
            name = run.program,
            agent = host.display_name(),
        );
        Self {
            host,
            name: run.program,
            program: program.to_path_buf(),
            text,
        }
    }
}

/// `word` as one `sh` word: in single quotes, a quote in it closed, escaped
/// and reopened.
pub(super) fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// Write the shim at `path`, runnable by its owner only.
pub(super) fn write_executable(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::home::write_private_program(path, bytes)
}
