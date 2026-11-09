//! The files a command line creates or replaces with content of its own: a
//! redirect, `tee`, `dd of=`, `sed -i`, the destination of a `cp`, `mv` or
//! `ln`. Removing a file, moving it away, emptying it or changing its mode is
//! a write to the policy (`tables::NO_CONTENT_WRITES`) but leaves nothing a
//! program later reads as settings, so those are not listed.
//!
//! What such a write leaves in the file cannot be known before it runs, so the
//! CLI refuses one aimed at a file an agent reads as its hook settings
//! (`project_settings/written.rs` in `openmoat-cli`).

use super::{ShellContext, Sink, commands};

/// Every absolute path `command`, run in `cwd` under `home`, creates or
/// replaces, read as the classifier reads it. A part the classifier stops at
/// hides no write it would have found before.
#[must_use]
pub fn replaced_files(command: &str, home: &str, cwd: &str) -> Vec<String> {
    let dirs = [Some(cwd.to_owned())];
    let ctx = ShellContext { home, cwd: &dirs };
    let mut sink = Sink::default();
    let _ = commands::classify_into(command, &ctx, &mut sink, 0);
    let split = command.replace("${IFS}", " ").replace("$IFS", " ");
    if split != command {
        let _ = commands::classify_into(&split, &ctx, &mut sink, 0);
    }
    sink.replaced
}

#[cfg(test)]
mod tests {
    use super::replaced_files;

    const FILE: &str = "/w/.codex/config.toml";

    fn replaced(command: &str) -> Vec<String> {
        replaced_files(command, "/h", "/w")
    }

    fn replaces_the_file(command: &str) -> bool {
        replaced(command).iter().any(|p| p == FILE)
    }

    #[test]
    fn each_shell_form_that_leaves_content_is_listed() {
        for command in [
            "printf x > .codex/config.toml",
            "printf x >> .codex/config.toml",
            "printf x >| .codex/config.toml",
            "printf x | tee .codex/config.toml",
            "printf x | tee -a .codex/config.toml",
            "cp evil.toml .codex/config.toml",
            "mv evil.toml .codex/config.toml",
            "mv evil/config.toml .codex/",
            "cp -t .codex evil/config.toml",
            "ln -sf /tmp/evil .codex/config.toml",
            "dd if=evil of=.codex/config.toml",
            "sed -i s/true/false/ .codex/config.toml",
            "cd .codex && printf x > config.toml",
            "sh -c 'printf x > .codex/config.toml'",
            "true; printf x>${IFS}.codex/config.toml",
        ] {
            assert!(
                replaces_the_file(command),
                "{command}: {:?}",
                replaced(command)
            );
        }
    }

    #[test]
    fn a_removal_a_move_away_or_a_read_is_not_listed() {
        for command in [
            "rm .codex/config.toml",
            "rm -f .codex/config.toml",
            "unlink .codex/config.toml",
            "touch .codex/config.toml",
            "chmod 600 .codex/config.toml",
            "truncate -s 0 .codex/config.toml",
            "mv .codex/config.toml .codex/config.toml.bak",
            "cp .codex/config.toml backup.toml",
            "cat .codex/config.toml",
            "grep hooks .codex/config.toml > out.txt",
            "git diff .codex/config.toml",
        ] {
            assert!(
                !replaces_the_file(command),
                "{command}: {:?}",
                replaced(command)
            );
        }
    }

    /// Removing the file first does not hide the write that follows.
    #[test]
    fn a_write_after_a_removal_is_still_listed() {
        assert!(replaces_the_file(
            "rm .codex/config.toml; printf x > .codex/config.toml"
        ));
        assert!(replaces_the_file(
            "printf x > .codex/config.toml; rm .codex/config.toml"
        ));
    }
}
