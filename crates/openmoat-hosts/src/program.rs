//! Which host a program is, by each spec's [`crate::ProcessSpec`]: `openmoat`'s
//! person-only commands look for an agent among their parents with it, and
//! `openmoat run` finds which agent it starts, whose own login stays readable
//! in its sandbox (ADR-054).

use crate::Host;

/// Extensions a host's program may carry; its names are written without them.
const EXTENSIONS: [&str; 4] = [".exe", ".js", ".mjs", ".cjs"];

impl Host {
    /// The host whose program `word` (a command name or a path, either case,
    /// `/` or `\` separated) is, with the name it was found by: one of the
    /// host's program names, for the last path segment without its
    /// extension, or else the first segment of a package directory the path
    /// runs through (`claude/versions`, `@openai/codex`), for a host that
    /// runs as `node <dir>/…/cli.js` or from a versioned file. `None` when no
    /// host matches.
    #[must_use]
    pub fn by_program(word: &str) -> Option<(Self, &'static str)> {
        let lower = word.trim_start_matches('-').to_ascii_lowercase();
        let segments: Vec<&str> = lower.split(['/', '\\']).filter(|s| !s.is_empty()).collect();
        let (&base, dirs) = segments.split_last()?;
        let stem = EXTENSIONS
            .iter()
            .find_map(|ext| base.strip_suffix(ext))
            .unwrap_or(base);
        let by_name = Self::EVERY.iter().find_map(|host| {
            let names = host.spec().process.names;
            names
                .iter()
                .find(|name| **name == stem)
                .map(|name| (*host, *name))
        });
        by_name.or_else(|| {
            Self::EVERY.iter().find_map(|host| {
                let dirs_of = host.spec().process.package_dirs;
                dirs_of
                    .iter()
                    .find(|pattern| dirs.windows(pattern.len()).any(|w| w == **pattern))
                    .map(|pattern| (*host, pattern[0]))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::Host;

    #[test]
    fn programs_are_known_by_name_or_package_directory() {
        let host = |word: &str| Host::by_program(word).map(|(h, _)| h.id());
        assert_eq!(host("claude"), Some("claude-code"));
        assert_eq!(
            host("/Users/me/.local/share/claude/versions/2.1.283"),
            Some("claude-code")
        );
        assert_eq!(
            host("/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js"),
            Some("claude-code")
        );
        assert_eq!(host("C:\\Tools\\Codex.exe"), Some("codex"));
        assert_eq!(host("/opt/homebrew/bin/goose"), Some("goose"));
        for other in ["/bin/zsh", "/usr/bin/python3", "npx", "", "/"] {
            assert_eq!(host(other), None, "{other}");
        }
    }
}
