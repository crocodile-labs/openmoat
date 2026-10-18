//! Files named by a Codex `apply_patch` envelope, whether Codex sends it as
//! its own tool or the agent runs `apply_patch` in a shell.
//!
//! ```text
//! *** Begin Patch
//! *** Add File: path        (create)
//! *** Update File: path     (edit; may be followed by `*** Move to: other`)
//! *** Delete File: path
//! *** End Patch
//! ```
//!
//! Every named path is written (a delete or a move removes its source). A
//! patch that names no file is passed on empty and decided as unparseable.
//!
//! Codex trims a file header before matching it, so ` *** Delete File: x`
//! after an added file's lines is a header to it. A line is matched the same
//! way here, ignoring case as well, and wherever it appears: naming a file the
//! patch does not touch only makes the decision stricter, while missing one
//! that Codex writes would let it through unchecked.

const HEADERS: &[&str] = &[
    "*** Add File:",
    "*** Update File:",
    "*** Delete File:",
    "*** Move to:",
];

/// Every file the patch `text` writes, in the order it names them.
#[must_use]
pub fn writes(text: &str) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(path) = HEADERS
            .iter()
            .find_map(|h| strip_header(line, h))
            .map(str::trim)
            .filter(|p| !p.is_empty())
        else {
            continue;
        };
        if !paths.iter().any(|p| p == path) {
            paths.push(path.to_owned());
        }
    }
    paths
}

/// `line` after `header`, compared without regard to ASCII case.
fn strip_header<'a>(line: &'a str, header: &str) -> Option<&'a str> {
    let head = line.get(..header.len())?;
    head.eq_ignore_ascii_case(header)
        .then(|| &line[header.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_header_names_a_written_file() {
        let patch = "*** Begin Patch\n*** Add File: src/new.rs\n+fn x() {}\n\
                     *** Update File: src/lib.rs\n*** Move to: src/core.rs\n@@\n-a\n+b\n\
                     *** Delete File: old.txt\r\n*** Update File: src/lib.rs\n*** End Patch\n";
        assert_eq!(
            writes(patch),
            ["src/new.rs", "src/lib.rs", "src/core.rs", "old.txt"]
        );
    }

    #[test]
    fn added_lines_that_look_like_headers_are_content() {
        // An added line `+*** Add File: x` starts with `+`, so it is content.
        assert_eq!(writes("*** Add File: a\n+*** Add File: ~/.zshrc\n"), ["a"]);
    }

    #[test]
    fn indented_and_differently_cased_headers_are_writes() {
        // Codex trims the line after an added file's content and reads it as
        // the next header, so the indented delete is applied.
        let patch = "*** Begin Patch\n*** Add File: a\n+x\n  *** Delete File: ~/.ssh/id_rsa\n\
                     \t*** update file: ~/.zshrc\n*** End Patch\n";
        assert_eq!(writes(patch), ["a", "~/.ssh/id_rsa", "~/.zshrc"]);
    }

    #[test]
    fn headers_outside_the_envelope_still_count() {
        let patch = "*** Begin Patch\n*** Add File: a\n+x\n*** End Patch\n*** Delete File: b\n";
        assert_eq!(writes(patch), ["a", "b"]);
    }

    #[test]
    fn a_root_path_is_passed_on_for_the_engine_to_decide() {
        assert_eq!(writes("*** Delete File: /\n"), ["/"]);
    }

    #[test]
    fn no_headers_means_no_files() {
        assert!(writes("just text").is_empty());
        assert!(writes("*** Add File:   \n").is_empty());
    }
}
