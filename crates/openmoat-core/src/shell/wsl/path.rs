//! A word read as Win32 reads a path: `\` and `/` alike, letter case
//! ignored, each component without the trailing dots and spaces Win32 drops
//! (`wsl.exe.`) and without an NTFS stream (`wsl.exe::$DATA`, `x:stream`),
//! `.` and empty components dropped and `..` taken back.

/// The components of a path, in lower case.
pub(super) struct WinPath {
    pub(super) parts: Vec<String>,
}

impl WinPath {
    /// The last component without `.exe`: the program a path runs.
    pub(super) fn program(&self) -> String {
        self.parts.last().map_or_else(String::new, |last| {
            last.strip_suffix(".exe").unwrap_or(last).to_owned()
        })
    }
}

/// `word` read as a Windows path.
pub(super) fn read(word: &str) -> WinPath {
    let unified = word.replace('\\', "/").to_ascii_lowercase();
    let mut parts: Vec<String> = Vec::new();
    for (index, raw) in unified.split('/').enumerate() {
        // `c:` at the start is a drive; anywhere else `:` starts a stream
        let is_drive = index == 0 && raw.len() == 2 && raw.ends_with(':');
        let name = if is_drive {
            raw
        } else {
            raw.split(':').next().unwrap_or(raw)
        };
        match name {
            "." => {}
            ".." => {
                parts.pop();
            }
            name => {
                let name = name.trim_end_matches(['.', ' ']);
                if !name.is_empty() {
                    parts.push(name.to_owned());
                }
            }
        }
    }
    WinPath { parts }
}

/// The program `word` runs, as [`WinPath::program`] reads it.
pub(super) fn program(word: &str) -> String {
    read(word).program()
}
