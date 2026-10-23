use super::{binary_of, command_for};

#[test]
fn the_binary_is_quoted_for_the_shell_and_read_back() {
    let id = "gemini-cli";
    let posix = command_for("/Users/me/My Tools/it's/openmoat", id, false);
    assert_eq!(
        posix,
        r"'/Users/me/My Tools/it'\''s/openmoat' guard --host gemini-cli"
    );
    assert_eq!(
        binary_of(&posix, id).as_deref(),
        Some("/Users/me/My Tools/it's/openmoat")
    );
    let windows = command_for(r"C:\Program Files\it's\openmoat.exe", id, true);
    assert_eq!(
        windows,
        r"& 'C:\Program Files\it''s\openmoat.exe' guard --host gemini-cli; if (-not $?) { exit 2 }"
    );
    assert_eq!(
        binary_of(&windows, id).as_deref(),
        Some(r"C:\Program Files\it's\openmoat.exe")
    );
    assert_eq!(
        binary_of("/usr/bin/openmoat guard --host gemini-cli", id).as_deref(),
        Some("/usr/bin/openmoat")
    );
    let doubled = command_for("/opt/a''b/openmoat", id, false);
    assert_eq!(
        binary_of(&doubled, id).as_deref(),
        Some("/opt/a''b/openmoat")
    );
    assert_eq!(binary_of("'/x/openmoat' guard --host cursor", id), None);
    assert_eq!(binary_of("node .gemini/hooks/check.js", id), None);
}
