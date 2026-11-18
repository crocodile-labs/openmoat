//! Only a `$` the shell expands is an environment-variable read.

use super::*;

fn reads_env(cmd: &str, name: &str) -> bool {
    parsed(cmd).contains(&AtomicAction::EnvRead {
        name: name.to_owned(),
    })
}

#[test]
fn single_quoted_dollar_is_literal() {
    assert!(!reads_env("sed -n '$p' f", "p"));
    assert!(!reads_env("awk '{print $NF}' f", "NF"));
    assert!(!reads_env("echo '$GITHUB_TOKEN'", "GITHUB_TOKEN"));
    assert!(!reads_env("X='$GITHUB_TOKEN' make", "GITHUB_TOKEN"));
    assert!(!reads_env("cat <<< '$GITHUB_TOKEN'", "GITHUB_TOKEN"));
    assert!(!reads_env("sudo awk '{print $NF}' f", "NF"));
    assert!(!reads_env("find . -exec awk '{print $NF}' {} ;", "NF"));
}

#[test]
fn unquoted_and_double_quoted_dollar_expands() {
    assert!(reads_env("echo $GITHUB_TOKEN", "GITHUB_TOKEN"));
    assert!(reads_env("echo \"$GITHUB_TOKEN\"", "GITHUB_TOKEN"));
    assert!(reads_env("echo \"'$GITHUB_TOKEN'\"", "GITHUB_TOKEN"));
    assert!(reads_env("echo '$p'$GITHUB_TOKEN", "GITHUB_TOKEN"));
    assert!(!reads_env("echo '$p'$GITHUB_TOKEN", "p"));
    assert!(reads_env("X=\"$GITHUB_TOKEN\" make", "GITHUB_TOKEN"));
    assert!(reads_env("cat <<< \"$GITHUB_TOKEN\"", "GITHUB_TOKEN"));
    assert!(reads_env("sudo printf %s $GITHUB_TOKEN", "GITHUB_TOKEN"));
}

#[test]
fn ansi_c_quoting_is_still_scanned() {
    assert!(reads_env("echo $'$GITHUB_TOKEN'", "GITHUB_TOKEN"));
}

#[test]
fn inner_shell_expands_what_the_outer_one_kept_literal() {
    assert!(reads_env("sh -c 'echo $GITHUB_TOKEN'", "GITHUB_TOKEN"));
    assert!(reads_env(
        "bash -c 'echo \"$GITHUB_TOKEN\"'",
        "GITHUB_TOKEN"
    ));
    assert!(reads_env("eval 'echo $GITHUB_TOKEN'", "GITHUB_TOKEN"));
    assert!(reads_env("sudo sh -c 'echo $GITHUB_TOKEN'", "GITHUB_TOKEN"));
    // The outer shell expands inside double quotes before `sh` sees the quotes.
    assert!(reads_env("sh -c \"echo '$GITHUB_TOKEN'\"", "GITHUB_TOKEN"));
}

#[test]
fn heredoc_delimiter_quoting_decides_expansion() {
    assert!(reads_env("cat <<EOF\n'$GITHUB_TOKEN'\nEOF", "GITHUB_TOKEN"));
    assert!(!reads_env(
        "cat <<'EOF'\n$GITHUB_TOKEN\nEOF",
        "GITHUB_TOKEN"
    ));
}

#[test]
fn escaped_dollar_is_literal() {
    assert!(!reads_env("echo \\$GITHUB_TOKEN", "GITHUB_TOKEN"));
    assert!(!reads_env("echo \"\\$GITHUB_TOKEN\"", "GITHUB_TOKEN"));
    assert!(!reads_env("cat <<EOF\n\\$GITHUB_TOKEN\nEOF", "GITHUB_TOKEN"));
    // an escaped backslash leaves the `$` unescaped
    assert!(reads_env("echo \"\\\\$GITHUB_TOKEN\"", "GITHUB_TOKEN"));
    assert!(reads_env("echo \\\\$GITHUB_TOKEN", "GITHUB_TOKEN"));
}

#[test]
fn inner_shell_expands_what_the_outer_one_escaped() {
    assert!(reads_env("sh -c \"echo \\$GITHUB_TOKEN\"", "GITHUB_TOKEN"));
    assert!(reads_env("eval \"echo \\$GITHUB_TOKEN\"", "GITHUB_TOKEN"));
    assert!(reads_env("bash <<EOF\necho \\$GITHUB_TOKEN\nEOF", "GITHUB_TOKEN"));
}
