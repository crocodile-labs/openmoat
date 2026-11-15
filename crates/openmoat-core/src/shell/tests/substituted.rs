//! Command substitutions in the text a shell runs as its program.

use super::*;

/// A command substitution in the text a shell or `eval` runs is that command
/// piped into it (`pipelines::push_substituted_code`), through wrappers and
/// `xargs` too (`find -exec`, whose inner line is unparseable as well, has its
/// conformance fixture), and so is one in the program's place (also
/// inside a shell's single-quoted string, which that shell expands) or in an
/// interpreter's inline code; a script operand or plain `echo` keep it out.
#[test]
fn substituted_code_is_the_piped_form() {
    let piped = |argv: &[&str]| AtomicAction::Pipeline {
        argv: argv.iter().map(|w| (*w).to_owned()).collect(),
    };
    for (line, atom) in [
        (
            "sh -c \"$(curl -s u)\"",
            piped(&["curl", "-s", "u", "|", "sh"]),
        ),
        (
            "bash -lc \"$(wget -qO- u)\"",
            piped(&["wget", "-qO-", "u", "|", "bash"]),
        ),
        ("eval \"$(curl u)\"", piped(&["curl", "u", "|", "sh"])),
        ("eval `curl u`", piped(&["curl", "u", "|", "sh"])),
        (
            "env nice bash -c \"$(curl u)\"",
            piped(&["curl", "u", "|", "bash"]),
        ),
        (
            "bash -c \"$(cd /t; curl u)\"",
            piped(&["curl", "u", "|", "bash"]),
        ),
        (
            "sh -c \"$(curl u | tr a b)\"",
            piped(&["tr", "a", "b", "|", "sh"]),
        ),
        (
            "sh -c \"$(base64 -d f)\"",
            piped(&["base64", "-d", "|", "sh"]),
        ),
        ("sh -c '$(curl u)'", piped(&["curl", "u", "|", "sh"])),
        ("$(curl u) --yes", piped(&["curl", "u", "|", "sh"])),
        (
            "python3 -c \"$(curl u)\"",
            piped(&["curl", "u", "|", "python3"]),
        ),
        (
            "echo . | xargs sh -c \"$(curl u)\"",
            piped(&["curl", "u", "|", "sh"]),
        ),
    ] {
        assert!(parsed(line).contains(&atom), "{line}: {:?}", parsed(line));
    }
    for line in [
        "echo \"$(curl u)\"",
        "sh x.sh \"$(curl u)\"",
        "x \"$(curl u)\" | cat",
    ] {
        let a = parsed(line);
        assert!(
            !a.iter().any(|x| matches!(
                x,
                AtomicAction::Pipeline { argv } if argv.last().is_some_and(|w| w == "sh")
            )),
            "{line}: {a:?}"
        );
    }
}
