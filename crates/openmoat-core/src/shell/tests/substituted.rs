//! Command substitutions in the text a shell runs as its program.

use super::*;

/// A command substitution in the text a shell or `eval` runs is that command
/// piped into it (`pipelines::push_substituted_code`), through wrappers too;
/// single quotes, a script operand or plain `echo` keep it out.
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
    ] {
        assert!(parsed(line).contains(&atom), "{line}: {:?}", parsed(line));
    }
    for line in [
        "echo \"$(curl u)\"",
        "sh -c '$(curl u)'",
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
