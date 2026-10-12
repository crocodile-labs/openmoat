//! `make` arguments that run code of the caller's choosing.
//!
//! `make test` runs the project's recipes, which a policy may allow. The same
//! command line can also replace the recipe shell (`SHELL=/tmp/x`), inject
//! makefile text (`--eval='x:;cmd'`), run commands while parsing variables
//! (`CC=$(shell cmd)`, `X!=cmd`) or let the environment override the makefile
//! (`-e`). Each such argument becomes its own `make <argument>` shell atom, so
//! a `make test*` allow rule no longer covers the call, and every embedded
//! command is classified like any other shell command.

use super::commands::classify_into;
use super::{ClassifyError, ShellContext, Sink};
use crate::action::AtomicAction;

/// Command-line variables that decide how recipes are executed.
const RECIPE_VARS: &[&str] = &["SHELL", ".SHELLFLAGS", "MAKESHELL", "MAKEFLAGS", "MFLAGS"];

/// Variables whose value is the program that runs every recipe line.
const SHELL_VARS: &[&str] = &["SHELL", "MAKESHELL"];

/// Single-letter options that take no value, as GNU make documents them.
const NO_VALUE_SHORT: &str = "bBdeiknpqrsStvw";

pub(super) fn classify(
    argv: &[String],
    ctx: &ShellContext<'_>,
    sink: &mut Sink,
    depth: u8,
) -> Result<(), ClassifyError> {
    let program = &argv[0];
    let flag = |sink: &mut Sink, arg: &str| {
        sink.push(AtomicAction::Shell {
            argv: vec![program.clone(), arg.to_owned()],
        })
    };
    let mut rest = argv[1..].iter();
    while let Some(arg) = rest.next() {
        let eval = if let Some(text) = arg.strip_prefix("--eval=") {
            Some(text)
        } else if arg == "--eval" || arg == "-E" {
            rest.next().map(String::as_str)
        } else {
            arg.strip_prefix("-E").filter(|t| !t.is_empty())
        };
        if let Some(text) = eval {
            flag(sink, "--eval")?;
            classify_into(text, ctx, sink, depth + 1)?;
        } else if arg == "--environment-overrides" || is_env_override_cluster(arg) {
            flag(sink, arg)?;
        } else if let Some((name, op, value)) = assignment(arg) {
            if RECIPE_VARS.contains(&name) {
                flag(sink, arg)?;
            }
            if SHELL_VARS.contains(&name) && !value.is_empty() {
                classify_into(value, ctx, sink, depth + 1)?;
            }
            if op == "!" {
                flag(sink, arg)?;
                classify_into(value, ctx, sink, depth + 1)?;
            }
            for call in shell_calls(value) {
                classify_into(call, ctx, sink, depth + 1)?;
            }
        }
    }
    Ok(())
}

/// `-e`, or a cluster of value-less short options containing `e` (`-ke`).
fn is_env_override_cluster(arg: &str) -> bool {
    arg.strip_prefix('-').is_some_and(|letters| {
        !letters.starts_with('-')
            && letters.contains('e')
            && letters.chars().all(|c| NO_VALUE_SHORT.contains(c))
    })
}

/// A make command-line assignment: `NAME=v`, `NAME:=v`, `NAME::=v`, `NAME+=v`,
/// `NAME?=v` or `NAME!=v` (the last runs `v` through the shell). Returns the
/// name, the operator prefix (`""`, `":"`, `"::"`, `"+"`, `"?"`, `"!"`) and the value.
fn assignment(arg: &str) -> Option<(&str, &str, &str)> {
    if arg.starts_with('-') {
        return None;
    }
    let (left, value) = arg.split_once('=')?;
    let (name, op) = ["::", ":", "+", "?", "!"]
        .iter()
        .find_map(|op| left.strip_suffix(op).map(|n| (n, *op)))
        .unwrap_or((left, ""));
    let valid = !name.is_empty()
        && !name
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, ':' | '#' | '=' | '$' | '(' | ')'));
    valid.then_some((name, op, value))
}

/// Bodies of `$(shell …)` and `${shell …}` calls in make text.
fn shell_calls(text: &str) -> Vec<&str> {
    let mut calls = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find('$') {
        rest = &rest[pos + 1..];
        let (open, close) = match rest.chars().next() {
            Some('(') => ('(', ')'),
            Some('{') => ('{', '}'),
            _ => continue,
        };
        let body = &rest[1..];
        let Some(after) = body.strip_prefix("shell") else {
            continue;
        };
        if !after.starts_with(char::is_whitespace) {
            continue;
        }
        let mut level = 1usize;
        let end = after.char_indices().find_map(|(i, c)| {
            if c == open {
                level += 1;
            } else if c == close {
                level -= 1;
            }
            (level == 0).then_some(i)
        });
        // An unterminated call is still a command make would try to run.
        let end = end.unwrap_or(after.len());
        calls.push(after[..end].trim());
        rest = &after[end..];
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments_and_operators() {
        assert_eq!(assignment("SHELL=/tmp/x"), Some(("SHELL", "", "/tmp/x")));
        assert_eq!(
            assignment(".SHELLFLAGS=-c"),
            Some((".SHELLFLAGS", "", "-c"))
        );
        assert_eq!(assignment("X!=id"), Some(("X", "!", "id")));
        assert_eq!(assignment("CC::=clang"), Some(("CC", "::", "clang")));
        assert_eq!(assignment("--file=x"), None);
        assert_eq!(assignment("test"), None);
    }

    #[test]
    fn shell_calls_are_extracted() {
        assert_eq!(
            shell_calls("x $(shell cat ~/.ssh/id_rsa) ${shell id} $(CC) $(shellx y)"),
            ["cat ~/.ssh/id_rsa", "id"]
        );
        assert_eq!(shell_calls("$(shell echo $(X))"), ["echo $(X)"]);
        assert_eq!(shell_calls("$(shell curl x"), ["curl x"]);
    }

    #[test]
    fn env_override_clusters() {
        assert!(is_env_override_cluster("-e"));
        assert!(is_env_override_cluster("-ke"));
        assert!(!is_env_override_cluster("-j4"));
        assert!(!is_env_override_cluster("--eval"));
        assert!(!is_env_override_cluster("-k"));
    }
}
