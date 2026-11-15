//! What the packages of every channel share (ADR-099): the guard script a
//! hook-command plugin runs in place of the binary, the hook file in the
//! host's own layout, and the JavaScript plugin `openmoat init` writes, made
//! to find `openmoat` on the search path.
//!
//! Nothing here names a host: each host's `plugin.rs` says which of these its
//! channel takes and where the files go.

use openmoat_core::{Decision, Verdict};
use serde_json::{Value, json};

use crate::contract::PluginFile;
use crate::wire::guard_command::GuardCommand;
use crate::wire::owned_file::OwnedFile;
use crate::{HookEvent, Host};

/// The flag a package's guard runs with: decide the call unless `openmoat
/// init`'s own hook for the host is installed and pinned, and record that the
/// package ran (`openmoat doctor` reports it).
pub const PLUGIN_FLAG: &str = "--plugin";

/// What a package says when there is no `openmoat` to run: the one install
/// command, and `openmoat init`, which writes the policy and its lock.
pub const NOT_INSTALLED: &str = "OpenMoat is not installed: install it with `brew install \
     crocodile-labs/tap/openmoat` (other ways: \
     https://github.com/crocodile-labs/openmoat/blob/main/docs/INSTALL.md), then run `openmoat init`";

/// The program every package runs, looked for on the search path.
pub const PROGRAM: &str = "openmoat";

/// Where OpenMoat's installers put the binary (`docs/INSTALL.md`: the shell
/// installer's `~/.cargo/bin`, Homebrew's prefixes), which the guard script
/// looks in after the search path: an agent started from a desktop launcher
/// may have a shorter one than the person's shell.
pub const INSTALL_DIRS: &[&str] = &[
    "$HOME/.cargo/bin",
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/home/linuxbrew/.linuxbrew/bin",
];

/// The rule id of a package's own block, the one the guard gives a call it
/// could not decide.
use openmoat_core::rule_id::KERNEL_ERROR as BLOCK_RULE;

/// `value` as a file: pretty JSON and a final newline.
pub(crate) fn json_file(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.push('\n');
    text
}

/// `text` as one single-quoted POSIX shell word.
fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The deny `host` reads for its default event, saying `why`: what the guard
/// itself answers when it cannot decide.
fn deny(host: Host, why: &str) -> String {
    host.render_response(
        &HookEvent::default(),
        &Decision::single(Verdict::Deny, BLOCK_RULE, why),
    )
}

/// The policy lock in the default state directory, relative to the home
/// directory, whose `binary` names the program `openmoat init` pinned.
pub const LOCK_FILE: &str = ".moat/policy.lock";

/// Why a package blocks a call whose lock names no program it can run.
pub const LOCK_UNUSABLE: &str = "the policy lock (`~/.moat/policy.lock`) names no `openmoat` \
     this package can run: reinstall OpenMoat, then run `openmoat init`";

/// Why a package blocks a call `openmoat guard` gave no answer for.
const NO_ANSWER: &str =
    "OpenMoat could not decide this call: `openmoat guard` gave no answer; run `openmoat doctor`";

/// The script a hook-command package runs in place of the `openmoat` binary
/// (POSIX `sh`). It runs the program the policy lock pins (`binary` in
/// [`LOCK_FILE`], the absolute path `openmoat init` recorded); without a lock,
/// the one in a folder OpenMoat's installers use ([`INSTALL_DIRS`]), then on
/// the search path, which an agent's environment can change and so is read
/// last and only where the guard denies anyway (no lock). It passes the
/// hook's arguments and [`PLUGIN_FLAG`], passes the answer on, and blocks the
/// call, exiting with the host's block code (`deny_exit`), when there is no
/// program to run or it exits without an answer.
pub(crate) fn guard_script(host: Host) -> String {
    let deny_exit = host.spec().deny_exit;
    let dirs: Vec<String> = INSTALL_DIRS
        .iter()
        .map(|dir| match dir.strip_prefix("$HOME") {
            Some(rest) => format!("\"$HOME{rest}\""),
            None => (*dir).to_owned(),
        })
        .collect();
    format!(
        r#"#!/bin/sh
# OpenMoat plugin for {name}: runs `openmoat guard` for each hook call.
# Generated from OpenMoat's host specs (plugins/README.md); do not edit.
#
# {name} runs this file where `openmoat init`'s hook runs the `openmoat`
# binary, with the same arguments (`guard --host {id}`, and `--event <event>`
# where the payload names no event), and `{flag}` added: the guard decides
# the call or, where `openmoat init`'s own hook is installed and pinned, gives
# no decision so that hook decides it alone (ADR-099).
#
# Which `openmoat`: the one the policy lock pins (`~/{lock}`, written by
# `openmoat init`); with no lock yet, one in a folder OpenMoat's installers
# use, then the search path (the guard denies every call until `openmoat
# init` writes the lock). Without one, or when it exits without an answer,
# the call is blocked. This file downloads and installs nothing.

missing={missing}
unusable={unusable}
failed={failed}

block() {{
  printf '%s\n' "$1"
  printf 'OpenMoat blocked this call: %s\n' "$2" >&2
  exit {deny_exit}
}}

lock="$HOME/{lock}"
moat=
if [ -e "$lock" ]; then
  # Read with the shell's own `read`, no program from the search path, which
  # the agent's environment or a repository could fill.
  while IFS= read -r line || [ -n "$line" ]; do
    case $line in
      '  "binary": "'*)
        moat=${{line#'  "binary": "'}}
        moat=${{moat%,}}
        moat=${{moat%\"}}
        break ;;
    esac
  done < "$lock" 2>/dev/null
  case $moat in
    *\\*|*\"*|'') block "$unusable" {unusable_text} ;;
    /*) ;;
    *) block "$unusable" {unusable_text} ;;
  esac
  [ -x "$moat" ] || block "$unusable" {unusable_text}
else
  for dir in {dirs}; do
    if [ -x "$dir/{program}" ]; then
      moat=$dir/{program}
      break
    fi
  done
  [ -n "$moat" ] || moat=$(command -v {program} 2>/dev/null) || moat=
fi
[ -n "$moat" ] || block "$missing" {not_installed}

answer=$("$moat" "$@" {flag})
code=$?
if [ "$code" -eq 0 ]; then
  [ -z "$answer" ] || printf '%s\n' "$answer"
  exit 0
fi
if [ "$code" -eq 2 ] && [ -n "$answer" ]; then
  printf '%s\n' "$answer"
  exit {deny_exit}
fi
block "$failed" "openmoat guard exited $code without an answer"
"#,
        name = host.display_name(),
        id = host.id(),
        flag = PLUGIN_FLAG,
        program = PROGRAM,
        lock = LOCK_FILE,
        missing = shell_word(&deny(host, NOT_INSTALLED)),
        unusable = shell_word(&deny(host, LOCK_UNUSABLE)),
        failed = shell_word(&deny(host, NO_ANSWER)),
        not_installed = shell_word(NOT_INSTALLED),
        unusable_text = shell_word(LOCK_UNUSABLE),
        dirs = dirs.join(" "),
    )
}

/// A hook-command package's hook file and guard script: the entries `openmoat
/// init` writes for `host`, in the host's own layout, each running `command`
/// (how the hook file names the script at `script`) in place of the binary,
/// with `entry_keys` added to each entry. Empty for a host whose hook file is
/// not entries among the person's own.
pub(crate) fn hook_plugin(
    host: Host,
    hook_file: &str,
    script: &str,
    command: &str,
    entry_keys: &[(&str, &str)],
) -> Vec<PluginFile> {
    let Some(install) = host.spec().install.as_ref() else {
        return Vec::new();
    };
    let Some(layout) = install.hook_file.entries() else {
        return Vec::new();
    };
    let mut root = json!({});
    let guard = GuardCommand::new(command);
    // A package is for the host's current releases, which know `onFailure`.
    if layout
        .upsert(
            &mut root,
            hook_file,
            host.id(),
            install.hooks,
            &guard,
            || true,
        )
        .is_err()
    {
        return Vec::new();
    }
    if let Some(Value::Object(events)) = root.get_mut(layout.section()) {
        for entries in events.values_mut() {
            for entry in entries.as_array_mut().into_iter().flatten() {
                for (key, value) in entry_keys {
                    entry[*key] = Value::from(*value);
                }
            }
        }
    }
    vec![
        PluginFile::data(hook_file, json_file(&root)),
        PluginFile::program(script, guard_script(host)),
    ]
}

/// The plugin `openmoat init` writes for a host that loads one, as a package
/// ships it: running the `openmoat` on the search path with [`PLUGIN_FLAG`]
/// in place of a binary and state directory `init` fills in.
pub(crate) fn packaged(owned: &OwnedFile) -> String {
    owned.text(PROGRAM, "").unwrap_or_default()
}

/// The `package.json` of an npm package of `meta`'s, named `name`, holding
/// `files`, with the host's own keys in `extra`.
pub(crate) fn package_json(
    meta: &crate::contract::Meta,
    name: &str,
    folder: &str,
    files: &[&str],
    keywords: &[&str],
    extra: Value,
) -> PluginFile {
    let mut doc = json!({
        "name": name,
        "version": meta.version,
        "description": meta.description,
        "license": meta.license,
        "author": meta.author,
        "homepage": meta.homepage,
        "repository": {
            "type": "git",
            "url": format!("git+{}.git", meta.repository),
            "directory": format!("plugins/{folder}"),
        },
        "keywords": keywords,
        "type": "module",
        "files": files,
    });
    if let (Value::Object(doc), Value::Object(extra)) = (&mut doc, extra) {
        doc.extend(extra);
    }
    PluginFile::data("package.json", json_file(&doc))
}

#[cfg(test)]
mod tests {
    use super::shell_word;

    #[test]
    fn a_shell_word_keeps_every_quote() {
        assert_eq!(shell_word("it's"), r"'it'\''s'");
        assert_eq!(shell_word("$(x)"), "'$(x)'");
    }
}
