//! Codex on Linux runs its own executable again inside bubblewrap to apply
//! seccomp (`build_inner_seccomp_command` in `linux-sandbox/src/linux_run_main.rs`
//! re-executes `current_exe()`) but grants itself no read access to it, so a
//! command starts only when the profile lets it read that file (#371). The
//! release executable is statically linked (musl): the file alone is enough.
//!
//! Codex's standalone installer keeps that executable in the Codex home
//! (`packages/standalone/releases/<version>-<target>/bin/codex`), which the
//! profile denies. Codex masks a denied directory after binding the read paths
//! inside it, so the file stays hidden unless the Codex home itself is not
//! denied (#374).

use std::path::{Path, PathBuf};

use openmoat_core::Kind;
use toml_edit::{Item, Table, value};

use super::Generated;
use crate::sandbox::patterns::is_below;

const RULE: &str = "codex.own-binary";

/// What Codex keeps in its home that commands must not read: the login, the
/// config (MCP server tokens) and the conversations.
const CODEX_STATE: &[&str] = &[
    "auth.json",
    "config.toml",
    "history.jsonl",
    "sessions",
    "archived_sessions",
    "log",
];

/// The executable `codex` on `PATH` runs, symlinks resolved.
pub fn own_binary() -> Option<PathBuf> {
    let path: Vec<PathBuf> = std::env::split_paths(&std::env::var_os("PATH")?).collect();
    native(&std::fs::canonicalize(crate::environment::find_in(&path, &[], "codex")?).ok()?)
}

/// `found` itself, or for npm's launcher (`<package>/bin/codex.js`) the
/// executable it starts: `vendor/<triple>/bin/codex` in the platform package
/// (`@openai/codex-linux-x64`) installed inside or beside the package, else in
/// the package itself (`findCodexExecutable` in `codex-cli/bin/codex.js`).
fn native(found: &Path) -> Option<PathBuf> {
    if found.extension().is_none_or(|e| e != "js") {
        return Some(found.to_path_buf());
    }
    let arch = match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        _ => return None,
    };
    let package = found.parent()?.parent()?;
    let platform = format!("codex-linux-{arch}");
    let binary = Path::new("vendor")
        .join(format!("{}-unknown-linux-musl", std::env::consts::ARCH))
        .join("bin/codex");
    [
        package.join("node_modules/@openai").join(&platform),
        package.with_file_name(&platform),
        package.to_path_buf(),
    ]
    .iter()
    .map(|dir| dir.join(&binary))
    .find(|candidate| candidate.is_file())
    .and_then(|candidate| std::fs::canonicalize(candidate).ok())
}

/// Let commands read Codex's own executable `binary`. A path the profile
/// denies stays denied (Codex applies deny masks last), and that, like Codex
/// missing from `PATH`, is reported as stricter. The exception is the Codex
/// home `codex_home` when no read or write grant includes it: commands cannot
/// read it then anyway, so its deny gives way to denies of [`CODEX_STATE`],
/// which still apply when a workspace root includes it.
pub fn read_own_binary(
    generated: &mut Generated,
    binary: Option<&Path>,
    codex_home: Option<&Path>,
) {
    let Some(binary) = binary else {
        generated.report.loss(
            Kind::FsRead,
            RULE,
            "`codex` was not on PATH: Codex on Linux runs its own executable inside the \
             sandbox, so it starts commands only when installed under a read root; run \
             `moat sandbox sync` after installing it"
                .into(),
        );
        return;
    };
    let key = crate::context::path_string(binary);
    let Some(filesystem) = generated
        .profile
        .get_mut("filesystem")
        .and_then(Item::as_table_mut)
    else {
        return;
    };
    let home = codex_home.and_then(|home| denied_home_above(filesystem, &key, home));
    let denied = filesystem
        .iter()
        .find(|(path, mode)| {
            mode.as_str() == Some("deny")
                && home.as_deref() != Some(*path)
                && (*path == key || is_below(&key, path))
        })
        .map(|(path, _)| path.to_owned());
    let denied = match (denied, &home) {
        (None, Some(home)) if !open_codex_home(filesystem, home) => Some(home.clone()),
        (denied, _) => denied,
    };
    if let Some(denied) = denied {
        generated.report.loss(
            Kind::FsRead,
            RULE,
            format!(
                "Codex's executable `{key}` is inside the denied `{denied}`, and Codex on Linux \
                 runs it inside the sandbox, so no command starts; install Codex outside it"
            ),
        );
        return;
    }
    if !filesystem.contains_key(&key) {
        filesystem.insert(&key, value("read"));
    }
    let opened = home.map_or_else(String::new, |home| {
        format!(
            ". It is in the Codex home `{home}`, which no read root includes, so the profile \
             denies the Codex home's {} instead of the whole directory",
            CODEX_STATE.join(", ")
        )
    });
    let message = format!(
        "Codex on Linux runs its own executable again inside the sandbox, so commands may read \
         it; run `moat sandbox sync` after moving or updating Codex{opened}"
    );
    generated
        .report
        .allowance(Kind::FsRead, RULE, vec![key], &message);
}

/// The Codex home's deny entry, when `binary` is inside `home` (as listed or
/// with links resolved, as Codex masks both) and the profile denies `home`.
fn denied_home_above(filesystem: &Table, binary: &str, home: &Path) -> Option<String> {
    let listed = crate::context::path_string(home);
    if filesystem.get(&listed).and_then(Item::as_str) != Some("deny") {
        return None;
    }
    let resolved = std::fs::canonicalize(home)
        .ok()
        .map(|home| crate::context::path_string(&home));
    std::iter::once(listed.clone())
        .chain(resolved)
        .any(|spelling| is_below(binary, &spelling))
        .then_some(listed)
}

/// Replace the deny of the Codex home `home` with denies of [`CODEX_STATE`]
/// below it, unless a read or write grant (`:tmpdir` included) covers `home`:
/// commands could then read the rest of it. Whether that happened.
fn open_codex_home(filesystem: &mut Table, home: &str) -> bool {
    let tmpdir = std::fs::canonicalize(std::env::temp_dir())
        .map(|dir| crate::context::path_string(&dir))
        .unwrap_or_default();
    let covered = filesystem.iter().any(|(path, mode)| {
        let path = if path == ":tmpdir" {
            tmpdir.as_str()
        } else {
            path
        };
        matches!(mode.as_str(), Some("read" | "write")) && (path == home || is_below(home, path))
    });
    if covered {
        return false;
    }
    filesystem.remove(home);
    for name in CODEX_STATE {
        filesystem.insert(&format!("{home}/{name}"), value("deny"));
    }
    true
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::sandbox::codex::tests::generated;

    fn mode<'a>(out: &'a Generated, key: &str) -> Option<&'a str> {
        out.profile["filesystem"].get(key)?.as_str()
    }

    #[test]
    fn the_executable_is_readable_and_listed_as_wider() {
        let mut out = generated(openmoat_core::DEFAULT_POLICY);
        read_own_binary(&mut out, Some(Path::new("/opt/codex/bin/codex")), None);
        assert_eq!(mode(&out, "/opt/codex/bin/codex"), Some("read"));
        let allowance = out.report.allowances.iter().find(|a| a.rule == RULE);
        assert_eq!(
            allowance.map(|a| a.patterns.clone()),
            Some(vec!["/opt/codex/bin/codex".to_owned()])
        );
    }

    #[test]
    fn a_denied_or_missing_executable_is_stricter_and_never_granted() {
        let mut out = generated(openmoat_core::DEFAULT_POLICY);
        let inside = "/Users/me/.ssh/codex";
        read_own_binary(&mut out, Some(Path::new(inside)), None);
        assert_eq!(mode(&out, inside), None);
        read_own_binary(&mut out, None, None);
        let losses: Vec<&str> = out
            .report
            .losses
            .iter()
            .filter(|l| l.rule == RULE)
            .map(|l| l.message.as_str())
            .collect();
        assert_eq!(losses.len(), 2, "{losses:?}");
        assert!(losses[0].contains("inside the denied `/Users/me/.ssh`"));
        assert!(!out.report.allowances.iter().any(|a| a.rule == RULE));
    }

    const STANDALONE: &str =
        "/Users/me/.codex/packages/standalone/releases/0.160.1-x86_64-unknown-linux-musl/bin/codex";

    #[test]
    fn the_standalone_executable_opens_the_codex_home_but_not_its_state() {
        let mut out = generated(openmoat_core::DEFAULT_POLICY);
        let home = Path::new("/Users/me/.codex");
        read_own_binary(&mut out, Some(Path::new(STANDALONE)), Some(home));
        assert_eq!(mode(&out, STANDALONE), Some("read"));
        assert_eq!(mode(&out, "/Users/me/.codex"), None);
        for name in CODEX_STATE {
            assert_eq!(
                mode(&out, &format!("/Users/me/.codex/{name}")),
                Some("deny")
            );
        }
        let allowance = out.report.allowances.iter().find(|a| a.rule == RULE);
        assert!(allowance.is_some_and(|a| a.message.contains("auth.json")));
    }

    #[test]
    fn a_covered_codex_home_or_another_deny_stays_denied() {
        let read_home = |out: &mut Generated| {
            out.profile["filesystem"]["/Users/me"] = value("read");
        };
        let deny_packages = |out: &mut Generated| {
            out.profile["filesystem"]["/Users/me/.codex/packages"] = value("deny");
        };
        for widen in [read_home, deny_packages] {
            let mut out = generated(openmoat_core::DEFAULT_POLICY);
            widen(&mut out);
            let home = Path::new("/Users/me/.codex");
            read_own_binary(&mut out, Some(Path::new(STANDALONE)), Some(home));
            assert_eq!(mode(&out, STANDALONE), None);
            assert_eq!(mode(&out, "/Users/me/.codex"), Some("deny"));
            assert_eq!(mode(&out, "/Users/me/.codex/auth.json"), None);
            assert!(out.report.losses.iter().any(|l| l.rule == RULE));
        }
    }

    #[test]
    fn npm_launcher_resolves_to_the_platform_executable() {
        let dir = tempfile::tempdir().unwrap();
        let modules = std::fs::canonicalize(dir.path()).unwrap();
        let launcher = modules.join("@openai/codex/bin/codex.js");
        std::fs::create_dir_all(launcher.parent().unwrap()).unwrap();
        std::fs::write(&launcher, "").unwrap();
        assert_eq!(native(&launcher), None, "no executable installed");
        let arch = if std::env::consts::ARCH == "x86_64" {
            "x64"
        } else {
            "arm64"
        };
        let executable = modules
            .join(format!("@openai/codex-linux-{arch}/vendor"))
            .join(format!("{}-unknown-linux-musl", std::env::consts::ARCH))
            .join("bin/codex");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, "").unwrap();
        assert_eq!(native(&launcher), Some(executable.clone()));
        assert_eq!(native(&executable), Some(executable));
    }
}
