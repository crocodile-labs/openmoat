//! Windows (ADR-129): `openmoat agent-account setup`, then `openmoat run` as
//! the account, then `remove`. It needs an administrator token, which CI's
//! `windows-latest` runner has: setup creates a real local account (named for
//! this test, through a switch only debug builds read), grants it read on the
//! test's home, installs its network filters, and remove deletes them all.
//! One test, so the steps run in order and no two tests share the
//! machine-wide account. The payloads are `cmd.exe` commands (`curl.exe` and
//! PowerShell for the network), never an agent.

/// The network filters' cases.
mod network;

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

use super::super::installed_with_secret;
use crate::common::{FAILED, OK, Sandbox, output, stderr, stdout, text};

/// The switch that names the account in a debug build.
const NAME: &str = "MOAT_TEST_AGENT_ACCOUNT";

/// `openmoat <args>` as a person at a terminal, with the test's account name.
fn person(sb: &Sandbox, account: &str, args: &[&str]) -> Output {
    output(
        sb.command()
            .args(args)
            .env("MOAT_ASSUME_TTY", "1")
            .env(NAME, account),
        None,
    )
}

/// `openmoat run -- cmd /d /c <script>` in `project`.
fn run_cmd(sb: &Sandbox, project: &Path, account: &str, script: &str) -> Output {
    output(
        sb.command()
            .current_dir(project)
            .env(NAME, account)
            .args(["run", "--", "cmd", "/d", "/c", script]),
        None,
    )
}

/// Whether Windows knows a local account `name`.
fn account_exists(name: &str) -> bool {
    Command::new("net")
        .args(["user", name])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Deletes the account when the test ends early, so a failure leaves no
/// account behind on the machine.
struct Cleanup(String);

impl Drop for Cleanup {
    fn drop(&mut self) {
        if account_exists(&self.0) {
            let _ = Command::new("net")
                .args(["user", &self.0, "/delete"])
                .output();
        }
    }
}

#[test]
fn setup_then_a_run_as_the_account_then_remove() {
    let (sb, project) = installed_with_secret();
    let account = format!("openmoat-t{}", std::process::id() % 100_000);
    let _cleanup = Cleanup(account.clone());
    let allowed = sb.home.join("notes.txt");
    std::fs::write(&allowed, "READABLE-NOTE").unwrap();

    let out = person(&sb, &account, &["agent-account", "setup"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(account_exists(&account), "{}", text(&out));
    let record: Value = serde_json::from_str(
        &std::fs::read_to_string(sb.home.join(".moat/agent-account.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(record["account"], account.as_str());
    // Eight filters, their provider and sublayer, a range of eight ports.
    let wfp = &record["wfp"];
    let filters = wfp["filters"].as_array().unwrap();
    assert_eq!(filters.len(), 8, "{record}");
    let ports = wfp["ports"].as_array().unwrap();
    assert_eq!(
        ports[1].as_u64().unwrap() - ports[0].as_u64().unwrap(),
        7,
        "{record}"
    );
    let keys: Vec<String> = [&wfp["provider"], &wfp["sublayer"]]
        .into_iter()
        .chain(filters.iter().map(|f| &f["key"]))
        .map(|k| k.as_str().unwrap().to_owned())
        .collect();
    assert!(network::engine_holds_any(&sb.home, &keys[2..]), "{record}");
    // Status reads them back and finds no drift.
    let out = person(&sb, &account, &["agent-account", "status"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        stdout(&out).contains("matches its record"),
        "{}",
        text(&out)
    );
    assert!(
        stdout(&out).contains("8 Windows Filtering Platform filters"),
        "{}",
        text(&out)
    );

    // The plan names the account, its filters and the read denies: 100, the
    // network the filters', its name lookups a `dns` downgrade.
    let out = output(
        sb.command()
            .current_dir(&project)
            .env(NAME, &account)
            .args(["run", "--print-boundary", "--format", "json", "--", "cmd"]),
        None,
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let plan: Value = serde_json::from_str(&stdout(&out)).unwrap();
    let names: Vec<&str> = plan["restrictions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    assert_eq!(
        names,
        [
            "agent_account",
            "job_object",
            "wfp_network",
            "windows_read_deny"
        ]
    );
    assert_eq!(plan["score"]["points"], 100, "{plan}");
    assert_eq!(plan["network"]["mode"], "wfp_account", "{plan}");
    assert_eq!(plan["downgrades"][0]["what"], "dns", "{plan}");

    network::the_filters_hold_the_account(&sb, &project, &account);

    // A file of the profile the policy does not deny reads.
    let out = run_cmd(
        &sb,
        &project,
        &account,
        &format!("type {}", allowed.display()),
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(stdout(&out).contains("READABLE-NOTE"), "{}", text(&out));
    assert!(
        stderr(&out).contains("as the agent account"),
        "{}",
        text(&out)
    );

    // `~/.ssh` is denied by the policy: Windows refuses it to the account.
    let key = sb.home.join(".ssh").join("id_rsa");
    let out = run_cmd(&sb, &project, &account, &format!("type {}", key.display()));
    assert_eq!(out.status.code(), Some(FAILED), "{}", text(&out));
    assert!(!stdout(&out).contains("FAKE-SSH-KEY"), "{}", text(&out));

    // A write in the project goes through; one in the home, outside every
    // write root, is refused.
    let inside = project.join("inside.txt");
    let out = run_cmd(
        &sb,
        &project,
        &account,
        &format!("echo in>{}", inside.display()),
    );
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(inside.exists(), "{}", text(&out));
    let planted = sb.home.join("planted.txt");
    let out = run_cmd(
        &sb,
        &project,
        &account,
        &format!("echo x>{}", planted.display()),
    );
    assert_eq!(out.status.code(), Some(FAILED), "{}", text(&out));
    assert!(!planted.exists(), "the write in the home went through");

    // `remove` undoes it all; status then finds nothing.
    let out = person(&sb, &account, &["agent-account", "remove"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(!account_exists(&account), "{}", text(&out));
    assert!(!sb.home.join(".moat/agent-account.json").exists());
    assert!(
        !network::engine_holds_any(&sb.home, &keys),
        "the filters are still there"
    );
    let out = person(&sb, &account, &["agent-account", "status"]);
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(text(&out).contains("no agent account"), "{}", text(&out));
    // The next run is ADR-115's again.
    let out = run_cmd(&sb, &project, &account, "echo back");
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    assert!(
        stderr(&out).contains("Windows preview tier"),
        "{}",
        text(&out)
    );
    assert!(
        !stderr(&out).contains("as the agent account"),
        "{}",
        text(&out)
    );
}
