//! The protection score (ADR-108): `--print-boundary` carries it, `doctor`
//! names it per tier, and `sandbox.strict: true` refuses a run whose score is
//! not whole, before anything starts. macOS's Seatbelt profile is the whole of
//! its score; on Linux the Isolated tier on Landlock ABI 10 is.

use serde_json::Value;

use super::boundary::print_boundary;
use super::confined::ran;
use super::{LIGHTWEIGHT, installed_with_secret, run_sh_flags};
use crate::common::{OK, Sandbox, USAGE, stderr, stdout, text};

/// `sb` with `sandbox.strict: true` in the user policy, re-pinned as a
/// person would.
fn strict(sb: &Sandbox) {
    let path = sb.home.join(".moat/policy.yaml");
    let policy = std::fs::read_to_string(&path).unwrap();
    let edited = policy.replacen("\nsandbox:\n", "\nsandbox:\n  strict: true\n", 1);
    assert_ne!(
        policy, edited,
        "the default policy has a `sandbox:` section"
    );
    std::fs::write(&path, edited).unwrap();
    let out = sb.moat_as_person(&["doctor", "--accept"]);
    assert!(text(&out).contains("re-pinned"), "{}", text(&out));
}

/// The plan's score: the points, and its items by name.
fn score(out: &std::process::Output) -> Value {
    let record: Value = serde_json::from_slice(&out.stdout).unwrap();
    record["score"].clone()
}

#[test]
fn print_boundary_carries_the_score_and_doctor_names_each_tier() {
    let (sb, project) = installed_with_secret();
    let out = print_boundary(&sb, &project, &[LIGHTWEIGHT]);
    if stderr(&out).contains("needs macOS 13") {
        eprintln!("skipped: `openmoat run` refuses on this macOS");
        return;
    }
    assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
    let score = score(&out);
    let points = score["points"].as_u64().unwrap();
    assert!(points <= 100, "{score}");
    if cfg!(target_os = "macos") {
        assert_eq!(points, 100, "{score}");
    } else {
        // `--no-isolate`: the Isolated tier's view is not asked for.
        assert!(points < 100, "{score}");
        let view = score["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["name"] == "isolated_view")
            .unwrap();
        assert_eq!(view["in_force"], false, "{score}");
        assert!(
            view["missing"].as_str().unwrap().contains("--isolate"),
            "{score}"
        );
    }
    let doctor = text(&sb.moat(&["doctor"]));
    assert!(doctor.contains("hook-only"), "{doctor}");
    assert!(doctor.contains("0/100"), "{doctor}");
    assert!(doctor.contains("lightweight"), "{doctor}");
}

/// `sandbox.strict: true`: a whole score starts, a partial one is refused
/// with what is missing named, and nothing starts.
#[test]
fn strict_refuses_a_partial_score_and_starts_a_whole_one() {
    let (sb, project) = installed_with_secret();
    strict(&sb);
    let plan = print_boundary(&sb, &project, &[]);
    if stderr(&plan).contains("needs macOS 13") {
        eprintln!("skipped: `openmoat run` refuses on this macOS");
        return;
    }
    let whole = score(&plan)["items"]
        .as_array()
        .is_some_and(|items| items.iter().all(|i| i["in_force"] == true));
    let out = run_sh_flags(&sb, &project, &[], "echo started", &[]);
    if whole {
        if !ran(&out) {
            return;
        }
        assert_eq!(out.status.code(), Some(OK), "{}", text(&out));
        assert!(stdout(&out).contains("started"), "{}", text(&out));
    } else {
        assert_eq!(plan.status.code(), Some(USAGE), "{}", text(&plan));
        assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
        assert!(
            stderr(&out).contains("sandbox.strict: true"),
            "{}",
            text(&out)
        );
        assert!(stderr(&out).contains("missing:"), "{}", text(&out));
        assert!(!stdout(&out).contains("started"), "{}", text(&out));
    }
    // `--no-isolate` on Linux gives up the view: never whole there.
    if cfg!(target_os = "linux") {
        let out = run_sh_flags(&sb, &project, &[LIGHTWEIGHT], "echo started", &[]);
        assert_eq!(out.status.code(), Some(USAGE), "{}", text(&out));
        assert!(stderr(&out).contains("isolated_view"), "{}", text(&out));
        assert!(!stdout(&out).contains("started"), "{}", text(&out));
    }
}
