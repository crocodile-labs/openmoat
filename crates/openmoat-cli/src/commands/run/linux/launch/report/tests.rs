use openmoat_core::boundary::Enforcement;

use super::*;

fn bound() -> (tempfile::TempDir, std::path::PathBuf, Reports) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("check.sock");
    let reports = Reports::bind(&path).unwrap();
    (dir, path, reports)
}

/// A report that names no gap of its own but shows one in its fields.
fn silent_gap() -> LaunchCheck {
    LaunchCheck {
        landlock: Some(Enforcement::Full),
        proc_no_new_privs: Some(true),
        proc_seccomp_filter: Some(false),
        ..LaunchCheck::default()
    }
}

/// A report without the nonce is not the run's: the next one is read, and
/// the gap it does not name is found here.
#[test]
fn only_the_report_with_the_nonce_counts_and_its_gaps_are_found_here() {
    let (_dir, path, reports) = bound();
    let mut forged = UnixStream::connect(&path).unwrap();
    writeln!(
        forged,
        "0000 {{\"landlock\":\"full\",\"in_bubblewrap\":false}}"
    )
    .unwrap();
    let mut real = UnixStream::connect(&path).unwrap();
    let json = serde_json::to_string(&silent_gap()).unwrap();
    writeln!(real, "{} {json}", reports.nonce).unwrap();
    let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
    let (got, _stream) = reports.receive(&mut child).unwrap().unwrap();
    tree::stop(&mut child);
    assert!(got.in_bubblewrap);
    let failure = got.failure.unwrap();
    assert!(failure.contains("Seccomp: 2"), "{failure}");
}

/// No report while bubblewrap runs on: a failure, not a wait forever.
#[test]
fn no_report_in_time_is_a_failure() {
    let (_dir, _path, mut reports) = bound();
    reports.wait = Duration::from_millis(200);
    let mut child = Command::new("/bin/sleep").arg("5").spawn().unwrap();
    let error = reports.receive(&mut child).unwrap_err();
    tree::stop(&mut child);
    assert!(format!("{error:#}").contains("did not report"), "{error:#}");
}

/// Bubblewrap that ends before anyone connected started no agent.
#[test]
fn bubblewrap_that_ends_unreported_started_nothing() {
    let (_dir, _path, reports) = bound();
    let mut child = Command::new("/bin/true").spawn().unwrap();
    let _ = child.wait();
    assert!(reports.receive(&mut child).unwrap().is_none());
}

/// Inside: [`GO`] lets the agent run on; [`STOP`], a closed connection or
/// no reply in time is an error, on which the agent is stopped.
#[test]
fn inside_only_go_lets_the_agent_run_on() {
    for (reply, ok) in [(Some(GO), true), (Some(STOP), false), (None, false)] {
        let (outside, inside) = UnixStream::pair().unwrap();
        let answer = std::thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(&outside).read_line(&mut line).unwrap();
            assert!(line.starts_with("testnonce {"), "{line}");
            if let Some(byte) = reply {
                (&outside).write_all(&[byte]).unwrap();
            }
        });
        let result = exchange(inside, "testnonce", &LaunchCheck::default(), WAIT);
        answer.join().unwrap();
        assert_eq!(result.is_ok(), ok, "{reply:?}: {result:?}");
    }
    let (_outside, inside) = UnixStream::pair().unwrap();
    let silent = exchange(
        inside,
        "testnonce",
        &LaunchCheck::default(),
        Duration::from_millis(100),
    );
    assert!(silent.is_err());
}
