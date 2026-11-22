use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::*;

/// A shell in its own process group running `script`.
fn server(script: &str) -> Child {
    own(Command::new("/bin/sh").args(["-c", script]))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .unwrap()
}

/// Time for the shell to set its trap.
fn settle() {
    std::thread::sleep(Duration::from_millis(200));
}

#[test]
fn a_server_is_asked_to_stop_before_it_is_killed() {
    let mut child = server("trap 'exit 7' TERM; while :; do sleep 0.05; done");
    settle();
    let started = Instant::now();
    let status = stop(&mut child, Duration::from_secs(5)).unwrap();
    assert_eq!(status.code(), Some(7), "the server got SIGTERM and exited");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn a_server_that_ignores_the_request_is_killed_after_the_grace() {
    use std::os::unix::process::ExitStatusExt as _;
    let mut child = server("trap '' TERM; while :; do sleep 0.05; done");
    settle();
    let started = Instant::now();
    let status = stop(&mut child, Duration::from_millis(300)).unwrap();
    assert_eq!(status.signal(), Some(9), "{status:?}");
    assert!(started.elapsed() >= Duration::from_millis(300));
}

#[test]
fn the_server_side_ends_the_drain_and_carries_its_result() {
    let (done, finished) = mpsc::channel();
    done.send(Pump::Host).unwrap();
    done.send(Pump::Server(Ok(()))).unwrap();
    assert!(drain(&finished, Duration::from_millis(50)).is_ok());
    done.send(Pump::Server(Err(anyhow::Error::msg("broken"))))
        .unwrap();
    assert!(drain(&finished, Duration::from_millis(50)).is_err());
}

#[test]
fn a_server_that_keeps_its_output_open_after_the_agent_left_times_out() {
    let (done, finished) = mpsc::channel();
    done.send(Pump::Host).unwrap();
    let error = drain(&finished, Duration::from_millis(50)).unwrap_err();
    assert!(
        format!("{error:#}").contains("did not close its output"),
        "{error:#}"
    );
    drop(done);
}
