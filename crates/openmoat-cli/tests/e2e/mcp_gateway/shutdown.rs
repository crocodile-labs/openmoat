//! `openmoat mcp proxy`'s bounded shutdown through the real binary: a server
//! that keeps running after the agent closed the proxy's input is stopped and
//! reaped (ADR-107).

use std::time::{Duration, Instant};

use super::{Gateway, Live};

#[test]
fn closing_stdin_reaps_an_upstream_that_ignores_eof() {
    let gateway = Gateway::new();
    let mut proxy = Live::start(&gateway, "stubborn");
    let ready = Instant::now() + Duration::from_secs(5);
    let pid = loop {
        if let Some(pid) = gateway
            .received()
            .first()
            .and_then(|row| row["pid"].as_u64())
        {
            break pid;
        }
        assert!(Instant::now() < ready, "server never started");
        std::thread::sleep(Duration::from_millis(20));
    };
    drop(proxy.stdin.take());
    // The proxy waits 5 s for the server to close its output, then 5 s after
    // SIGTERM before SIGKILL; leave room for a busy runner.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = proxy.child.try_wait().unwrap() {
            assert!(!status.success(), "forced shutdown must not report success");
            break;
        }
        if Instant::now() >= deadline {
            let _ = proxy.child.kill();
            let _ = proxy.child.wait();
            panic!("upstream {pid} prevented the proxy from exiting after EOF");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = rustix::process::Pid::from_raw(i32::try_from(pid).unwrap()).unwrap();
    assert_eq!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    );
}
