use super::*;

#[test]
fn one_holder_gets_at_most_half_the_slots() {
    let shares = Shares::new(8);
    assert_eq!(shares.cap(), 4);
    let a: Vec<_> = (0..4).map(|_| shares.take("run-a").unwrap()).collect();
    assert!(
        shares.take("run-a").is_none(),
        "a fifth connection of one session"
    );
    // Another session, and the unauthenticated holder, keep their own share.
    let b: Vec<_> = (0..4).map(|_| shares.take("run-b").unwrap()).collect();
    assert!(shares.take(PENDING).is_some());
    assert_eq!((shares.held("run-a"), shares.held("run-b")), (4, 4));
    drop(a);
    drop(b);
}

#[test]
fn a_share_is_given_back_when_its_connection_ends() {
    let shares = Shares::new(2);
    let first = shares.take("run-a").unwrap();
    assert!(shares.take("run-a").is_none());
    drop(first);
    assert_eq!(shares.held("run-a"), 0);
    assert!(shares.take("run-a").is_some());
}

#[test]
fn a_proxy_with_one_slot_still_serves_one_connection() {
    let shares = Shares::new(1);
    assert_eq!(shares.cap(), 1);
    let _held = shares.take("run-a").unwrap();
    assert!(shares.take("run-a").is_none());
}
