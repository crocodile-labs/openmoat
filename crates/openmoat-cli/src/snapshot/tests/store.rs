//! The store as a whole: retention, pruning and its lock.

use super::*;

#[test]
fn retention_keeps_the_newest_and_drops_by_count_and_age() {
    let listed = |ages: &[i64]| -> Vec<Listed> {
        ages.iter()
            .enumerate()
            .map(|(i, ts)| Listed {
                id: format!("{i}"),
                commit: format!("{i}"),
                tree: String::new(),
                refname: format!("r{i}"),
                ts_ms: *ts,
                meta: Meta {
                    version: META_VERSION,
                    reason: Reason::Manual,
                    session: None,
                    files: 0,
                    bytes: 0,
                    left_out: Vec::new(),
                    left_out_total: 0,
                    ignored: Vec::new(),
                    ignored_total: 0,
                },
            })
            .collect()
    };
    let r = Retention {
        keep: 2,
        max_age_ms: 100,
    };
    let ids = |v: Vec<&Listed>| v.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
    assert_eq!(ids(r.expired(&listed(&[1000, 1000, 1000]), 1000)), ["0"]);
    assert_eq!(ids(r.expired(&listed(&[0, 990]), 1000)), ["0"]);
    // The newest stays however old it is.
    assert_eq!(ids(r.expired(&listed(&[0]), 1000)), Vec::<String>::new());
}

#[test]
fn pruning_removes_snapshots_from_the_store() {
    let f = fixture();
    for n in 0..3 {
        f.write("a.txt", &format!("{n}\n"));
        f.take(Reason::Manual);
    }
    let keep_one = Retention {
        keep: 1,
        max_age_ms: i64::MAX,
    };
    assert_eq!(
        f.store
            .prune(&f.held(), keep_one, crate::time::now_ms())
            .unwrap(),
        2
    );
    let left = f.store.list().unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(f.files(&left[0]), ["a.txt"]);
}

#[test]
fn one_process_at_a_time_holds_the_store() {
    let f = fixture();
    let held = f.held();
    let busy = f.store.lock(std::time::Duration::ZERO).unwrap_err();
    assert!(format!("{busy:#}").contains("try again"), "{busy:#}");
    drop(held);
    f.held();
}

/// Two takes and a prune at once, as two `openmoat run` in one project do:
/// every snapshot left is whole, and no take failed on a shared index.
#[test]
fn takes_and_a_prune_at_once_lose_no_object() {
    let f = fixture();
    f.write("a.txt", "a\n");
    let keep_two = Retention {
        keep: 2,
        max_age_ms: i64::MAX,
    };
    std::thread::scope(|s| {
        for run in ["run-a", "run-b"] {
            let f = &f;
            s.spawn(move || {
                for n in 0..3 {
                    let held = f.store.lock(LOCK_WAIT).unwrap();
                    f.write(&format!("{run}.txt"), &format!("{n}\n"));
                    f.store
                        .take(
                            &held,
                            &f.denied,
                            Limits::default(),
                            Reason::Manual,
                            Some(run),
                        )
                        .unwrap();
                }
            });
        }
        s.spawn(|| {
            for _ in 0..2 {
                let held = f.store.lock(LOCK_WAIT).unwrap();
                f.store
                    .prune(&held, keep_two, crate::time::now_ms())
                    .unwrap();
            }
        });
    });
    f.store
        .git
        .output(&["fsck", "--connectivity-only", "--no-dangling"], None)
        .unwrap();
    for snapshot in f.store.list().unwrap() {
        assert!(f.files(&snapshot).contains(&"a.txt".to_owned()));
    }
}

/// An object no snapshot holds yet (a take that has not written its ref) is
/// not dropped by a prune.
#[test]
fn a_prune_keeps_objects_younger_than_its_grace() {
    let f = fixture();
    for n in 0..2 {
        f.write("a.txt", &format!("{n}\n"));
        f.take(Reason::Manual);
    }
    let in_flight = f
        .store
        .git
        .text(&["hash-object", "-w", "--stdin"], Some(b"a take's file\n"))
        .unwrap();
    let keep_one = Retention {
        keep: 1,
        max_age_ms: i64::MAX,
    };
    f.store
        .prune(&f.held(), keep_one, crate::time::now_ms())
        .unwrap();
    f.store
        .git
        .output(&["cat-file", "-e", &in_flight], None)
        .unwrap();
}
