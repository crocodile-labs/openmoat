//! Signed checkpoints over a real log (ADR-110): what they catch, checked
//! from the database and from an export, without the audit key.

use super::*;
use crate::{Checkpoint, CheckpointCheck, Frontier, SigningKey, check_export, testing};

fn log(events: usize) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let store = Store::open(&path).unwrap().with_chain_key(key());
    record_n(&store, events);
    (dir, path)
}

fn record_n(store: &Store, events: usize) {
    let d = decision(Verdict::Allow, "dev-shell", "ok");
    for i in 0..events {
        let a = Action::Shell {
            command: format!("echo {i}"),
        };
        store.record(&sample(&d, &a)).unwrap();
    }
}

fn signer() -> SigningKey {
    SigningKey::from_seed(&[3; 32]).unwrap()
}

/// The checkpoint `openmoat audit checkpoint` signs over `store` now, opened
/// again from its note as a verifier elsewhere would.
fn signed(store: &Store) -> Checkpoint {
    let frontier = store.frontier().unwrap();
    let key = signer();
    let note = key
        .sign(&Checkpoint {
            origin: key.verifier().name().to_owned(),
            size: frontier.size(),
            root: frontier.root(),
        })
        .unwrap();
    Checkpoint::open(&note, key.verifier()).unwrap()
}

fn export_text(store: &Store, filter: &ExportFilter<'_>) -> String {
    store
        .export(filter)
        .unwrap()
        .iter()
        .map(|l| serde_json::to_string(l).unwrap() + "\n")
        .collect()
}

#[test]
fn a_checkpoint_holds_over_the_log_and_its_export_and_after_more_events() {
    let (_dir, path) = log(9);
    let store = Store::open_existing(&path).unwrap().with_chain_key(key());
    let checkpoint = signed(&store);
    assert_eq!(checkpoint.size, 9);
    let holds = CheckpointCheck::Holds { size: 9, total: 9 };
    assert_eq!(store.check_checkpoint(&checkpoint).unwrap(), holds);
    // Without the audit key, on another machine: the export alone.
    let reader = Store::open_read_only(&path).unwrap();
    assert_eq!(reader.check_checkpoint(&checkpoint).unwrap(), holds);
    let text = export_text(&reader, &ExportFilter::default());
    assert_eq!(verify_export(&text, None).broken, None);
    assert_eq!(check_export(&text, &checkpoint), holds);
    // Later events leave an earlier checkpoint holding.
    record_n(&store, 4);
    assert_eq!(
        store.check_checkpoint(&checkpoint).unwrap(),
        CheckpointCheck::Holds { size: 9, total: 13 }
    );
}

#[test]
fn truncation_below_a_checkpoint_is_caught_although_the_chain_verifies() {
    let (_dir, path) = log(9);
    let checkpoint = signed(&Store::open_read_only(&path).unwrap());
    testing::truncate_after(&path, 6).unwrap();
    let store = Store::open_read_only(&path).unwrap().with_chain_key(key());
    assert_eq!(
        store.verify_chain().unwrap().broken,
        None,
        "a shorter chain verifies"
    );
    let truncated = CheckpointCheck::Truncated { size: 9, total: 6 };
    assert_eq!(store.check_checkpoint(&checkpoint).unwrap(), truncated);
    let text = export_text(&store, &ExportFilter::default());
    assert_eq!(check_export(&text, &checkpoint), truncated);
    // Dropping the newest lines of an export is the same cut.
    let full = export_text(
        &Store::open_read_only(&path).unwrap(),
        &ExportFilter::default(),
    );
    let cut: String = full.lines().take(3).flat_map(|l| [l, "\n"]).collect();
    assert!(!check_export(&cut, &checkpoint).holds());
}

#[test]
fn a_rewrite_that_recomputes_the_chain_changes_the_root() {
    let (_dir, path) = log(9);
    let checkpoint = signed(&Store::open_read_only(&path).unwrap());
    // Rewritten by someone with the database and the audit key too, as code
    // running as the user could: the chain and the MACs could be made to
    // verify, so only the hashes are recomputed here, and the root still moves.
    testing::rewrite_without_key(&path, 4, "deny").unwrap();
    let store = Store::open_read_only(&path).unwrap();
    assert_eq!(
        store.check_checkpoint(&checkpoint).unwrap(),
        CheckpointCheck::Differs { size: 9, total: 9 }
    );
    let text = export_text(&store, &ExportFilter::default());
    assert_eq!(
        verify_export(&text, None).broken,
        None,
        "the hashes link again"
    );
    assert!(!check_export(&text, &checkpoint).holds());
}

#[test]
fn an_export_that_does_not_start_at_the_first_event_is_not_checked() {
    let (_dir, path) = log(5);
    let store = Store::open_read_only(&path).unwrap();
    let checkpoint = signed(&store);
    // What `--since` leaves: the newest lines without the first.
    let full = export_text(&store, &ExportFilter::default());
    let tail: String = full.lines().skip(2).flat_map(|l| [l, "\n"]).collect();
    assert_eq!(
        check_export(&tail, &checkpoint),
        CheckpointCheck::NotWholeLog
    );
    // A host filter starts at the first event but leaves gaps: another root.
    let other = export_text(
        &store,
        &ExportFilter {
            host: Some("codex"),
            ..ExportFilter::default()
        },
    );
    assert!(!check_export(&other, &checkpoint).holds());
}

#[test]
fn the_frontier_extends_from_where_it_stopped_and_rebuilds_after_a_rewrite() {
    let (_dir, path) = log(5);
    let store = Store::open_existing(&path).unwrap().with_chain_key(key());
    let mut frontier = store.frontier().unwrap();
    let saved = Frontier::parse(&frontier.encode()).unwrap();
    record_n(&store, 6);
    assert!(!store.extend_frontier(&mut frontier).unwrap());
    assert_eq!(
        frontier,
        store.frontier().unwrap(),
        "incremental = from scratch"
    );
    assert_eq!(frontier.size(), 11);
    drop(store);
    // The saved state's last event is rewritten: it starts again from event 1.
    testing::rewrite_without_key(&path, 5, "deny").unwrap();
    let store = Store::open_read_only(&path).unwrap();
    let mut stale = saved;
    assert!(store.extend_frontier(&mut stale).unwrap());
    assert_eq!(stale, store.frontier().unwrap());
}
