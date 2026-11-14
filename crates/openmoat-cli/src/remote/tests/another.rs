//! A second channel, registered beside the real ones, goes end to end through
//! the unchanged core: connect, approver ids, open, a prompt shaped to its
//! capabilities (no buttons: reply codes), an answer, and the one allowed
//! call. Adding a channel needs a spec, a `Channel` and a registry row.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::time::Duration;

use anyhow::Result;
use openmoat_audit::KnownSecrets;
use openmoat_core::Verdict;

use super::super::answer::{self, Answer};
use super::super::channel::{
    Capabilities, Channel, Credential, Field, Options, Prompt, Registry, Reply, Secrets, Spec,
};
use super::super::listen::Listener;
use super::super::settings::{DEFAULT_EXPIRY_S, Settings};
use super::super::store::{DIR, Store};
use super::super::{REGISTRY, connect, gate, open};
use super::{NOW, Rows, call, review};
use crate::proxy_session::Key;

thread_local! {
    static OUTBOX: RefCell<Vec<(String, Prompt)>> = const { RefCell::new(Vec::new()) };
    static INBOX: RefCell<VecDeque<Reply>> = const { RefCell::new(VecDeque::new()) };
}

/// A text-only pager: no buttons, short messages, two secrets and one setting.
static PAGER: Spec = Spec {
    name: "pager",
    title: "Pager",
    capabilities: Capabilities {
        buttons: false,
        button_bytes: 0,
        max_text: 1200,
        poll_wait: Duration::ZERO,
    },
    fields: &[
        Field {
            key: "key",
            ask: "Pager key: ",
            secret: true,
            valid: |c| c.starts_with("pk-") && c.len() > 8,
        },
        Field {
            key: "signing_secret",
            ask: "Signing secret: ",
            secret: true,
            valid: |c| c.len() >= 16,
        },
        Field {
            key: "room",
            ask: "Room: ",
            secret: false,
            valid: |r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_lowercase()),
        },
    ],
    user_id: "a pager number",
    valid_user: |id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()),
    open: |secrets: &Secrets, options: &Options| {
        anyhow::ensure!(secrets.get("key").is_some_and(|k| k.as_str() == KEY));
        anyhow::ensure!(options.get("room").map(String::as_str) == Some("ops"));
        Ok(Box::new(Pager))
    },
    next_steps: |account| format!("page {account}"),
    revoke: "rotate the pager key",
};

struct Pager;

impl Channel for Pager {
    fn account(&mut self) -> Result<String> {
        Ok("pager-bot".to_owned())
    }
    fn send(&mut self, to: &str, prompt: &Prompt) -> Result<()> {
        OUTBOX.with(|o| o.borrow_mut().push((to.to_owned(), prompt.clone())));
        Ok(())
    }
    fn notify(&mut self, _: &str, _: &str) -> Result<()> {
        Ok(())
    }
    fn poll(&mut self, _: Duration) -> Result<Vec<Reply>> {
        Ok(INBOX.with(|i| i.borrow_mut().drain(..).collect()))
    }
    fn settle(&mut self, _: &Reply, _: &str) -> Result<()> {
        Ok(())
    }
}

/// Made up for the test.
const KEY: &str = "pk-12345678";
const SIGNING: &str = "0123456789abcdef";

fn secrets_of(key: &str, signing: &str) -> Secrets {
    Secrets::from([
        ("key".to_owned(), Credential::new(key.to_owned())),
        (
            "signing_secret".to_owned(),
            Credential::new(signing.to_owned()),
        ),
    ])
}

/// This build's channels and the pager.
fn registry() -> Registry {
    let all: Vec<&'static Spec> = REGISTRY.0.iter().copied().chain([&PAGER]).collect();
    Registry(Box::leak(all.into_boxed_slice()))
}

fn text(from: &str, text: &str) -> Reply {
    Reply {
        from: from.to_owned(),
        name: "someone".to_owned(),
        text: Some(text.to_owned()),
        ..Reply::default()
    }
}

#[test]
fn a_second_channel_works_through_the_unchanged_core() {
    let registry = registry();
    registry.check().unwrap();
    let pager = registry.find("pager").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path().join(DIR));
    let room = |r: &str| Options::from([("room".to_owned(), r.to_owned())]);

    // Nothing is saved for a bad or missing secret, a missing or bad setting,
    // or a secret given as a setting.
    let mut as_setting = room("ops");
    as_setting.insert("key".to_owned(), KEY.to_owned());
    for (secrets, options) in [
        (secrets_of("nope", SIGNING), room("ops")),
        (
            Secrets::from([("key".to_owned(), Credential::new(KEY.to_owned()))]),
            room("ops"),
        ),
        (secrets_of(KEY, SIGNING), Options::new()),
        (secrets_of(KEY, SIGNING), room("Ops!")),
        (secrets_of(KEY, SIGNING), as_setting),
    ] {
        assert!(connect(&store, pager, &secrets, options, DEFAULT_EXPIRY_S).is_err());
        assert!(!store.connected());
    }
    let account = connect(
        &store,
        pager,
        &secrets_of(KEY, SIGNING),
        room("ops"),
        DEFAULT_EXPIRY_S,
    )
    .unwrap();
    assert_eq!(account, "pager-bot");
    let files = store.channel(pager);
    assert!(files.dir().ends_with("remote/pager"));
    assert!(files.credential_path().is_file() && files.settings_path().is_file());
    // The secrets are in the credential file only, and read back checked.
    let settings_text = std::fs::read_to_string(files.settings_path()).unwrap();
    assert!(!settings_text.contains(KEY) && !settings_text.contains(SIGNING));
    assert!(
        settings_text.contains("\"room\": \"ops\""),
        "{settings_text}"
    );
    let read = files.read_secrets(pager).unwrap();
    assert_eq!(
        read.get("signing_secret").map(|s| s.as_str()),
        Some(SIGNING)
    );
    crate::home::write_private(&files.credential_path(), br#"{"key":"pk-12345678"}"#).unwrap();
    let missing = format!("{:#}", files.read_secrets(pager).unwrap_err());
    assert!(!missing.contains(KEY), "{missing}");
    crate::home::write_private(&files.credential_path(), b"pk-12345678").unwrap();
    assert!(files.read_secrets(pager).is_err());
    files.put_secrets(&secrets_of(KEY, SIGNING)).unwrap();

    // Approver ids are qualified with the channel; another channel's are refused.
    assert_eq!(registry.approver(pager, "77").unwrap(), "pager:77");
    assert_eq!(registry.approver(pager, "pager:77").unwrap(), "pager:77");
    for other in REGISTRY.0 {
        assert!(
            registry
                .approver(pager, &format!("{}:77", other.name))
                .is_err()
        );
    }
    assert!(registry.approver(pager, "x7").is_err());
    let key = Key::load(&store.key_path()).unwrap();
    let mut settings = Settings::load(&store.settings_path(), &key).unwrap();
    assert_eq!(settings.channel, "pager");
    settings.approvers.push("pager:77".to_owned());
    settings.save(&store.settings_path(), &key).unwrap();

    // A held call goes out as text with reply codes, as the pager has no buttons.
    let req = call("s1", "npm publish");
    gate(&store, &req, review(), &KnownSecrets::default(), NOW);
    let request = only_request_in(&store);
    let (spec, mut channel) = open(&store, &registry, &key, &settings).unwrap();
    assert_eq!(spec.name, "pager");
    let mut rows = Rows::default();
    let mut listener = Listener::new(&store, &key, spec, settings.clone());
    listener
        .step(channel.as_mut(), &mut rows, Duration::ZERO, &|| NOW + 1)
        .unwrap();
    let (to, prompt) = OUTBOX.with(|o| o.borrow()[0].clone());
    assert_eq!(to, "77", "sent to the pager's own id");
    assert_eq!(prompt.choices, Vec::new());
    let code = answer::button(&key, answer::Verdict::Approve, &request);
    assert!(prompt.text.contains(&code), "{}", prompt.text);
    assert!(prompt.text.chars().count() <= 1200);

    // The same code from someone else is refused; from the approver it stands.
    INBOX.with(|i| {
        let mut i = i.borrow_mut();
        i.push_back(text("78", &code));
        i.push_back(text("77", &format!("  {code}\n")));
    });
    listener
        .step(channel.as_mut(), &mut rows, Duration::ZERO, &|| NOW + 2)
        .unwrap();
    assert!(
        rows.0
            .iter()
            .any(|r| r.reason.contains("pager:78 is not an approver")),
        "{:?}",
        rows.0
    );
    let answer = store.answer(&request.id).unwrap();
    assert_eq!(
        (answer.approver.as_str(), answer.channel.as_str()),
        ("pager:77", "pager")
    );
    let allowed = gate(&store, &req, review(), &KnownSecrets::default(), NOW + 3);
    assert_eq!(allowed.verdict, Verdict::Allow, "{allowed:?}");
}

/// The same user number on two channels is two approvers: an answer signed
/// for `<other>:77` never counts where `pager:77` is allowed.
#[test]
fn ids_of_two_channels_never_collide() {
    let registry = registry();
    let pager = registry.find("pager").unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = Store::at(dir.path().join(DIR));
    let options = Options::from([("room".to_owned(), "ops".to_owned())]);
    connect(
        &store,
        pager,
        &secrets_of(KEY, SIGNING),
        options,
        DEFAULT_EXPIRY_S,
    )
    .unwrap();
    let key = Key::load(&store.key_path()).unwrap();
    let mut settings = Settings::load(&store.settings_path(), &key).unwrap();
    settings.approvers.push("pager:77".to_owned());
    settings.save(&store.settings_path(), &key).unwrap();
    // An approver of another channel cannot even be written to the list.
    let mut wrong = settings.clone();
    wrong.approvers.push("other:77".to_owned());
    assert!(wrong.save(&store.settings_path(), &key).is_err());

    let req = call("s1", "npm publish");
    gate(&store, &req, review(), &KnownSecrets::default(), NOW);
    let request = only_request_in(&store);
    for (approver, channel) in [
        ("other:77", "other"),
        ("pager:77", "other"),
        ("77", "pager"),
    ] {
        let forged = Answer::signed(
            &key,
            &request,
            (answer::Verdict::Approve, approver, channel),
            NOW,
        )
        .unwrap();
        store.forget_answer(&request.id);
        store.put_answer(&forged).unwrap();
        let d = gate(&store, &req, review(), &KnownSecrets::default(), NOW + 1);
        assert_eq!(d.verdict, Verdict::Review, "{approver} on {channel}: {d:?}");
    }
}

fn only_request_in(store: &Store) -> super::super::request::Request {
    let all: Vec<_> = store.requests().unwrap().into_iter().flatten().collect();
    assert_eq!(all.len(), 1, "{all:?}");
    all.into_iter().next().unwrap()
}
