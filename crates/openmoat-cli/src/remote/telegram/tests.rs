//! The Telegram adapter against a fake Bot API: no network, no real token.

use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};

use super::*;
use crate::remote::channel::{Channel as _, Prompt};

#[derive(Default)]
struct FakeApi {
    calls: Vec<(String, Value)>,
    answers: Vec<Value>,
}

impl Api for &mut FakeApi {
    fn call(&mut self, method: &str, body: &Value, _: Duration) -> Result<Value> {
        self.calls.push((method.to_owned(), body.clone()));
        Ok(if self.answers.is_empty() {
            json!({ "ok": true, "result": true })
        } else {
            self.answers.remove(0)
        })
    }
}

/// Made up at run time, shaped like a token; no real one.
fn token() -> String {
    format!("{}:{}", 123_456, "A".repeat(35))
}

#[test]
fn token_and_user_shapes() {
    assert!(valid_token(&token()));
    for bad in [
        "",
        "abc",
        "12:short",
        ":AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "1 2:x",
    ] {
        assert!(!valid_token(bad), "{bad}");
    }
    assert!(!valid_token(&format!("{}\n", token()).replace(':', ":\n")));
    assert!(valid_user("4242"));
    for bad in ["", "0", "-5", "@me", "12a"] {
        assert!(!valid_user(bad), "{bad}");
    }
}

#[test]
fn a_prompt_is_plain_text_with_two_buttons_and_no_preview() {
    let mut api = FakeApi::default();
    let mut telegram = Telegram::new(&mut api);
    let prompt = Prompt {
        text: "<b>run</b> https://evil.test".to_owned(),
        approve: "a.x.y".to_owned(),
        deny: "d.x.y".to_owned(),
    };
    telegram.send("4242", &prompt).unwrap();
    let (method, body) = &api.calls[0];
    assert_eq!(method, "sendMessage");
    assert_eq!(body["chat_id"], 4242);
    assert_eq!(body["text"], "<b>run</b> https://evil.test");
    assert_eq!(body.get("parse_mode"), None, "no markup is rendered");
    assert_eq!(body["link_preview_options"]["is_disabled"], true);
    let row = &body["reply_markup"]["inline_keyboard"][0];
    assert_eq!(row[0]["callback_data"], "a.x.y");
    assert_eq!(row[1]["callback_data"], "d.x.y");
}

#[test]
fn updates_become_replies_and_move_the_offset() {
    let mut api = FakeApi {
        answers: vec![json!({ "ok": true, "result": [
            { "update_id": 7, "callback_query": { "id": "cb1",
                "from": { "id": 4242, "is_bot": false, "username": "me" }, "data": "a.x.y" } },
            { "update_id": 8, "message": { "from": { "id": 99, "is_bot": false,
                "first_name": "Stranger" }, "text": "/start" } },
            { "update_id": 9, "message": { "from": { "id": 5, "is_bot": true } } },
            { "update_id": 10, "callback_query": { "id": "cb2" } }
        ]})],
        ..FakeApi::default()
    };
    let mut telegram = Telegram::new(&mut api);
    let replies = telegram.poll(Duration::from_secs(1)).unwrap();
    assert_eq!(telegram.offset, 11);
    assert_eq!(replies.len(), 2, "{replies:?}");
    assert_eq!(replies[0].from, "4242");
    assert_eq!(replies[0].button.as_deref(), Some("a.x.y"));
    assert_eq!(replies[0].handle, "cb1");
    assert_eq!(replies[1].from, "99");
    assert_eq!(replies[1].button, None);
    telegram.poll(Duration::from_secs(1)).unwrap();
    assert_eq!(api.calls[1].1["offset"], 11);
}

#[test]
fn a_refusal_names_telegrams_reason_not_the_token() {
    let mut api = FakeApi {
        answers: vec![json!({ "ok": false, "error_code": 401, "description": "Unauthorized" })],
        ..FakeApi::default()
    };
    let error = Telegram::new(&mut api).bot_name().unwrap_err();
    let text = format!("{error:#}");
    assert!(text.contains("Unauthorized"), "{text}");
    assert!(!text.contains(&token()), "{text}");
}

#[test]
fn settling_answers_the_button_and_tells_the_sender() {
    let mut api = FakeApi::default();
    let mut telegram = Telegram::new(&mut api);
    let reply = crate::remote::channel::Reply {
        from: "4242".to_owned(),
        name: "@me".to_owned(),
        button: Some("a.x.y".to_owned()),
        handle: "cb1".to_owned(),
    };
    telegram.settle(&reply, "Approved").unwrap();
    assert_eq!(api.calls[0].0, "answerCallbackQuery");
    assert_eq!(api.calls[0].1["callback_query_id"], "cb1");
    assert_eq!(api.calls[1].0, "sendMessage");
}

#[test]
fn response_bodies_by_length_chunks_or_end() {
    let by_length = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}xx";
    assert_eq!(https::body_of(by_length).unwrap(), b"{}xx");
    let chunked =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{\"\r\n3\r\nok\"\r\n0\r\n\r\n";
    assert_eq!(https::body_of(chunked).unwrap(), b"{\"ok\"");
    let to_end = b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}";
    assert_eq!(https::body_of(to_end).unwrap(), b"{\"ok\":true}");
    let cut = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n{}";
    assert!(https::body_of(cut).is_err());
    assert!(https::body_of(b"HTTP/1.1 200").is_err());
}

#[test]
fn a_token_file_others_may_read_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("telegram.token");
    crate::home::write_private(&path, token().as_bytes()).unwrap();
    assert_eq!(read_token(&path).unwrap().as_str(), token());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_token(&path).unwrap_err();
        assert!(!format!("{error:#}").contains(&token()));
    }
    crate::home::write_private(&path, b"not a token").unwrap();
    assert!(read_token(&path).is_err());
}
