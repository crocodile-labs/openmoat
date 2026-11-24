//! The two bodies a Streamable HTTP server answers a `POST` with: one JSON-RPC
//! message as `application/json`, or a `text/event-stream` of them, one per
//! event's `data` (MCP's Streamable HTTP transport; the HTML Standard's
//! server-sent events). Only whole events are read: a stream cut in the
//! middle of one leaves that event out, and the relay never sees half a
//! message.

/// The body's kind, from its `Content-Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `application/json`: the body is one message (or batch).
    Json,
    /// `text/event-stream`: each event's data is one message.
    Events,
}

impl Kind {
    /// The kind `content_type` names, if it is one of the two.
    pub fn of(content_type: &str) -> Option<Self> {
        let media = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match media.as_str() {
            "application/json" => Some(Self::Json),
            "text/event-stream" => Some(Self::Events),
            _ => None,
        }
    }
}

/// The data of every whole event in `stream`, in order. Comments (`:`), `id`,
/// `retry`, events with no data and an event the stream stopped in are
/// skipped; an event's type is not read (MCP sends `message`).
pub fn events(stream: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(stream);
    let mut out = Vec::new();
    let mut data: Option<String> = None;
    // Lines end at CRLF, LF or CR; an event ends at a blank line. The last
    // line has no end yet when the stream stops in it, so it is not read.
    let normalised = text.replace("\r\n", "\n").replace('\r', "\n");
    let Some(whole) = normalised.rfind('\n').map(|end| &normalised[..=end]) else {
        return out;
    };
    for line in whole.split_inclusive('\n') {
        let line = line.trim_end_matches('\n');
        if line.is_empty() {
            if let Some(event) = data.take()
                && !event.is_empty()
            {
                out.push(event);
            }
            continue;
        }
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        if field == "data" {
            let event = data.get_or_insert_with(String::new);
            if !event.is_empty() {
                event.push('\n');
            }
            event.push_str(value);
        }
    }
    out
}
