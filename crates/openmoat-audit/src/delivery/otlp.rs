//! OTLP/HTTP logs in the JSON encoding: an `ExportLogsServiceRequest`
//! (opentelemetry-proto `collector/logs/v1`), as the OTLP specification's
//! "JSON Protobuf Encoding" writes it: lowerCamelCase field names, 64-bit
//! integers as decimal strings, enums as numbers.
//! <https://opentelemetry.io/docs/specs/otlp/#json-protobuf-encoding>

use serde_json::{Value, json};

use super::{Delivered, Gap, Origin};
use crate::StoreError;

/// `SeverityNumber` values of the logs data model.
/// <https://opentelemetry.io/docs/specs/otel/logs/data-model/#field-severitynumber>
const INFO: u8 = 9;
const INFO2: u8 = 10;
const WARN: u8 = 13;
const ERROR: u8 = 17;

/// The instrumentation scope every record carries.
const SCOPE: &str = "openmoat.audit";

/// One `ExportLogsServiceRequest` holding `records` and, as an `ERROR` record
/// each, the `gaps`, from one resource: `service.name` `openmoat`, its
/// version and `host.name` the configured machine name.
pub fn logs(
    origin: Origin<'_>,
    sent_ms: i64,
    records: &[Delivered],
    gaps: &[Gap],
) -> Result<Vec<u8>, StoreError> {
    let observed = nanos(sent_ms);
    let mut log_records: Vec<Value> = records.iter().map(|r| record(r, &observed)).collect();
    log_records.extend(gaps.iter().map(|g| gap(g, &observed)));
    let body = json!({
        "resourceLogs": [{
            "resource": { "attributes": [
                string("service.name", "openmoat"),
                string("service.version", origin.version),
                string("host.name", origin.machine),
            ]},
            "scopeLogs": [{
                "scope": { "name": SCOPE, "version": origin.version },
                "logRecords": log_records,
            }],
        }],
    });
    serde_json::to_vec(&body).map_err(StoreError::Encode)
}

fn record(r: &Delivered, observed: &str) -> Value {
    let (severity, text) = match r.verdict.as_str() {
        "deny" => (WARN, "WARN"),
        "review" => (INFO2, "INFO2"),
        _ => (INFO, "INFO"),
    };
    let mut attributes = vec![
        string("openmoat.event.id", &r.id.to_string()),
        string("openmoat.host", &r.host),
        string("session.id", &r.session_id),
        string("openmoat.tool", &r.tool),
        string("openmoat.verdict", &r.verdict),
        strings("openmoat.rules", &r.rules),
        strings("openmoat.reasons", &r.reasons),
        string("openmoat.action", &r.action.to_string()),
        int("openmoat.latency_us", r.latency_us),
        string("openmoat.hash", &r.hash),
        string("openmoat.prev_hash", &r.prev_hash),
    ];
    if let Some(call) = &r.call_id {
        attributes.push(string("openmoat.call_id", call));
    }
    if let Some(cwd) = &r.cwd {
        attributes.push(string("openmoat.cwd", cwd));
    }
    json!({
        "timeUnixNano": nanos(r.ts_ms),
        "observedTimeUnixNano": observed,
        "severityNumber": severity,
        "severityText": text,
        "body": { "stringValue": summary(r) },
        "attributes": attributes,
    })
}

fn gap(g: &Gap, observed: &str) -> Value {
    json!({
        "timeUnixNano": observed,
        "observedTimeUnixNano": observed,
        "severityNumber": ERROR,
        "severityText": "ERROR",
        "body": { "stringValue": g.describe() },
        "attributes": [
            string("openmoat.gap.first", &g.first.to_string()),
            string("openmoat.gap.last", &g.last.to_string()),
            int("openmoat.gap.count", i64::try_from(g.count).unwrap_or(i64::MAX)),
        ],
    })
}

/// Log records a collector took the request without: its answer was a
/// success, and its body an `ExportLogsServiceResponse` whose
/// `partial_success` counts them. The OTLP specification says a sender must
/// not send such a request again; the records are lost to that collector.
/// <https://opentelemetry.io/docs/specs/otlp/#partial-success-1>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejected {
    /// `rejected_log_records`, more than zero.
    pub count: u64,
    /// `error_message`, as the collector wrote it (empty when it gave none):
    /// text from the network, to be masked and cleaned before it is shown
    /// or recorded.
    pub message: String,
}

/// The [`Rejected`] records a success's `body` names, `None` when it names
/// none: no body, not JSON, no `partial_success`, or a count of zero (a
/// warning, which loses nothing). Both the lowerCamelCase field names the
/// JSON encoding writes and the proto names are read, and the count as a
/// decimal string or a number.
#[must_use]
pub fn rejected(body: &[u8]) -> Option<Rejected> {
    let response: Value = serde_json::from_slice(body).ok()?;
    let field = |value: &Value, camel: &str, snake: &str| -> Option<Value> {
        value.get(camel).or_else(|| value.get(snake)).cloned()
    };
    let partial = field(&response, "partialSuccess", "partial_success")?;
    let count = match field(&partial, "rejectedLogRecords", "rejected_log_records")? {
        Value::String(text) => text.trim().parse::<u64>().ok()?,
        number => number.as_u64()?,
    };
    if count == 0 {
        return None;
    }
    let message = field(&partial, "errorMessage", "error_message")
        .and_then(|m| m.as_str().map(str::to_owned))
        .unwrap_or_default();
    Some(Rejected { count, message })
}

/// `deny Bash [rule, rule]`: what a person scanning a log view needs first.
fn summary(r: &Delivered) -> String {
    format!("{} {} [{}]", r.verdict, r.tool, r.rules.join(", "))
}

/// Milliseconds as the decimal string of nanoseconds OTLP JSON uses; a time
/// before the epoch is written as 0.
fn nanos(ms: i64) -> String {
    u64::try_from(ms)
        .map_or(0, |ms| ms.saturating_mul(1_000_000))
        .to_string()
}

fn string(key: &str, value: &str) -> Value {
    json!({ "key": key, "value": { "stringValue": value } })
}

fn strings(key: &str, values: &[String]) -> Value {
    let values: Vec<Value> = values.iter().map(|v| json!({ "stringValue": v })).collect();
    json!({ "key": key, "value": { "arrayValue": { "values": values } } })
}

fn int(key: &str, value: i64) -> Value {
    json!({ "key": key, "value": { "intValue": value.to_string() } })
}
