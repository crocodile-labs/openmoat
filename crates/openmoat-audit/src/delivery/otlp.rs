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
