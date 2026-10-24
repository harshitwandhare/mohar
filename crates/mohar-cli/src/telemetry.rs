//! Optional OpenTelemetry export for the daemon: a span per decision, counts of decisions by result and
//! of verifier outcomes, a histogram of decision latency, and how many requests are in flight.
//!
//! It speaks OTLP/HTTP with JSON bodies to a collector on this machine (`/v1/traces` and `/v1/metrics`)
//! using std networking only, as the daemon does for its own HTTP. It is off unless the daemon is
//! started with `--otlp-endpoint`, and only a loopback endpoint is accepted, so nothing about decisions
//! leaves the machine unless a local collector forwards it. Export runs on its own thread; a collector
//! that is down or slow loses telemetry and never delays or changes a decision.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Upper bounds, in milliseconds, of the decision latency histogram's buckets.
const BOUNDS_MS: [f64; 8] = [0.5, 1.0, 2.0, 5.0, 10.0, 25.0, 100.0, 1000.0];
/// How often collected telemetry is sent.
const FLUSH_EVERY: Duration = Duration::from_millis(500);
/// Spans held between flushes; past this the oldest are dropped rather than growing without bound.
const MAX_SPANS: usize = 4096;
/// How long a send to the collector may take.
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// What the daemon reports.
pub enum Event {
    /// A decision was answered.
    Decision {
        /// `allow`, `escalate` or `deny`.
        result: String,
        /// `gate` or `score`.
        by: String,
        /// The capability the daemon classified the action as.
        capability: String,
        /// The receipt that records it.
        receipt_seq: u64,
        /// When handling began, in nanoseconds since the Unix epoch.
        start_ns: u64,
        /// How long it took.
        took: Duration,
    },
    /// A verifier's outcome was recorded.
    Outcome {
        /// `tests`, `diff`, `replay`, `human` or `host`.
        verifier: String,
        /// `pass`, `fail` or `unknown`.
        result: String,
        /// How many decisions it was recorded for.
        count: u64,
    },
    /// Requests being handled right now.
    InFlight(usize),
}

/// A handle the daemon sends events to. Sending never blocks and never fails the caller.
#[derive(Clone)]
pub struct Telemetry {
    tx: mpsc::Sender<Event>,
}

impl Telemetry {
    /// Start exporting to `endpoint` (`http://127.0.0.1:4318` or similar). Refuses anything that isn't
    /// a loopback address.
    pub fn start(endpoint: &str) -> Result<Self, String> {
        let hostport = endpoint
            .strip_prefix("http://")
            .ok_or_else(|| format!("{endpoint}: the OTLP endpoint must be an http:// URL"))?
            .trim_end_matches('/');
        let addr: SocketAddr = hostport
            .to_socket_addrs()
            .map_err(|e| format!("{endpoint}: {e}"))?
            .next()
            .ok_or_else(|| format!("{endpoint}: no address"))?;
        if !addr.ip().is_loopback() {
            return Err(format!(
                "{endpoint}: the OTLP endpoint must be on this machine (a loopback address)"
            ));
        }
        let (tx, rx) = mpsc::channel();
        let host = hostport.to_string();
        std::thread::spawn(move || export(rx, addr, &host));
        Ok(Self { tx })
    }

    /// Report an event. If the exporter has stopped, the event is dropped.
    pub fn send(&self, e: Event) {
        let _ = self.tx.send(e);
    }
}

/// Nanoseconds since the Unix epoch.
pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Everything collected since the exporter started. Counts are cumulative, as OTLP expects for
/// monotonic sums with cumulative temporality.
#[derive(Default)]
struct Totals {
    decisions: BTreeMap<String, u64>,
    outcomes: BTreeMap<(String, String), u64>,
    latency: [u64; BOUNDS_MS.len() + 1],
    latency_sum_ms: f64,
    latency_count: u64,
    in_flight: usize,
}

impl Totals {
    fn add_latency(&mut self, ms: f64) {
        let bucket = BOUNDS_MS
            .iter()
            .position(|b| ms <= *b)
            .unwrap_or(BOUNDS_MS.len());
        self.latency[bucket] += 1;
        self.latency_sum_ms += ms;
        self.latency_count += 1;
    }
}

fn export(rx: mpsc::Receiver<Event>, addr: SocketAddr, host: &str) {
    let started = now_ns();
    let mut totals = Totals::default();
    let mut spans: Vec<Value> = Vec::new();
    let mut changed = false;
    loop {
        match rx.recv_timeout(FLUSH_EVERY) {
            Ok(e) => {
                record(&mut totals, &mut spans, e);
                changed = true;
                continue;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        }
        if !changed {
            continue;
        }
        if !spans.is_empty() {
            let _ = post(
                addr,
                host,
                "/v1/traces",
                &traces(std::mem::take(&mut spans)),
            );
        }
        let _ = post(
            addr,
            host,
            "/v1/metrics",
            &metrics(&totals, started, now_ns()),
        );
        changed = false;
    }
}

fn record(totals: &mut Totals, spans: &mut Vec<Value>, e: Event) {
    match e {
        Event::Decision {
            result,
            by,
            capability,
            receipt_seq,
            start_ns,
            took,
        } => {
            *totals.decisions.entry(result.clone()).or_default() += 1;
            totals.add_latency(took.as_secs_f64() * 1000.0);
            if spans.len() == MAX_SPANS {
                spans.remove(0);
            }
            let end_ns =
                start_ns.saturating_add(u64::try_from(took.as_nanos()).unwrap_or(u64::MAX));
            spans.push(span(
                &result,
                &by,
                &capability,
                receipt_seq,
                start_ns,
                end_ns,
            ));
        }
        Event::Outcome {
            verifier,
            result,
            count,
        } => *totals.outcomes.entry((verifier, result)).or_default() += count,
        Event::InFlight(n) => totals.in_flight = n,
    }
}

fn attr(key: &str, value: Value) -> Value {
    let v = match value {
        Value::String(s) => json!({ "stringValue": s }),
        Value::Number(n) => json!({ "intValue": n.to_string() }),
        other => json!({ "stringValue": other.to_string() }),
    };
    json!({ "key": key, "value": v })
}

/// Trace and span ids derived from the receipt and the time, so no random source is needed; they only
/// have to be unique, and the receipt number already is within a log.
fn ids(receipt_seq: u64, start_ns: u64) -> (String, String) {
    let digest = Sha256::digest(format!("{receipt_seq}:{start_ns}").as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    (hex[..32].to_string(), hex[32..48].to_string())
}

fn span(result: &str, by: &str, capability: &str, seq: u64, start_ns: u64, end_ns: u64) -> Value {
    let (trace_id, span_id) = ids(seq, start_ns);
    json!({
        "traceId": trace_id,
        "spanId": span_id,
        "name": "mohar.decide",
        "kind": 2,
        "startTimeUnixNano": start_ns.to_string(),
        "endTimeUnixNano": end_ns.to_string(),
        "attributes": [
            attr("mohar.result", json!(result)),
            attr("mohar.by", json!(by)),
            attr("mohar.capability", json!(capability)),
            attr("mohar.receipt_seq", json!(seq)),
        ],
    })
}

fn resource() -> Value {
    json!({ "attributes": [attr("service.name", json!("mohar"))] })
}

fn traces(spans: Vec<Value>) -> Value {
    json!({ "resourceSpans": [{
        "resource": resource(),
        "scopeSpans": [{ "scope": { "name": "mohar" }, "spans": spans }],
    }]})
}

fn metrics(t: &Totals, start: u64, now: u64) -> Value {
    let (start, now) = (start.to_string(), now.to_string());
    let sum = |points: Vec<Value>| json!({ "aggregationTemporality": 2, "isMonotonic": true, "dataPoints": points });
    let decisions: Vec<Value> = t
        .decisions
        .iter()
        .map(|(result, n)| {
            json!({ "attributes": [attr("mohar.result", json!(result))],
                    "startTimeUnixNano": start, "timeUnixNano": now, "asInt": n.to_string() })
        })
        .collect();
    let outcomes: Vec<Value> = t
        .outcomes
        .iter()
        .map(|((verifier, result), n)| {
            json!({ "attributes": [attr("mohar.verifier", json!(verifier)), attr("mohar.result", json!(result))],
                    "startTimeUnixNano": start, "timeUnixNano": now, "asInt": n.to_string() })
        })
        .collect();
    json!({ "resourceMetrics": [{
        "resource": resource(),
        "scopeMetrics": [{ "scope": { "name": "mohar" }, "metrics": [
            { "name": "mohar.decisions", "unit": "1", "sum": sum(decisions) },
            { "name": "mohar.outcomes", "unit": "1", "sum": sum(outcomes) },
            { "name": "mohar.decide.duration", "unit": "ms", "histogram": {
                "aggregationTemporality": 2,
                "dataPoints": [{
                    "startTimeUnixNano": start, "timeUnixNano": now,
                    "count": t.latency_count.to_string(), "sum": t.latency_sum_ms,
                    "bucketCounts": t.latency.iter().map(u64::to_string).collect::<Vec<_>>(),
                    "explicitBounds": BOUNDS_MS,
                }],
            }},
            { "name": "mohar.inflight", "unit": "1", "gauge": {
                "dataPoints": [{ "timeUnixNano": now, "asInt": t.in_flight.to_string() }],
            }},
        ]}],
    }]})
}

/// One OTLP/HTTP JSON request. Errors are returned for tests and otherwise ignored.
fn post(addr: SocketAddr, host: &str, path: &str, body: &Value) -> Result<(), String> {
    let mut s = TcpStream::connect_timeout(&addr, SEND_TIMEOUT).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(SEND_TIMEOUT))
        .map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(SEND_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let text = body.to_string();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    )
    .map_err(|e| e.to_string())?;
    let mut answer = Vec::new();
    let _ = s.take(64 * 1024).read_to_end(&mut answer);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn only_a_loopback_http_endpoint_is_accepted() {
        assert!(Telemetry::start("http://127.0.0.1:4318").is_ok());
        assert!(Telemetry::start("127.0.0.1:4318").is_err(), "needs http://");
        assert!(Telemetry::start("http://203.0.113.7:4318").is_err());
        assert!(Telemetry::start("http://no-such-host.invalid:4318").is_err());
    }

    #[test]
    fn latency_lands_in_the_right_bucket_and_slow_ones_in_the_last() {
        let mut t = Totals::default();
        for ms in [0.1, 0.5, 0.7, 3.0, 5000.0] {
            t.add_latency(ms);
        }
        assert_eq!(t.latency, [2, 1, 0, 1, 0, 0, 0, 0, 1]);
        assert_eq!(t.latency_count, 5);
    }

    #[test]
    fn spans_past_the_limit_drop_the_oldest() {
        let (mut t, mut spans) = (Totals::default(), Vec::new());
        for seq in 0..(MAX_SPANS as u64 + 3) {
            record(
                &mut t,
                &mut spans,
                Event::Decision {
                    result: "allow".into(),
                    by: "score".into(),
                    capability: "fs.edit.docs".into(),
                    receipt_seq: seq,
                    start_ns: 1,
                    took: Duration::from_micros(10),
                },
            );
        }
        assert_eq!(spans.len(), MAX_SPANS);
        assert_eq!(spans[0]["attributes"][3]["value"]["intValue"], "3");
        assert_eq!(t.decisions["allow"], MAX_SPANS as u64 + 3);
    }

    #[test]
    fn metrics_carry_counts_by_result_and_by_verifier() {
        let (mut t, mut spans) = (Totals::default(), Vec::new());
        record(
            &mut t,
            &mut spans,
            Event::Outcome {
                verifier: "tests".into(),
                result: "pass".into(),
                count: 2,
            },
        );
        record(&mut t, &mut spans, Event::InFlight(3));
        let m = metrics(&t, 1, 2);
        let list = &m["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];
        assert_eq!(list[1]["name"], "mohar.outcomes");
        assert_eq!(list[1]["sum"]["dataPoints"][0]["asInt"], "2");
        assert_eq!(list[3]["gauge"]["dataPoints"][0]["asInt"], "3");
        assert_eq!(attr("k", json!(true))["value"]["stringValue"], "true");
    }

    #[test]
    fn a_collector_that_is_down_is_an_error_not_a_hang() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = l.local_addr().expect("addr");
        drop(l);
        assert!(post(addr, "x", "/v1/traces", &json!({})).is_err());
    }
}
