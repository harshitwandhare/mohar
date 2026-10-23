//! `mohar daemon`: the local service that adapters ask for decisions and report outcomes to.
//!
//! It listens on a loopback address only, speaks just enough HTTP/1.1 for two JSON endpoints, and
//! signs every decision and outcome into the log through `FileLog`, which holds the writer lock for
//! as long as the daemon runs. Until the trust engine lands, the policy is fixed: reads run, everything
//! else goes to a person. Every answer is still a signed receipt.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mohar_core::store::{FileLog, for_each_receipt};
use mohar_core::{Action, Decision, Entry, Receipt, Verification};
use serde::Deserialize;
use serde_json::json;

/// Largest request head (request line and headers) the daemon reads.
const MAX_HEAD: usize = 8 * 1024;
/// Largest request body: a decision or an outcome is a few hundred bytes.
const MAX_BODY: usize = 64 * 1024;
/// Longest value accepted in an identifier field.
const MAX_FIELD: usize = 512;
/// Longest target (a path, a branch, a command line).
const MAX_TARGET: usize = 4096;

pub struct Config {
    pub addr: SocketAddr,
    /// Requests being handled at once; past this the daemon answers 503 instead of queueing.
    pub max_inflight: usize,
    /// How long a client may take to send its request or read the answer.
    pub io_timeout: Duration,
}

/// A decision that has no outcome yet: enough to write the follow-up receipt.
#[derive(Clone)]
struct Pending {
    agent_id: String,
    action: Action,
    decision: Decision,
}

struct State {
    log: Mutex<Inner>,
    inflight: AtomicUsize,
    max_inflight: usize,
}

struct Inner {
    log: FileLog,
    pending: HashMap<u64, Pending>,
    /// Host call ids (Claude Code's tool_use_id) to the decision they belong to, for this run only.
    calls: HashMap<String, u64>,
}

/// Serve until the process is stopped. Prints `listening on ADDR` once bound, so callers that ask
/// for port 0 learn the real port.
pub fn serve(dir: &Path, cfg: Config) -> Result<(), String> {
    if !cfg.addr.ip().is_loopback() {
        return Err(format!(
            "{} is not a loopback address; the daemon only listens on this machine",
            cfg.addr
        ));
    }
    let log = FileLog::open(dir).map_err(|e| e.to_string())?;
    let pending = pending_decisions(&dir.join("receipts.jsonl"))?;
    let listener = TcpListener::bind(cfg.addr).map_err(|e| format!("{}: {e}", cfg.addr))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    println!("listening on {local}");
    if !pending.is_empty() {
        println!("{} decisions are waiting for an outcome", pending.len());
    }
    let _ = std::io::stdout().flush();

    let state = Arc::new(State {
        log: Mutex::new(Inner {
            log,
            pending,
            calls: HashMap::new(),
        }),
        inflight: AtomicUsize::new(0),
        max_inflight: cfg.max_inflight,
    });
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let _ = stream.set_read_timeout(Some(cfg.io_timeout));
        let _ = stream.set_write_timeout(Some(cfg.io_timeout));
        if state.inflight.fetch_add(1, Ordering::SeqCst) >= state.max_inflight {
            state.inflight.fetch_sub(1, Ordering::SeqCst);
            respond(
                &mut stream,
                503,
                &json!({"error": "too many requests in flight"}),
            );
            drain(&mut stream);
            continue;
        }
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            handle(&mut stream, &state);
            state.inflight.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

/// Decisions in the log that no later receipt has recorded an outcome for.
fn pending_decisions(receipts: &Path) -> Result<HashMap<u64, Pending>, String> {
    let mut pending = HashMap::new();
    for_each_receipt(receipts, |r: Receipt| match r.verification {
        Some(v) => {
            pending.remove(&v.of);
        }
        None => {
            pending.insert(
                r.seq,
                Pending {
                    agent_id: r.agent.id,
                    action: r.action,
                    decision: r.decision,
                },
            );
        }
    })
    .map_err(|e| e.to_string())?;
    Ok(pending)
}

fn handle(stream: &mut TcpStream, state: &State) {
    let (path, body) = match read_request(stream) {
        Ok(req) => req,
        Err((status, msg)) => {
            respond(stream, status, &json!({ "error": msg }));
            return drain(stream);
        }
    };
    let (status, answer) = match path.as_str() {
        "/v1/decide" => decide(state, &body),
        "/v1/outcome" => outcome(state, &body),
        _ => (404, json!({"error": "no such endpoint"})),
    };
    respond(stream, status, &answer);
}

type Failure = (u16, &'static str);

/// Read one POST request. Only what the two endpoints need is accepted: a JSON body with a
/// Content-Length, under fixed size limits.
fn read_request(stream: &mut TcpStream) -> Result<(String, Vec<u8>), Failure> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Err((431, "request head too large"));
        }
        let n = stream
            .read(&mut chunk)
            .map_err(|_| (408, "timed out reading the request"))?;
        if n == 0 {
            return Err((400, "connection closed before the request was complete"));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head =
        std::str::from_utf8(&buf[..head_end]).map_err(|_| (400, "request head is not UTF-8"))?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, path, version) = (first.next(), first.next(), first.next());
    if version != Some("HTTP/1.1") && version != Some("HTTP/1.0") {
        return Err((400, "not an HTTP request"));
    }
    if method != Some("POST") {
        return Err((405, "only POST is accepted"));
    }
    let path = path.unwrap_or("").to_string();
    let mut length = None;
    let mut json_body = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return Err((400, "malformed header"));
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| (400, "bad Content-Length"))?,
                )
            }
            "content-type" => {
                json_body = value.to_ascii_lowercase().starts_with("application/json")
            }
            "transfer-encoding" => return Err((501, "chunked bodies are not accepted")),
            _ => {}
        }
    }
    let length = length.ok_or((411, "Content-Length is required"))?;
    if length > MAX_BODY {
        return Err((413, "body too large"));
    }
    if !json_body {
        return Err((415, "Content-Type must be application/json"));
    }
    let mut body = buf[head_end + 4..].to_vec();
    if body.len() > length {
        return Err((400, "more bytes than Content-Length"));
    }
    while body.len() < length {
        let n = stream
            .read(&mut chunk)
            .map_err(|_| (408, "timed out reading the body"))?;
        if n == 0 {
            return Err((400, "connection closed before the body was complete"));
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() > length {
            return Err((400, "more bytes than Content-Length"));
        }
    }
    Ok((path, body))
}

/// Read and drop what the client is still sending, briefly, so closing the socket doesn't reset the
/// connection before the client has read the answer.
fn drain(stream: &mut TcpStream) {
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut sink = [0u8; 4096];
    let mut total = 0;
    while total < MAX_HEAD + MAX_BODY {
        match stream.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => total += n,
        }
    }
}

fn respond(stream: &mut TcpStream, status: u16, body: &serde_json::Value) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let text = body.to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.flush();
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecideRequest {
    agent: String,
    capability: String,
    tool: String,
    target: String,
    args_sha256: String,
    /// The host's id for this call, so its outcome can be matched without the receipt number.
    #[serde(default)]
    call_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeRequest {
    #[serde(default)]
    receipt_seq: Option<u64>,
    #[serde(default)]
    call_id: Option<String>,
    verifier: String,
    result: String,
    evidence_sha256: String,
}

fn bad(msg: &str) -> (u16, serde_json::Value) {
    (400, json!({ "error": msg }))
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn field_ok(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max
}

/// The fixed policy until the trust engine exists: reads run, everything else asks a person.
fn policy(capability: &str) -> &'static str {
    if capability == "fs.read" || capability.starts_with("fs.read.") {
        "allow"
    } else {
        "escalate"
    }
}

fn decide(state: &State, body: &[u8]) -> (u16, serde_json::Value) {
    let req: DecideRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return bad("body is not a valid decide request"),
    };
    if !(field_ok(&req.agent, MAX_FIELD)
        && field_ok(&req.capability, MAX_FIELD)
        && field_ok(&req.tool, MAX_FIELD))
    {
        return bad("agent, capability and tool must be non-empty and at most 512 bytes");
    }
    if req.target.len() > MAX_TARGET {
        return bad("target is longer than 4096 bytes");
    }
    if !is_sha256_hex(&req.args_sha256) {
        return bad("args_sha256 must be 64 lowercase hex characters");
    }
    if req
        .call_id
        .as_deref()
        .is_some_and(|c| !field_ok(c, MAX_FIELD))
    {
        return bad("call_id must be non-empty and at most 512 bytes");
    }
    let action = Action {
        capability: req.capability,
        tool: req.tool,
        target: req.target,
        args_sha256: req.args_sha256,
    };
    let decision = Decision {
        result: policy(&action.capability).to_string(),
        level: 0,
        by: "gate".to_string(),
    };
    let mut inner = match state.log.lock() {
        Ok(g) => g,
        Err(_) => return (500, json!({"error": "log lock poisoned"})),
    };
    let entry = Entry {
        ts: crate::now_rfc3339(),
        agent_id: req.agent.clone(),
        action: action.clone(),
        decision: decision.clone(),
        verification: None,
    };
    let receipt = match inner.log.append(entry) {
        Ok(r) => r,
        Err(e) => return (500, json!({ "error": e.to_string() })),
    };
    inner.pending.insert(
        receipt.seq,
        Pending {
            agent_id: req.agent,
            action,
            decision: decision.clone(),
        },
    );
    if let Some(call) = req.call_id {
        inner.calls.insert(call, receipt.seq);
    }
    (
        200,
        json!({ "result": decision.result, "level": decision.level, "receipt_seq": receipt.seq }),
    )
}

fn outcome(state: &State, body: &[u8]) -> (u16, serde_json::Value) {
    let req: OutcomeRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return bad("body is not a valid outcome request"),
    };
    // `host` is the host's own report that a tool ran. It is recorded, never counted as verification.
    if !matches!(
        req.verifier.as_str(),
        "tests" | "diff" | "replay" | "human" | "host"
    ) {
        return bad("verifier must be tests, diff, replay, human or host");
    }
    if !matches!(req.result.as_str(), "pass" | "fail" | "unknown") {
        return bad("result must be pass, fail or unknown");
    }
    if !is_sha256_hex(&req.evidence_sha256) {
        return bad("evidence_sha256 must be 64 lowercase hex characters");
    }
    let mut inner = match state.log.lock() {
        Ok(g) => g,
        Err(_) => return (500, json!({"error": "log lock poisoned"})),
    };
    let seq = match (req.receipt_seq, req.call_id) {
        (Some(seq), None) => seq,
        (None, Some(call)) => match inner.calls.remove(&call) {
            Some(seq) => seq,
            None => {
                return (
                    404,
                    json!({"error": "no pending decision for that call_id"}),
                );
            }
        },
        _ => return bad("give exactly one of receipt_seq or call_id"),
    };
    let Some(p) = inner.pending.get(&seq).cloned() else {
        return (
            404,
            json!({"error": "no pending decision with that receipt_seq"}),
        );
    };
    let entry = Entry {
        ts: crate::now_rfc3339(),
        agent_id: p.agent_id,
        action: p.action,
        decision: p.decision,
        verification: Some(Verification {
            evidence_sha256: req.evidence_sha256,
            kind: req.verifier,
            of: seq,
            result: req.result,
        }),
    };
    match inner.log.append(entry) {
        Ok(r) => {
            inner.pending.remove(&seq);
            (200, json!({ "receipt_seq": r.seq }))
        }
        Err(e) => (500, json!({ "error": e.to_string() })),
    }
}
