//! `mohar daemon`: the local service that adapters ask for decisions and report outcomes to.
//!
//! It listens on a loopback address only, speaks just enough HTTP/1.1 for two JSON endpoints, and
//! signs every decision and outcome into the log through `FileLog`, which holds the writer lock for
//! as long as the daemon runs. Answers come from the trust ledger, which is rebuilt from the log on
//! start: trust exists only as signed receipts.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mohar_core::policy::{Policy, Risk};
use mohar_core::store::{FileLog, for_each_receipt};
use mohar_core::trust::{Ledger, Outcome, Severity};
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
    /// Exit when stdin closes, so a parent process can stop the daemon by closing the pipe.
    pub exit_on_stdin_eof: bool,
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
    policy: Policy,
    /// The log directory, absolute. The daemon writes there during every task, so it is never part of
    /// what a task changed.
    log_dir: PathBuf,
    inflight: AtomicUsize,
    max_inflight: usize,
}

struct Inner {
    log: FileLog,
    pending: HashMap<u64, Pending>,
    /// Host call ids (Claude Code's tool_use_id) to the decision they belong to, for this run only.
    calls: HashMap<String, u64>,
    /// Decisions made in each task, by (agent, task id), waiting for the task to be verified. Like
    /// call ids, this lives for the daemon's run only.
    tasks: HashMap<(String, String), Vec<u64>>,
    /// Decisions the host reported as having run (allowed, or approved by a person).
    ran: HashSet<u64>,
    /// Files git already showed as changed when each task began, so earlier work isn't blamed on it.
    /// `None` when the root isn't a git repository.
    baselines: HashMap<(String, String), Option<HashSet<String>>>,
    /// Trust per agent and capability, rebuilt from the log on start.
    ledger: Ledger,
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
    let policy = load_policy(dir)?;
    let log = FileLog::open(dir).map_err(|e| e.to_string())?;
    let (pending, ledger) = replay(&dir.join("receipts.jsonl"), &policy)?;
    let listener = TcpListener::bind(cfg.addr).map_err(|e| format!("{}: {e}", cfg.addr))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    // Nobody may be reading stdout (a closed pipe on Windows); the daemon must not die over that.
    let mut out = std::io::stdout();
    let _ = writeln!(out, "listening on {local}");
    if !pending.is_empty() {
        let _ = writeln!(
            out,
            "{} decisions are waiting for an outcome",
            pending.len()
        );
    }
    let _ = out.flush();
    if cfg.exit_on_stdin_eof {
        // The process that started the daemon closes stdin to stop it. Exiting this way, not by being
        // killed, lets every receipt already appended stay synced and ends the process cleanly.
        std::thread::spawn(|| {
            let _ = std::io::copy(&mut std::io::stdin(), &mut std::io::sink());
            std::process::exit(0);
        });
    }

    // Resolved the way the policy resolves its root (following symlinks, and in the long-path form on
    // Windows), so the two can be compared.
    let log_dir = std::fs::canonicalize(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let state = Arc::new(State {
        log_dir,
        log: Mutex::new(Inner {
            log,
            pending,
            ledger,
            tasks: HashMap::new(),
            ran: HashSet::new(),
            baselines: HashMap::new(),
            calls: HashMap::new(),
        }),
        inflight: AtomicUsize::new(0),
        max_inflight: cfg.max_inflight,
        policy,
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

/// The project's policy from `<dir>/policy.json`, rooted at the directory that holds the log
/// directory; without one, the built-in policy rooted at the working directory. An invalid policy
/// stops the daemon from starting rather than being ignored.
fn load_policy(dir: &Path) -> Result<Policy, String> {
    let file = dir.join("policy.json");
    match std::fs::read_to_string(&file) {
        Ok(text) => {
            let base = std::path::absolute(dir)
                .map_err(|e| e.to_string())?
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_default();
            Policy::from_json(&text, &base).map_err(|e| format!("{}: {e}", file.display()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let cwd = std::env::current_dir().map_err(|e| e.to_string())?;
            Ok(Policy::builtin(&cwd))
        }
        Err(e) => Err(format!("{}: {e}", file.display())),
    }
}

/// Read the log once: decisions still waiting for an outcome, and the trust ledger rebuilt from every
/// verified outcome. Trust lives nowhere but the signed log.
fn replay(receipts: &Path, policy: &Policy) -> Result<(HashMap<u64, Pending>, Ledger), String> {
    let mut pending = HashMap::new();
    let mut ledger = Ledger::new();
    for_each_receipt(receipts, |r: Receipt| match r.verification {
        Some(v) => {
            if v.kind != "host" {
                pending.remove(&v.of);
            }
            if let Some(o) = verified(
                &v.kind,
                &v.result,
                &r.action.capability,
                policy,
                parse_rfc3339(&r.ts),
            ) {
                ledger.record(&r.agent.id, &r.action.capability, &o);
            }
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
    Ok((pending, ledger))
}

/// The trust outcome an outcome receipt stands for, if it counts. The host's own report that a tool
/// ran never counts, and neither does an `unknown` result. Until remediation plans name what a pass
/// must exercise (#87), every verified pass counts as exercising the failure.
fn verified(
    kind: &str,
    result: &str,
    capability: &str,
    policy: &Policy,
    at: u64,
) -> Option<Outcome> {
    if kind == "host" {
        return None;
    }
    let passed = match result {
        "pass" => true,
        "fail" => false,
        _ => return None,
    };
    Some(Outcome {
        at,
        passed,
        severity: Severity::for_capability(&policy.spec(capability)),
        exercises_failure: true,
        related: Vec::new(),
    })
}

/// Seconds since the Unix epoch for an RFC 3339 UTC timestamp as the log writes it; 0 if malformed.
fn parse_rfc3339(ts: &str) -> u64 {
    let num = |a: usize, b: usize| ts.get(a..b).and_then(|s| s.parse::<i64>().ok());
    let (Some(y), Some(m), Some(d), Some(hh), Some(mm), Some(ss)) = (
        num(0, 4),
        num(5, 7),
        num(8, 10),
        num(11, 13),
        num(14, 16),
        num(17, 19),
    ) else {
        return 0;
    };
    // Days from civil date, Howard Hinnant's algorithm.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3_600 + mm * 60 + ss).unwrap_or(0)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
        "/v1/verify" => verify_task(state, &body),
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
    tool: String,
    target: String,
    args_sha256: String,
    /// The host's id for this call, so its outcome can be matched without the receipt number.
    #[serde(default)]
    call_id: Option<String>,
    /// The task this action belongs to (Claude Code's session id), so the task can be verified as a
    /// whole when it ends.
    #[serde(default)]
    task: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerifyRequest {
    agent: String,
    task: String,
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

fn decide(state: &State, body: &[u8]) -> (u16, serde_json::Value) {
    let req: DecideRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return bad("body is not a valid decide request"),
    };
    if !(field_ok(&req.agent, MAX_FIELD) && field_ok(&req.tool, MAX_FIELD)) {
        return bad("agent and tool must be non-empty and at most 512 bytes");
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
    if req.task.as_deref().is_some_and(|t| !field_ok(t, MAX_FIELD)) {
        return bad("task must be non-empty and at most 512 bytes");
    }
    // The daemon classifies the action from its own policy; the agent's side never names its capability.
    let classified = state.policy.classify(&req.tool, &req.target);
    let action = Action {
        capability: classified.capability,
        tool: req.tool,
        target: req.target,
        args_sha256: req.args_sha256,
    };
    let mut inner = match state.log.lock() {
        Ok(g) => g,
        Err(_) => return (500, json!({"error": "log lock poisoned"})),
    };
    let now = now_secs();
    // Hard gates come first; no record outweighs them.
    let stop = state
        .policy
        .gate(&action.tool, &action.target, &action.capability);
    let suspended = inner.ledger.is_suspended(&req.agent);
    let verdict = inner
        .ledger
        .decide(&req.agent, &action.capability, &classified.spec, now);
    let decision = match &stop {
        Some(_) => Decision {
            result: "deny".to_string(),
            level: verdict.level,
            by: "gate".to_string(),
        },
        // A fixed rule (a suspension, an action with no effect) is a gate; anything else came from
        // the record.
        None => Decision {
            result: verdict.result.to_string(),
            level: verdict.level,
            by: if suspended || classified.spec.risk == Risk::None {
                "gate"
            } else {
                "score"
            }
            .to_string(),
        },
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
            agent_id: req.agent.clone(),
            action,
            decision: decision.clone(),
        },
    );
    if let Some(call) = req.call_id {
        inner.calls.insert(call, receipt.seq);
    }
    if let Some(task) = req.task {
        let key = (req.agent.clone(), task);
        if !inner.baselines.contains_key(&key) {
            let before = changed_files(state.policy.root());
            inner.baselines.insert(key.clone(), before);
        }
        inner.tasks.entry(key).or_default().push(receipt.seq);
    }
    if decision.result == "allow" {
        inner.ran.insert(receipt.seq);
    }
    (
        200,
        json!({
            "result": decision.result,
            "level": decision.level,
            "receipt_seq": receipt.seq,
            "gate": stop.as_ref().map(|g| g.gate),
            "reason": stop.map(|g| g.reason),
        }),
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
    if !inner.pending.contains_key(&seq) {
        return (
            404,
            json!({"error": "no pending decision with that receipt_seq"}),
        );
    }
    match append_outcome(
        &mut inner,
        &state.policy,
        seq,
        &req.verifier,
        &req.result,
        req.evidence_sha256,
    ) {
        Ok(r) => (200, json!({ "receipt_seq": r })),
        Err(e) => (500, json!({ "error": e })),
    }
}

/// Sign an outcome for a pending decision, and let it change trust once it is on disk. A `host` report
/// only marks the decision as having run: it is recorded, but the decision stays open for a verifier.
fn append_outcome(
    inner: &mut Inner,
    policy: &Policy,
    seq: u64,
    kind: &str,
    result: &str,
    evidence_sha256: String,
) -> Result<u64, String> {
    let p = inner
        .pending
        .get(&seq)
        .cloned()
        .ok_or("no pending decision")?;
    let counted = verified(kind, result, &p.action.capability, policy, now_secs());
    let (agent, capability) = (p.agent_id.clone(), p.action.capability.clone());
    let entry = Entry {
        ts: crate::now_rfc3339(),
        agent_id: p.agent_id,
        action: p.action,
        decision: p.decision,
        verification: Some(Verification {
            evidence_sha256,
            kind: kind.to_string(),
            of: seq,
            result: result.to_string(),
        }),
    };
    let r = inner.log.append(entry).map_err(|e| e.to_string())?;
    if kind == "host" {
        inner.ran.insert(seq);
    } else {
        inner.pending.remove(&seq);
        inner.ran.remove(&seq);
    }
    if let Some(o) = counted {
        inner.ledger.record(&agent, &capability, &o);
    }
    Ok(r.seq)
}

/// Verify a finished task: run the project's tests once and record the result for every decision in
/// the task that ran and changed something. An agent that changed a test file in the task fails,
/// whatever the tests say, since it could have changed the tests to pass.
fn verify_task(state: &State, body: &[u8]) -> (u16, serde_json::Value) {
    let req: VerifyRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return bad("body is not a valid verify request"),
    };
    if !(field_ok(&req.agent, MAX_FIELD) && field_ok(&req.task, MAX_FIELD)) {
        return bad("agent and task must be non-empty and at most 512 bytes");
    }
    // Take the task's decisions, then let go of the lock while the tests run.
    let (targets, seqs, granted, baseline) = {
        let Ok(mut inner) = state.log.lock() else {
            return (500, json!({"error": "log lock poisoned"}));
        };
        let key = (req.agent.clone(), req.task.clone());
        let all = inner.tasks.remove(&key).unwrap_or_default();
        let baseline = inner.baselines.remove(&key).flatten();
        let seqs: Vec<u64> = all
            .into_iter()
            .filter(|seq| inner.ran.contains(seq))
            .filter(|seq| {
                inner
                    .pending
                    .get(seq)
                    .is_some_and(|p| state.policy.spec(&p.action.capability).risk != Risk::None)
            })
            .collect();
        let targets: Vec<(String, String)> = seqs
            .iter()
            .filter_map(|seq| inner.pending.get(seq))
            .map(|p| (p.action.tool.clone(), p.action.target.clone()))
            .collect();
        // The capabilities the agent was given in this task: those of the actions that ran.
        let granted: HashSet<String> = seqs
            .iter()
            .filter_map(|seq| inner.pending.get(seq))
            .map(|p| p.action.capability.clone())
            .collect();
        (targets, seqs, granted, baseline)
    };
    if seqs.is_empty() {
        return (200, json!({ "verified": 0, "result": null }));
    }
    let changed_tests: Vec<&str> = targets
        .iter()
        .filter(|(tool, target)| {
            WRITE_TOOLS.contains(&tool.as_str()) && state.policy.is_test_path(target)
        })
        .map(|(_, target)| target.as_str())
        .collect();
    // One outcome per decision, from the first verifier that fails: scope, then the tests' own files,
    // then the tests. Recording each verifier separately would count one action's success twice.
    let out_of_scope =
        diff_out_of_scope(&state.policy, &state.log_dir, baseline.as_ref(), &granted);
    let (kind, result, evidence) = if !out_of_scope.is_empty() {
        (
            "diff",
            "fail",
            sha256_hex(
                format!(
                    "changed outside the task's capabilities: {}",
                    out_of_scope.join(", ")
                )
                .as_bytes(),
            ),
        )
    } else if !changed_tests.is_empty() {
        (
            "tests",
            "fail",
            sha256_hex(
                format!("the agent changed test files: {}", changed_tests.join(", ")).as_bytes(),
            ),
        )
    } else {
        let (result, evidence) = run_tests(&state.policy);
        ("tests", result, evidence)
    };
    let Ok(mut inner) = state.log.lock() else {
        return (500, json!({"error": "log lock poisoned"}));
    };
    let mut recorded = 0;
    for seq in seqs {
        if inner.pending.contains_key(&seq) {
            if let Err(e) = append_outcome(
                &mut inner,
                &state.policy,
                seq,
                kind,
                result,
                evidence.clone(),
            ) {
                return (500, json!({ "error": e }));
            }
            recorded += 1;
        }
    }
    (
        200,
        json!({ "verified": recorded, "result": result, "verifier": kind, "out_of_scope": out_of_scope }),
    )
}

/// Files git shows as changed under `root`, relative to it, renames counted under both names. `None`
/// when git can't say (not a repository, git missing).
fn changed_files(root: &Path) -> Option<HashSet<String>> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let mut files = HashSet::new();
    let mut entries = out.stdout.split(|b| *b == 0).filter(|e| !e.is_empty());
    while let Some(entry) = entries.next() {
        let text = String::from_utf8_lossy(entry);
        let (status, path) = (text.get(..2).unwrap_or(""), text.get(3..).unwrap_or(""));
        files.insert(path.to_string());
        // A rename or copy is followed by its original name.
        if (status.starts_with('R') || status.starts_with('C'))
            && let Some(from) = entries.next()
        {
            files.insert(String::from_utf8_lossy(from).into_owned());
        }
    }
    Some(files)
}

/// The files changed since the task began whose capability the agent wasn't given in it, sorted.
/// Empty when git can't say, so the tests still decide.
fn diff_out_of_scope(
    policy: &Policy,
    log_dir: &Path,
    baseline: Option<&HashSet<String>>,
    granted: &HashSet<String>,
) -> Vec<String> {
    let (Some(before), Some(now)) = (baseline, changed_files(policy.root())) else {
        return Vec::new();
    };
    let mut out: Vec<String> = now
        .difference(before)
        .filter(|rel| !policy.root().join(rel).starts_with(log_dir))
        .filter(|rel| {
            let cap = policy
                .classify("Edit", &policy.root().join(rel).to_string_lossy())
                .capability;
            !granted.contains(&cap)
        })
        .cloned()
        .collect();
    out.sort();
    out
}

/// Host tools that change files.
const WRITE_TOOLS: [&str; 4] = ["Edit", "MultiEdit", "Write", "NotebookEdit"];

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Run the project's test command from the root. `pass` on exit 0, `fail` on any other exit, and
/// `unknown` when there is no command, it can't start, or it runs past its timeout. The evidence is
/// the SHA-256 of the exit status and everything it printed.
fn run_tests(policy: &Policy) -> (&'static str, String) {
    use std::process::{Command, Stdio};
    let Some(t) = policy.tests_verifier() else {
        return ("unknown", sha256_hex(b"no test command configured"));
    };
    let Some((program, args)) = t.command.split_first() else {
        return ("unknown", sha256_hex(b"empty test command"));
    };
    let child = Command::new(program)
        .args(args)
        .current_dir(policy.root())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return (
                "unknown",
                sha256_hex(format!("could not start {program}: {e}").as_bytes()),
            );
        }
    };
    // Read output on threads so a chatty test run can't fill a pipe and stall.
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let read_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(o) = out.as_mut() {
            let _ = o.read_to_end(&mut b);
        }
        b
    });
    let read_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        if let Some(e) = err.as_mut() {
            let _ = e.read_to_end(&mut b);
        }
        b
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(t.timeout_secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let mut evidence = Vec::new();
    evidence.extend_from_slice(
        format!(
            "{status:?}
"
        )
        .as_bytes(),
    );
    evidence.extend(read_out.join().unwrap_or_default());
    evidence.extend(read_err.join().unwrap_or_default());
    let result = match status {
        Some(s) if s.success() => "pass",
        Some(_) => "fail",
        None => "unknown",
    };
    (result, sha256_hex(&evidence))
}

#[cfg(test)]
mod tests {
    use super::parse_rfc3339;

    #[test]
    fn timestamps_round_trip_through_the_log_format() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00.000Z"), 0);
        assert_eq!(parse_rfc3339("2026-10-22T13:45:07.311Z"), 1_792_676_707);
        assert_eq!(
            parse_rfc3339("2000-02-29T00:00:00.000Z"),
            951_782_400,
            "a leap day"
        );
        let now = crate::now_rfc3339();
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert!(parse_rfc3339(&now).abs_diff(secs) <= 1);
        assert_eq!(parse_rfc3339("garbage"), 0);
    }
}
