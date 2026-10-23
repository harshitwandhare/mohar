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
}

impl Daemon {
    fn start(dir: &Path, extra: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .arg("--dir")
            .arg(dir)
            .args(["daemon", "--addr", "127.0.0.1:0"])
            .args(extra)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn daemon");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("read listening line");
        let port = line
            .trim()
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .unwrap_or_else(|| panic!("no port in {line:?}"));
        Self { child, port }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Kill without any chance to clean up, like a crash.
    fn crash(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
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

fn decide(port: u16, capability: &str, call: Option<&str>) -> (u16, Value) {
    let mut b = json!({"agent": "agent:test/1", "capability": capability, "tool": "Edit",
                       "target": "docs/a.md", "args_sha256": SHA});
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
    let (s, a) = decide(d.port, "fs.read", None);
    assert_eq!(
        (s, a["result"].as_str(), a["receipt_seq"].as_u64()),
        (200, Some("allow"), Some(0))
    );
    let (s, b) = decide(d.port, "fs.edit", None);
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
    d.crash();
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
    let extra = json!({"agent": "a", "capability": "c", "tool": "t", "target": "x",
                       "args_sha256": SHA, "level": 2});
    assert_eq!(
        post(p, "/v1/decide", &extra.to_string()).0,
        400,
        "unknown fields are refused"
    );
    let short =
        json!({"agent": "a", "capability": "c", "tool": "t", "target": "x", "args_sha256": "abc"});
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
    d.crash();
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
    let d = Daemon::start(&dir, &["--max-inflight", "0"]);
    assert_eq!(decide(d.port, "fs.edit", None).0, 503);
}

#[test]
fn a_crash_between_decide_and_outcome_loses_nothing() {
    let dir = fresh_log("crash");
    let d = Daemon::start(&dir, &[]);
    let (_, a) = decide(d.port, "fs.edit", Some("toolu_1"));
    let seq = a["receipt_seq"].as_u64().expect("seq");
    d.crash();
    verify(&dir);
    // After a restart the decision is still waiting, by its receipt number. Call ids lived only in
    // the old process, so they are gone.
    let d = Daemon::start(&dir, &[]);
    let by_call = json!({"call_id": "toolu_1", "verifier": "host", "result": "unknown", "evidence_sha256": SHA});
    assert_eq!(post(d.port, "/v1/outcome", &by_call.to_string()).0, 404);
    let by_seq =
        json!({"receipt_seq": seq, "verifier": "human", "result": "pass", "evidence_sha256": SHA});
    assert_eq!(post(d.port, "/v1/outcome", &by_seq.to_string()).0, 200);
    d.crash();
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
        &pre("Read", json!({"file_path": "/repo/README.md"}), None),
    );
    assert_eq!(decision(&read), "allow");
    let edit = run_hook(
        &d.url(),
        &pre(
            "Edit",
            json!({"file_path": "/repo/src/a.rs", "old_string": "a", "new_string": "b"}),
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
        "tool_input": {"file_path": "/repo/src/a.rs"}, "tool_response": {"filePath": "/repo/src/a.rs"},
    });
    assert_eq!(
        run_hook(&d.url(), &post),
        Value::Null,
        "PostToolUse prints nothing"
    );
    d.crash();
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
    assert_eq!(lines[1]["action"]["capability"], "fs.edit");
    assert_eq!(lines[1]["action"]["target"], "/repo/src/a.rs");
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
}
