//! `mohar hook claude-code`: the command Claude Code runs for PreToolUse and PostToolUse.
//!
//! It reads the hook payload on stdin, asks the local daemon, and prints the answer in the form
//! Claude Code reads (`hookSpecificOutput.permissionDecision`). If the daemon can't be reached or
//! answers with anything unexpected, a PreToolUse call is denied: Mohar fails closed. Payload fields
//! follow https://code.claude.com/docs/en/hooks.md as of October 2026.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Largest payload read from stdin. Tool inputs with whole files in them can be large.
const MAX_STDIN: u64 = 8 * 1024 * 1024;
/// How long the hook waits for the daemon before it denies.
const DAEMON_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the hook waits for a task's tests, matching the hook timeout in hooks.json.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(890);

/// Run the hook. Returns the text for stdout; the process always exits 0 so Claude Code reads it.
pub fn claude_code(daemon: &str, input: &mut dyn Read) -> String {
    let mut raw = Vec::new();
    if input.take(MAX_STDIN + 1).read_to_end(&mut raw).is_err() || raw.len() as u64 > MAX_STDIN {
        return deny("Mohar could not read the hook payload");
    }
    let Ok(payload) = serde_json::from_slice::<Value>(&raw) else {
        return deny("Mohar could not parse the hook payload");
    };
    match payload["hook_event_name"].as_str() {
        Some("PreToolUse") => pre_tool_use(daemon, &payload),
        Some("PostToolUse") => {
            post_tool_use(daemon, &payload);
            String::new()
        }
        // The task (or a subagent's part of it) is done: verify what it changed.
        Some("Stop") | Some("SubagentStop") => {
            task_done(daemon, &payload);
            String::new()
        }
        // Nothing to decide for other events; say nothing so Claude Code carries on.
        _ => String::new(),
    }
}

fn pre_tool_use(daemon: &str, p: &Value) -> String {
    let tool = p["tool_name"].as_str().unwrap_or("");
    if tool.is_empty() {
        return deny("Mohar got a PreToolUse payload with no tool_name");
    }
    let input = &p["tool_input"];
    let mut req = json!({
        "agent": agent_id(p),
        "tool": tool,
        "target": target(input),
        "args_sha256": sha256_jcs(input),
    });
    if let Some(call) = p["tool_use_id"].as_str().filter(|c| !c.is_empty()) {
        req["call_id"] = json!(call);
    }
    if let Some(task) = p["session_id"].as_str().filter(|t| !t.is_empty()) {
        req["task"] = json!(task);
    }
    let answer = match post(daemon, "/v1/decide", &req) {
        Ok((200, body)) => body,
        Ok((status, body)) => {
            let why = body["error"].as_str().unwrap_or("no reason given");
            return deny(&format!(
                "Mohar daemon refused the request ({status}: {why}); denying"
            ));
        }
        Err(e) => {
            return deny(&format!(
                "Mohar daemon unreachable at {daemon} ({e}); denying"
            ));
        }
    };
    let seq = answer["receipt_seq"].as_u64();
    let reason = |what: &str| match seq {
        Some(s) => format!("Mohar: {what} (receipt {s})"),
        None => format!("Mohar: {what}"),
    };
    let (decision, why) = match answer["result"].as_str() {
        Some("allow") => ("allow", reason("allowed")),
        Some("escalate") => (
            "ask",
            reason("not earned yet on this capability, so a person decides"),
        ),
        Some("deny") => match answer["reason"].as_str() {
            Some(why) => ("deny", reason(&format!("refused by a gate: {why}"))),
            None => ("deny", reason("denied")),
        },
        _ => ("deny", reason("unexpected answer from the daemon; denying")),
    };
    decision_json(decision, &why)
}

/// Record that the tool ran. This is the host's report, not verification, and never counts toward
/// trust. A failure here can't undo the action, so it is reported on stderr and otherwise ignored.
fn post_tool_use(daemon: &str, p: &Value) {
    let Some(call) = p["tool_use_id"].as_str().filter(|c| !c.is_empty()) else {
        return;
    };
    let req = json!({
        "call_id": call,
        "verifier": "host",
        "result": "unknown",
        "evidence_sha256": sha256_jcs(&p["tool_response"]),
    });
    if let Err(e) = post(daemon, "/v1/outcome", &req) {
        eprintln!("mohar: could not record the outcome of {call}: {e}");
    }
}

/// Ask the daemon to verify the finished task. Verification failing to start can't undo anything, so
/// it is reported on stderr and the session carries on.
fn task_done(daemon: &str, p: &Value) {
    let Some(task) = p["session_id"].as_str().filter(|t| !t.is_empty()) else {
        return;
    };
    let req = json!({ "agent": agent_id(p), "task": task });
    match post_waiting(daemon, "/v1/verify", &req, VERIFY_TIMEOUT) {
        Ok((200, body)) => {
            if let Some(r) = body["result"].as_str() {
                eprintln!("mohar: verified {} actions: {r}", body["verified"]);
            }
        }
        Ok((status, body)) => {
            eprintln!("mohar: verification refused ({status}): {}", body["error"])
        }
        Err(e) => eprintln!("mohar: could not verify the task: {e}"),
    }
}

fn decision_json(decision: &str, reason: &str) -> String {
    json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    })
    .to_string()
}

fn deny(reason: &str) -> String {
    decision_json("deny", reason)
}

/// Agents are identified by role, not by session, so their record carries across sessions.
fn agent_id(p: &Value) -> String {
    let role = p["agent_type"]
        .as_str()
        .filter(|t| !t.is_empty())
        .unwrap_or("main");
    format!("agent:claude-code/{role}")
}

/// What the tool acts on, as the receipt's target.
fn target(input: &Value) -> String {
    for key in [
        "file_path",
        "notebook_path",
        "path",
        "url",
        "pattern",
        "query",
        "command",
    ] {
        if let Some(v) = input[key].as_str() {
            return v.chars().take(4096).collect();
        }
    }
    String::new()
}

/// SHA-256 of the RFC 8785 form of a JSON value, so the same arguments always hash the same.
fn sha256_jcs(v: &Value) -> String {
    let bytes = serde_jcs::to_vec(v).unwrap_or_default();
    Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// POST JSON to the daemon. Only loopback addresses are accepted, so the hook never sends tool
/// arguments off the machine.
fn post(daemon: &str, path: &str, body: &Value) -> Result<(u16, Value), String> {
    post_waiting(daemon, path, body, DAEMON_TIMEOUT)
}

fn post_waiting(
    daemon: &str,
    path: &str,
    body: &Value,
    wait: Duration,
) -> Result<(u16, Value), String> {
    let hostport = daemon
        .strip_prefix("http://")
        .unwrap_or(daemon)
        .trim_end_matches('/');
    let addr: SocketAddr = hostport
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or("no address")?;
    if !addr.ip().is_loopback() {
        return Err(format!("{addr} is not a loopback address"));
    }
    let mut s = TcpStream::connect_timeout(&addr, DAEMON_TIMEOUT).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(wait)).map_err(|e| e.to_string())?;
    s.set_write_timeout(Some(DAEMON_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let text = body.to_string();
    write!(
        s,
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        text.len()
    )
    .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.take(1024 * 1024)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let raw = String::from_utf8(raw).map_err(|_| "answer is not UTF-8".to_string())?;
    let (head, body) = raw.split_once("\r\n\r\n").ok_or("malformed answer")?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("no status in answer")?;
    let value = serde_json::from_str(body).map_err(|_| "answer body is not JSON".to_string())?;
    Ok((status, value))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// A stand-in daemon on a free loopback port that gives every request the same answer and
    /// passes on what it was asked. Returns its URL and the requests' paths and bodies.
    fn fake(status: u16, body: &str) -> (String, mpsc::Receiver<(String, Value)>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("addr"));
        let answer = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { return };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read the head, then exactly Content-Length bytes of body.
                let (path, req) = loop {
                    let Ok(n) = s.read(&mut chunk) else { return };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                        let len: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("Content-Length: "))
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        if rest.len() >= len {
                            let path = head.split(' ').nth(1).unwrap_or("").to_string();
                            break (path, serde_json::from_str(rest).unwrap_or(Value::Null));
                        }
                    }
                };
                let _ = tx.send((path, req));
                let _ = s.write_all(answer.as_bytes());
            }
        });
        (url, rx)
    }

    fn run(daemon: &str, payload: &Value) -> String {
        claude_code(daemon, &mut payload.to_string().as_bytes())
    }

    fn answer_of(out: &str) -> (String, String) {
        let v: Value = serde_json::from_str(out).expect("hook output is JSON");
        let h = &v["hookSpecificOutput"];
        (
            h["permissionDecision"].as_str().unwrap_or("").to_string(),
            h["permissionDecisionReason"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        )
    }

    fn pre(tool: &str, input: Value) -> Value {
        json!({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input,
               "tool_use_id": "toolu_1", "session_id": "s1"})
    }

    /// A port nothing listens on.
    fn closed_port() -> String {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        format!("http://{}", l.local_addr().expect("addr"))
    }

    #[test]
    fn a_daemon_refusal_is_a_deny_that_says_why() {
        let (url, _) = fake(503, r#"{"error": "too many requests in flight"}"#);
        let (decision, why) = answer_of(&run(&url, &pre("Bash", json!({"command": "ls"}))));
        assert_eq!(decision, "deny");
        assert!(why.contains("503: too many requests in flight"), "{why}");
        let (url, _) = fake(500, "{}");
        let (decision, why) = answer_of(&run(&url, &pre("Bash", json!({"command": "ls"}))));
        assert_eq!(decision, "deny");
        assert!(why.contains("no reason given"), "{why}");
    }

    #[test]
    fn any_answer_but_allow_or_escalate_is_a_deny() {
        for (body, expect) in [
            (r#"{"result": "allow"}"#, ("allow", "Mohar: allowed")),
            (r#"{"result": "deny"}"#, ("deny", "Mohar: denied")),
            (
                r#"{"result": "maybe", "receipt_seq": 4}"#,
                (
                    "deny",
                    "Mohar: unexpected answer from the daemon; denying (receipt 4)",
                ),
            ),
            (
                r#"{"no": "result"}"#,
                ("deny", "Mohar: unexpected answer from the daemon; denying"),
            ),
        ] {
            let (url, _) = fake(200, body);
            let (decision, why) = answer_of(&run(&url, &pre("Read", json!({"file_path": "a"}))));
            assert_eq!((decision.as_str(), why.as_str()), expect, "{body}");
        }
    }

    #[test]
    fn malformed_answers_and_payloads_are_denied() {
        let (url, _) = fake(200, "not json");
        assert_eq!(answer_of(&run(&url, &pre("Read", json!({})))).0, "deny");
        let no_tool = json!({"hook_event_name": "PreToolUse", "tool_input": {}});
        let (decision, why) = answer_of(&run(&closed_port(), &no_tool));
        assert_eq!(decision, "deny");
        assert!(why.contains("no tool_name"), "{why}");
        let huge = vec![b' '; (MAX_STDIN + 1) as usize];
        let (decision, why) = answer_of(&claude_code(&closed_port(), &mut huge.as_slice()));
        assert_eq!(decision, "deny");
        assert!(why.contains("could not read"), "{why}");
    }

    #[test]
    fn a_tool_with_no_known_target_field_has_an_empty_target() {
        let (url, asked) = fake(200, r#"{"result": "allow"}"#);
        run(&url, &pre("TodoWrite", json!({"todos": []})));
        let (_, req) = asked.recv().expect("asked");
        assert_eq!(req["target"], "");
    }

    #[test]
    fn events_the_hook_does_not_handle_get_no_answer() {
        let out = run(&closed_port(), &json!({"hook_event_name": "Notification"}));
        assert_eq!(out, "");
    }

    #[test]
    fn reports_without_ids_send_nothing_and_failures_never_block() {
        let (url, asked) = fake(200, r#"{"receipt_seq": 1}"#);
        assert_eq!(run(&url, &json!({"hook_event_name": "PostToolUse"})), "");
        assert_eq!(run(&url, &json!({"hook_event_name": "Stop"})), "");
        assert!(asked.try_recv().is_err(), "nothing was sent");

        let down = closed_port();
        let post = json!({"hook_event_name": "PostToolUse", "tool_use_id": "toolu_1", "tool_response": {}});
        let stop = json!({"hook_event_name": "Stop", "session_id": "s1"});
        assert_eq!(run(&down, &post), "");
        assert_eq!(run(&down, &stop), "");

        let (refusing, asked) = fake(400, r#"{"error": "agent and task must be non-empty"}"#);
        assert_eq!(run(&refusing, &stop), "");
        assert_eq!(asked.recv().expect("asked").0, "/v1/verify");
    }
}
