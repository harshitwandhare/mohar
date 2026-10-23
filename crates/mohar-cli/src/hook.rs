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
    s.set_read_timeout(Some(DAEMON_TIMEOUT))
        .map_err(|e| e.to_string())?;
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
