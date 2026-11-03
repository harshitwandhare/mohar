//! `mohar approve` and `mohar refuse`: show a person an escalated action and the agent's record, then
//! send their answer to the daemon, bound to the hash of exactly what was shown.

use std::io::BufRead;
use std::process::ExitCode;

use serde_json::{Value, json};

use crate::hook::post;

/// Fetch escalation `seq`, print it, ask unless `yes`, and post `act` (`approve` or `refuse`) as `by`.
/// Exit 0 when the answer is recorded, 1 when the person says no or the daemon refuses the answer.
pub fn run(
    daemon: &str,
    act: &str,
    seq: u64,
    by: &str,
    yes: bool,
    input: &mut dyn BufRead,
) -> Result<ExitCode, String> {
    let shown = match post(daemon, "/v1/escalation", &json!({ "receipt_seq": seq }))? {
        (200, body) => body,
        (_, body) => return Ok(refused(&body)),
    };
    let hash = shown["action_sha256"]
        .as_str()
        .ok_or("the daemon's answer has no action_sha256")?
        .to_string();
    print!("{}", describe(&shown));
    if !yes {
        println!("{act} this exact action as {by}? [y/N]");
        let mut line = String::new();
        input.read_line(&mut line).map_err(|e| e.to_string())?;
        if !matches!(line.trim(), "y" | "Y" | "yes") {
            println!("nothing sent");
            return Ok(ExitCode::from(1));
        }
    }
    // The hash of what was printed, so a different action can't be answered by mistake.
    let body = json!({ "receipt_seq": seq, "by": by, "action_sha256": hash });
    match post(daemon, &format!("/v1/{act}"), &body)? {
        (200, r) => {
            let what = if act == "approve" {
                "approved"
            } else {
                "refused"
            };
            match r["until"].as_u64() {
                Some(until) => println!(
                    "{what}, receipt {}; usable once until {until}",
                    r["receipt_seq"]
                ),
                None => println!("{what}, receipt {}", r["receipt_seq"]),
            }
            Ok(ExitCode::SUCCESS)
        }
        (_, r) => Ok(refused(&r)),
    }
}

fn refused(body: &Value) -> ExitCode {
    eprintln!(
        "mohar: the daemon refused: {}",
        body["error"].as_str().unwrap_or("no reason given")
    );
    ExitCode::from(1)
}

/// The escalation as a person reads it.
fn describe(e: &Value) -> String {
    let s = |v: &Value| v.as_str().unwrap_or("?").to_string();
    let a = &e["action"];
    let asked: Vec<String> = e["to"]
        .as_array()
        .map(|to| to.iter().map(s).collect())
        .unwrap_or_default();
    let n = |v: &Value| v.as_u64().unwrap_or(0);
    let word = |k: u64, one: &'static str, many: &'static str| if k == 1 { one } else { many };
    format!(
        "escalation {seq}\n  agent    {agent}\n  action   {tool} {target} ({cap})\n  args     sha256:{args}\n  hash     sha256:{hash}\n  asked    {asked}\n  record   level {level}, {p} verified {ps}, {f} {fs}{susp}\n",
        seq = e["receipt_seq"],
        agent = s(&e["agent"]),
        tool = s(&a["tool"]),
        target = s(&a["target"]),
        cap = s(&a["capability"]),
        args = s(&a["args_sha256"]),
        hash = s(&e["action_sha256"]),
        asked = if asked.is_empty() {
            "nobody named (the host's prompt decides)".to_string()
        } else {
            asked.join(", ")
        },
        level = n(&e["level"]),
        p = n(&e["passes"]),
        ps = word(n(&e["passes"]), "pass", "passes"),
        f = n(&e["failures"]),
        fs = word(n(&e["failures"]), "failure", "failures"),
        susp = if e["suspended"] == json!(true) {
            ", suspended"
        } else {
            ""
        },
    )
}

#[cfg(test)]
mod tests {
    use super::describe;
    use serde_json::json;

    #[test]
    fn an_escalation_reads_plainly() {
        let e = json!({"receipt_seq": 7, "agent": "agent:x/1", "action_sha256": "ab",
            "action": {"tool": "Edit", "target": "src/a.rs", "capability": "fs.edit.code", "args_sha256": "cd"},
            "to": ["user:lead-1", "user:o"], "level": 1, "passes": 1, "failures": 2, "suspended": true});
        let text = describe(&e);
        assert!(
            text.contains("action   Edit src/a.rs (fs.edit.code)"),
            "{text}"
        );
        assert!(text.contains("asked    user:lead-1, user:o"), "{text}");
        assert!(
            text.contains("level 1, 1 verified pass, 2 failures, suspended"),
            "{text}"
        );
        let none = describe(&json!({"to": [], "passes": 3, "failures": 1}));
        assert!(none.contains("nobody named"), "{none}");
        assert!(none.contains("3 verified passes, 1 failure\n"), "{none}");
    }
}
