//! Strict privacy mode: no agent id or target reaches receipts.jsonl in the clear.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use mohar_core::privacy::is_pseudonym;
use mohar_core::store::{FileLog, OpenError, read_receipts, verify_file};
use mohar_core::{Action, Decision, Entry, parse_public_key};

const AGENT: &str = "agent:clinic/intake-bot";
const TARGET: &str = "patients/ana-ruiz/notes.md";

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mohar-privacy-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn entry(agent: &str, target: &str) -> Entry {
    Entry {
        ts: "2026-10-14T09:00:00.000Z".into(),
        agent_id: agent.into(),
        action: Action {
            capability: "fs.edit.docs".into(),
            tool: "Edit".into(),
            target: target.into(),
            args_sha256: "c41b77d0".into(),
        },
        decision: Decision {
            result: "allow".into(),
            level: 1,
            by: "score".into(),
        },
        verification: None,
    }
}

fn read(dir: &Path, file: &str) -> String {
    fs::read_to_string(dir.join(file)).expect(file)
}

/// The clear values in identities.jsonl, by pseudonym.
fn identities(dir: &Path) -> Vec<(String, String)> {
    read(dir, "identities.jsonl")
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).expect("identity line");
            (
                v["id"].as_str().expect("id").to_string(),
                v["value"].as_str().expect("value").to_string(),
            )
        })
        .collect()
}

#[test]
fn no_id_or_target_is_in_the_log_in_the_clear() {
    let dir = temp_dir("clear");
    let mut log = FileLog::init_strict(&dir).expect("init");
    assert!(log.is_strict());
    let r = log.append(entry(AGENT, TARGET)).expect("append");
    log.append(entry(AGENT, "patients/ana-ruiz/plan.md"))
        .expect("append");
    drop(log);

    let text = read(&dir, "receipts.jsonl");
    for clear in ["clinic", "intake-bot", "ana-ruiz", "patients", "notes.md"] {
        assert!(!text.contains(clear), "{clear} is in the log: {text}");
    }
    assert!(is_pseudonym(&r.agent.id), "{}", r.agent.id);
    assert!(is_pseudonym(&r.action.target), "{}", r.action.target);
    let receipts = read_receipts(&dir.join("receipts.jsonl")).expect("read");
    assert_eq!(
        receipts[0].agent.id, receipts[1].agent.id,
        "one agent, one id"
    );
    assert_ne!(receipts[0].action.target, receipts[1].action.target);
}

#[test]
fn the_mapping_back_is_written_once_per_value_outside_the_chain() {
    let dir = temp_dir("mapping");
    let mut log = FileLog::init_strict(&dir).expect("init");
    let r = log.append(entry(AGENT, TARGET)).expect("append");
    log.append(entry(AGENT, TARGET)).expect("append");
    assert_eq!(log.pseudonym(AGENT), r.agent.id);
    drop(log);
    assert_eq!(
        identities(&dir),
        vec![
            (r.agent.id.clone(), AGENT.to_string()),
            (r.action.target.clone(), TARGET.to_string())
        ]
    );
    // A reopened log knows what it already wrote.
    FileLog::open(&dir)
        .expect("open")
        .append(entry(AGENT, TARGET))
        .expect("append");
    assert_eq!(identities(&dir).len(), 2);
}

#[test]
fn the_log_verifies_after_the_mapping_and_the_secret_are_erased() {
    let dir = temp_dir("erased");
    let mut log = FileLog::init_strict(&dir).expect("init");
    for _ in 0..3 {
        log.append(entry(AGENT, TARGET)).expect("append");
    }
    drop(log);
    fs::remove_file(dir.join("identities.jsonl")).expect("erase mapping");
    fs::remove_file(dir.join("privacy.key")).expect("erase secret");
    let key = parse_public_key(read(&dir, "public.key").trim()).expect("public key");
    let stats = verify_file(&dir.join("receipts.jsonl"), &key).expect("still verifies");
    assert_eq!(stats.receipts, 3);
}

#[test]
fn erasing_the_mapping_keeps_the_same_pseudonyms() {
    let dir = temp_dir("same");
    let mut log = FileLog::init_strict(&dir).expect("init");
    let before = log.append(entry(AGENT, TARGET)).expect("append");
    drop(log);
    fs::remove_file(dir.join("identities.jsonl")).expect("erase mapping");

    let mut log = FileLog::open(&dir).expect("open");
    assert!(log.is_strict(), "the secret alone keeps the mode on");
    let after = log.append(entry(AGENT, TARGET)).expect("append");
    assert_eq!(before.agent.id, after.agent.id, "trust keeps adding up");
    drop(log);
    assert_eq!(identities(&dir).len(), 2, "written again once seen again");
}

#[test]
fn a_pseudonym_is_written_through_unchanged() {
    let dir = temp_dir("through");
    let mut log = FileLog::init_strict(&dir).expect("init");
    let id = log.pseudonym(AGENT);
    let r = log.append(entry(&id, TARGET)).expect("append");
    assert_eq!(r.agent.id, id, "not hashed twice");
    drop(log);
    assert_eq!(identities(&dir).len(), 1, "only the target was new");
}

#[test]
fn identities_without_the_secret_refuse_to_open() {
    let dir = temp_dir("nosecret");
    FileLog::init_strict(&dir)
        .expect("init")
        .append(entry(AGENT, TARGET))
        .expect("append");
    fs::remove_file(dir.join("privacy.key")).expect("remove secret");
    match FileLog::open(&dir) {
        Err(OpenError::PrivacyKeyMissing(p)) => assert!(p.ends_with("privacy.key")),
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!("opened a strict log without its secret"),
    }
}

#[test]
fn a_secret_of_the_wrong_length_refuses_to_open() {
    let dir = temp_dir("badsecret");
    drop(FileLog::init_strict(&dir).expect("init"));
    fs::write(dir.join("privacy.key"), [7u8; 31]).expect("write");
    match FileLog::open(&dir) {
        Err(OpenError::BadKey(p)) => assert!(p.ends_with("privacy.key")),
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!("opened with a short secret"),
    }
}

#[test]
fn a_torn_mapping_line_is_ended_before_the_next_one() {
    let dir = temp_dir("torn");
    drop(FileLog::init_strict(&dir).expect("init"));
    fs::write(dir.join("identities.jsonl"), b"{\"id\":\"hmac-sha256:ab").expect("tear");
    FileLog::open(&dir)
        .expect("open")
        .append(entry(AGENT, TARGET))
        .expect("append");
    let text = read(&dir, "identities.jsonl");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    for l in &lines[1..] {
        serde_json::from_str::<serde_json::Value>(l).expect("whole line");
    }
}

#[test]
fn a_plain_log_keeps_ids_and_targets_as_given() {
    let dir = temp_dir("plain");
    let mut log = FileLog::init(&dir).expect("init");
    assert!(!log.is_strict());
    assert_eq!(log.pseudonym(AGENT), AGENT);
    let r = log.append(entry(AGENT, TARGET)).expect("append");
    assert_eq!(
        (r.agent.id.as_str(), r.action.target.as_str()),
        (AGENT, TARGET)
    );
    assert!(!dir.join("identities.jsonl").exists());
    assert!(!dir.join("privacy.key").exists());
}

#[cfg(unix)]
#[test]
fn the_secret_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("mode");
    drop(FileLog::init_strict(&dir).expect("init"));
    let mode = fs::metadata(dir.join("privacy.key"))
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn a_secret_that_cannot_be_read_refuses_to_open() {
    let dir = temp_dir("unreadable");
    drop(FileLog::init_strict(&dir).expect("init"));
    fs::remove_file(dir.join("privacy.key")).expect("remove");
    fs::create_dir(dir.join("privacy.key")).expect("a directory in its place");
    match FileLog::open(&dir) {
        Err(OpenError::Io { path, .. }) => assert!(path.ends_with("privacy.key")),
        Err(e) => panic!("wrong error: {e}"),
        Ok(_) => panic!("opened without reading the secret"),
    }
}

#[test]
fn erasing_the_secret_and_the_mapping_together_does_not_turn_the_mode_off() {
    let dir = temp_dir("both");
    FileLog::init_strict(&dir)
        .expect("init")
        .append(entry(AGENT, TARGET))
        .expect("append");
    fs::remove_file(dir.join("identities.jsonl")).expect("erase mapping");
    fs::remove_file(dir.join("privacy.key")).expect("erase secret");
    assert!(
        matches!(FileLog::open(&dir), Err(OpenError::PrivacyKeyMissing(_))),
        "new receipts would be written in the clear"
    );
}
