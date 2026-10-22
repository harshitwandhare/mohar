//! The mohar binary end to end.
#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn mohar(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mohar"))
        .arg("--dir")
        .arg(dir)
        .args(args)
        .output()
        .expect("run mohar")
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mohar-cli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn append(dir: &Path, target: &str) -> Output {
    mohar(
        dir,
        &[
            "append",
            "--agent",
            "agent:test/1",
            "--capability",
            "fs.edit.docs",
            "--tool",
            "Edit",
            "--target",
            target,
            "--args-sha256",
            "c41b77d0",
            "--result",
            "allow",
            "--level",
            "1",
            "--by",
            "score",
        ],
    )
}

#[test]
fn init_append_log_verify() {
    let dir = temp_dir("happy");
    assert!(mohar(&dir, &["init"]).status.success());
    for t in ["docs/a.md", "docs/b.md", "docs/c.md"] {
        let out = append(&dir, t);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let log = String::from_utf8(mohar(&dir, &["log", "--last", "2"]).stdout).expect("utf8");
    assert_eq!(log.lines().count(), 2);
    assert!(log.contains("docs/c.md"));

    let v = mohar(&dir, &["verify"]);
    assert!(v.status.success());
    assert!(String::from_utf8_lossy(&v.stdout).contains("ok: 3 receipts verified"));
}

#[test]
fn verify_names_the_broken_receipt_and_exits_1() {
    let dir = temp_dir("broken");
    assert!(mohar(&dir, &["init"]).status.success());
    for t in ["a", "b", "c"] {
        assert!(append(&dir, t).status.success());
    }
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let edited: Vec<String> = text
        .lines()
        .enumerate()
        .map(|(i, l)| {
            if i == 1 {
                l.replace("\"level\":1", "\"level\":2")
            } else {
                l.to_string()
            }
        })
        .collect();
    fs::write(&path, edited.join("\n") + "\n").expect("write");

    let v = mohar(&dir, &["verify"]);
    assert_eq!(v.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&v.stdout).contains("receipt 1: BadSignature"));
}

#[test]
fn append_refuses_a_tampered_log() {
    let dir = temp_dir("refuse");
    assert!(mohar(&dir, &["init"]).status.success());
    assert!(append(&dir, "a").status.success());
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    fs::write(&path, text.replace("\"allow\"", "\"deny\"")).expect("write");
    let out = append(&dir, "b");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("chain does not verify"));
}
