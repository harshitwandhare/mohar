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
    assert!(
        String::from_utf8_lossy(&v.stdout).contains("ok: 3 receipts and 0 checkpoints verified")
    );
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

#[test]
fn verify_catches_receipts_removed_after_a_checkpoint() {
    let dir = temp_dir("cut");
    assert!(mohar(&dir, &["init"]).status.success());
    for t in ["a", "b", "c"] {
        assert!(append(&dir, t).status.success());
    }
    assert!(mohar(&dir, &["checkpoint"]).status.success());
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let kept: Vec<&str> = text.lines().take(2).collect();
    fs::write(
        &path,
        kept.join(
            "
",
        ) + "
",
    )
    .expect("write");

    let v = mohar(&dir, &["verify"]);
    assert_eq!(v.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&v.stdout).contains("should hold 3 receipts, holds 2"));
}

#[test]
fn an_external_checkpoint_catches_a_log_cut_together_with_its_own_checkpoints() {
    let dir = temp_dir("ext-cut");
    let outside = temp_dir("ext-cut-published");
    fs::create_dir_all(&outside).expect("mkdir");
    let published = outside.join("published.jsonl");
    let published_arg = published.to_str().expect("utf8 path");
    assert!(mohar(&dir, &["init"]).status.success());
    for t in ["a", "b", "c"] {
        assert!(append(&dir, t).status.success());
    }
    let out = mohar(&dir, &["checkpoint", "--publish", published_arg]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let ok = mohar(&dir, &["verify", "--checkpoints", published_arg]);
    assert!(
        String::from_utf8_lossy(&ok.stdout).contains("ok: 3 receipts and 2 checkpoints verified"),
        "{}",
        String::from_utf8_lossy(&ok.stdout)
    );

    // Cut the last receipt and every local checkpoint, so the log alone looks whole.
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let kept: Vec<&str> = text.lines().take(2).collect();
    fs::write(&path, kept.join("\n") + "\n").expect("write");
    fs::write(dir.join("checkpoints.jsonl"), "").expect("write");
    assert!(mohar(&dir, &["verify"]).status.success());

    let v = mohar(&dir, &["verify", "--checkpoints", published_arg]);
    assert_eq!(v.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&v.stdout).contains("should hold 3 receipts, holds 2"));
}

#[test]
fn verify_fails_when_the_named_external_checkpoints_are_missing() {
    let dir = temp_dir("ext-missing");
    assert!(mohar(&dir, &["init"]).status.success());
    let missing = dir.with_extension("nowhere.jsonl");
    let v = mohar(
        &dir,
        &["verify", "--checkpoints", missing.to_str().expect("utf8")],
    );
    assert_ne!(v.status.code(), Some(0));
}

#[test]
fn publish_refuses_a_target_inside_the_log_directory() {
    let dir = temp_dir("ext-inside");
    assert!(mohar(&dir, &["init"]).status.success());
    let inside = dir.join("published.jsonl");
    let out = mohar(
        &dir,
        &["checkpoint", "--publish", inside.to_str().expect("utf8")],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("outside the log directory"));
    assert!(!inside.exists());
}

#[test]
fn publish_refuses_a_url_for_now() {
    let dir = temp_dir("ext-url");
    assert!(mohar(&dir, &["init"]).status.success());
    let out = mohar(
        &dir,
        &["checkpoint", "--publish", "https://example.invalid/log"],
    );
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn log_prints_every_receipt_or_the_last_few() {
    let dir = temp_dir("log-all");
    assert!(mohar(&dir, &["init"]).status.success());
    for t in ["a.md", "b.md", "c.md"] {
        assert!(append(&dir, t).status.success());
    }
    let all = String::from_utf8(mohar(&dir, &["log"]).stdout).expect("utf8");
    assert_eq!(all.lines().count(), 3);
    assert!(all.lines().next().unwrap_or("").contains("a.md"));
    let none = mohar(&dir, &["log", "--last", "0"]);
    assert!(none.status.success());
    assert!(none.stdout.is_empty());
}

#[test]
fn publish_takes_a_bare_file_name_relative_to_where_it_runs() {
    let dir = temp_dir("ext-bare");
    let cwd = temp_dir("ext-bare-cwd");
    fs::create_dir_all(&cwd).expect("mkdir");
    assert!(mohar(&dir, &["init"]).status.success());
    assert!(append(&dir, "a").status.success());
    let out = Command::new(env!("CARGO_BIN_EXE_mohar"))
        .current_dir(&cwd)
        .arg("--dir")
        .arg(&dir)
        .args(["checkpoint", "--publish", "published.jsonl"])
        .output()
        .expect("run mohar");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read_to_string(cwd.join("published.jsonl"))
            .expect("published")
            .lines()
            .count(),
        1
    );
}

#[test]
fn verify_can_trust_checkpoints_and_still_catches_a_cut_tail() {
    let dir = temp_dir("trust");
    assert!(mohar(&dir, &["init"]).status.success());
    for t in ["a", "b", "c"] {
        assert!(append(&dir, t).status.success());
    }
    assert!(mohar(&dir, &["checkpoint"]).status.success());
    assert!(append(&dir, "d").status.success());
    let ok = mohar(&dir, &["verify", "--trust-checkpoints"]);
    assert!(
        String::from_utf8_lossy(&ok.stdout).contains("ok: 4 receipts and 1 checkpoints verified"),
        "{}",
        String::from_utf8_lossy(&ok.stdout)
    );
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let kept: Vec<&str> = text.lines().take(2).collect();
    fs::write(&path, kept.join("\n") + "\n").expect("write");
    let v = mohar(&dir, &["verify", "--trust-checkpoints"]);
    assert_eq!(v.status.code(), Some(1));
}

/// Run git in `dir` with a fixed identity, and fail the test if it fails.
fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
        .args(args)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A bare repository standing in for the remote, with one commit, and two clones of it: the
/// operator's, which publishes, and an auditor's, which only reads.
fn git_remote(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = temp_dir(name);
    let remote = root.join("remote.git");
    fs::create_dir_all(&remote).expect("mkdir");
    git(&remote, &["init", "-q", "--bare", "-b", "main"]);
    let seed = root.join("seed");
    fs::create_dir_all(&seed).expect("mkdir");
    git(&seed, &["init", "-q", "-b", "main"]);
    fs::write(seed.join("README"), "checkpoints\n").expect("write");
    git(&seed, &["add", "README"]);
    git(&seed, &["commit", "-q", "-m", "start"]);
    git(
        &seed,
        &["remote", "add", "origin", remote.to_str().expect("utf8")],
    );
    git(&seed, &["push", "-q", "-u", "origin", "main"]);
    let clone = |to: &str| {
        let path = root.join(to);
        git(&root, &["clone", "-q", remote.to_str().expect("utf8"), to]);
        path
    };
    (remote.clone(), clone("operator"), clone("auditor"))
}

/// mohar with a git identity, so the publishing commit works on a machine with none configured.
fn mohar_git(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mohar"))
        .arg("--dir")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .expect("run mohar")
}

fn arg(prefix: &str, p: &Path) -> String {
    format!("{prefix}{}", p.to_str().expect("utf8 path"))
}

#[test]
fn a_checkpoint_pushed_to_git_catches_a_log_cut_with_every_local_copy() {
    let dir = temp_dir("git-cut");
    let (_remote, operator, auditor) = git_remote("git-cut-remote");
    assert!(mohar(&dir, &["init"]).status.success());
    for t in ["a", "b", "c"] {
        assert!(append(&dir, t).status.success());
    }
    let out = mohar_git(&dir, &["checkpoint", "--publish", &arg("git:", &operator)]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let ok = mohar_git(&dir, &["verify", "--checkpoints", &arg("git:", &auditor)]);
    assert!(
        String::from_utf8_lossy(&ok.stdout).contains("ok: 3 receipts and 2 checkpoints verified"),
        "{}{}",
        String::from_utf8_lossy(&ok.stdout),
        String::from_utf8_lossy(&ok.stderr)
    );

    // The operator cuts the log, empties its own checkpoints and deletes its clone.
    let path = dir.join("receipts.jsonl");
    let text = fs::read_to_string(&path).expect("read");
    let kept: Vec<&str> = text.lines().take(2).collect();
    fs::write(&path, kept.join("\n") + "\n").expect("write");
    fs::write(dir.join("checkpoints.jsonl"), "").expect("write");
    let _ = fs::remove_dir_all(&operator);
    assert!(mohar(&dir, &["verify"]).status.success());

    let v = mohar_git(&dir, &["verify", "--checkpoints", &arg("git:", &auditor)]);
    assert_eq!(v.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&v.stdout).contains("should hold 3 receipts, holds 2"));
}

#[test]
fn a_checkpoint_that_cannot_be_pushed_is_reported_as_not_published() {
    let dir = temp_dir("git-push-fails");
    let (remote, operator, _) = git_remote("git-push-fails-remote");
    assert!(mohar(&dir, &["init"]).status.success());
    assert!(append(&dir, "a").status.success());
    fs::remove_dir_all(&remote).expect("the remote goes away");
    let out = mohar_git(&dir, &["checkpoint", "--publish", &arg("git:", &operator)]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not published"));
}

#[test]
fn a_git_source_that_cannot_be_brought_up_to_date_is_not_counted_as_checked() {
    let dir = temp_dir("git-pull-fails");
    let (remote, _, auditor) = git_remote("git-pull-fails-remote");
    assert!(mohar(&dir, &["init"]).status.success());
    fs::remove_dir_all(&remote).expect("the remote goes away");
    let v = mohar_git(&dir, &["verify", "--checkpoints", &arg("git:", &auditor)]);
    assert_eq!(v.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&v.stdout).contains("ok:"));
}

#[test]
fn a_git_clone_inside_the_log_directory_is_refused() {
    let dir = temp_dir("git-inside");
    assert!(mohar(&dir, &["init"]).status.success());
    let inside = dir.join("clone");
    fs::create_dir_all(&inside).expect("mkdir");
    let out = mohar_git(&dir, &["checkpoint", "--publish", &arg("git:", &inside)]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("outside the log directory"));
}
