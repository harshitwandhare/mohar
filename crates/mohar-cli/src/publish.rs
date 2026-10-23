//! Where checkpoints are published: a plain file, or a git clone whose remote the log's operator can't
//! rewrite (a protected branch in a repository someone else controls, for example).
//!
//! A git target is `git:<path to a clone>`. Publishing pulls (fast-forward only), appends the checkpoint
//! to `checkpoints.jsonl` in the clone, commits and pushes. Verifying pulls first and reads the same file.
//! Any git step that fails is an error: a checkpoint that didn't reach the remote isn't published, and a
//! remote that couldn't be read hasn't been checked.

use std::path::{Path, PathBuf};
use std::process::Command;

use mohar_core::checkpoint::Checkpoint;
use mohar_core::store::publish_checkpoint;

/// The file a git target keeps its checkpoints in, at the top of the clone.
const GIT_FILE: &str = "checkpoints.jsonl";

/// A place checkpoints are published to and read back from.
#[derive(Debug, PartialEq, Eq)]
pub enum Target {
    /// An append-only file.
    File(PathBuf),
    /// A git clone with a remote to push to and pull from.
    Git(PathBuf),
}

impl Target {
    /// `git:<clone>` or a file path. Other URLs are refused rather than written as local paths.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(clone) = s.strip_prefix("git:") {
            if clone.is_empty() {
                return Err("git: needs the path of a clone".into());
            }
            return Ok(Self::Git(PathBuf::from(clone)));
        }
        if s.contains("://") {
            return Err(format!(
                "{s}: publish to a file or to git:<clone>, not a URL"
            ));
        }
        Ok(Self::File(PathBuf::from(s)))
    }

    /// Refuse a target inside the log directory: deleting the log would delete it too.
    pub fn check_outside(&self, log_dir: &Path) -> Result<(), String> {
        let (path, shown) = match self {
            // A file need not exist yet; its directory must.
            Self::File(p) => (
                match p.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => parent,
                    _ => Path::new("."),
                },
                p.display(),
            ),
            Self::Git(clone) => (clone.as_path(), clone.display()),
        };
        // Both sides resolved the same way, so symlinks and Windows path forms can't sneak past.
        let path = std::fs::canonicalize(path).map_err(|e| format!("{shown}: {e}"))?;
        let dir =
            std::fs::canonicalize(log_dir).map_err(|e| format!("{}: {e}", log_dir.display()))?;
        if path.starts_with(&dir) {
            return Err(format!("{shown}: must be outside the log directory"));
        }
        Ok(())
    }

    /// Append `c` and, for git, commit and push it.
    pub fn publish(&self, c: &Checkpoint) -> Result<(), String> {
        match self {
            Self::File(p) => publish_checkpoint(p, c).map_err(|e| e.to_string()),
            Self::Git(clone) => {
                git(clone, &["pull", "--ff-only", "--quiet"])?;
                let file = clone.join(GIT_FILE);
                publish_checkpoint(&file, c).map_err(|e| e.to_string())?;
                git(clone, &["add", "--", GIT_FILE])?;
                let message = format!("mohar checkpoint at {} receipts", c.count);
                git(clone, &["commit", "--quiet", "-m", &message])?;
                git(clone, &["push", "--quiet"])
            }
        }
    }

    /// The file to read this target's checkpoints from, brought up to date first.
    pub fn fetch(&self) -> Result<PathBuf, String> {
        match self {
            Self::File(p) => Ok(p.clone()),
            Self::Git(clone) => {
                git(clone, &["pull", "--ff-only", "--quiet"])?;
                Ok(clone.join(GIT_FILE))
            }
        }
    }
}

/// Run git in `clone`, without a shell; anything but success is an error carrying git's own words.
fn git(clone: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(clone)
        .args(args)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "git {} in {}: {}",
        args.join(" "),
        clone.display(),
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

#[cfg(test)]
mod tests {
    use super::Target;
    use std::path::PathBuf;

    #[test]
    fn targets_parse_as_files_or_git_clones_and_urls_are_refused() {
        assert_eq!(
            Target::parse("out/cp.jsonl"),
            Ok(Target::File(PathBuf::from("out/cp.jsonl")))
        );
        assert_eq!(
            Target::parse("git:../audit"),
            Ok(Target::Git(PathBuf::from("../audit")))
        );
        assert!(Target::parse("git:").is_err());
        assert!(Target::parse("https://example.invalid/log").is_err());
    }
}
