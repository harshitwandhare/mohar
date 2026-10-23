//! The capability policy: which capability an action falls under, and what that capability is.
//!
//! A project writes `.mohar/policy.json`: named capabilities with a risk tier, a reversibility flag
//! and a ceiling, and an ordered list of rules mapping a host tool plus a path or command onto one of
//! them. The first matching rule wins. An action that matches nothing, or names a path outside the
//! project root, is `unclassified`: the highest risk, irreversible, with a ceiling of 0.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

/// How much damage a capability can do. `None` is for actions with no effect, such as reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    /// Reads and other actions that change nothing.
    None,
    /// Changes that are cheap to undo.
    Low,
    /// Changes that matter but can be undone.
    Medium,
    /// Changes that are costly or impossible to undo.
    High,
}

/// What a capability is.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capability {
    /// Risk tier.
    pub risk: Risk,
    /// Whether the action can be undone.
    pub reversible: bool,
    /// The highest trust level an agent may reach on it, 0 to 2. Set by a person.
    pub ceiling: u8,
}

/// The capability an action was classified as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    /// Capability name, or `unclassified`.
    pub capability: String,
    /// What that capability is.
    pub spec: Capability,
}

/// Name given to actions that match no rule.
pub const UNCLASSIFIED: &str = "unclassified";

const UNCLASSIFIED_SPEC: Capability = Capability {
    risk: Risk::High,
    reversible: false,
    ceiling: 0,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    /// Host tool names this rule applies to; empty means any tool.
    #[serde(default)]
    tools: Vec<String>,
    /// Globs over the target as a path relative to the root (`*`, `**`, `?`).
    #[serde(default)]
    paths: Vec<String>,
    /// Globs over the target as a command line; `*` matches anything.
    #[serde(default)]
    commands: Vec<String>,
    /// The capability an action matching this rule falls under.
    capability: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    #[serde(default)]
    root: Option<PathBuf>,
    capabilities: BTreeMap<String, Capability>,
    rules: Vec<Rule>,
    #[serde(default)]
    gates: Gates,
}

/// Hard gates: checked before any trust score, and no score outweighs them.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gates {
    /// Capabilities no agent may use at any level, such as pushing the default branch.
    #[serde(default)]
    pub deny_capabilities: Vec<String>,
    /// Hosts an agent may send requests to. When set, any other host is refused; when absent, this
    /// gate is off.
    #[serde(default)]
    pub allowed_hosts: Option<Vec<String>>,
    /// Paths (globs relative to the root) no agent may change, such as the files that verify its work.
    #[serde(default)]
    pub protected_paths: Vec<String>,
}

/// A gate that stopped an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateStop {
    /// Which gate: `outside_root`, `denied_capability`, `unlisted_host`, `protected_path` or
    /// `undecidable`.
    pub gate: &'static str,
    /// Why, in a sentence a person can act on.
    pub reason: String,
}

/// Host tools that change files, whose targets are paths.
const WRITE_TOOLS: [&str; 4] = ["Edit", "MultiEdit", "Write", "NotebookEdit"];
/// Host tools whose target is a URL.
const URL_TOOLS: [&str; 1] = ["WebFetch"];

/// A loaded, validated policy.
#[derive(Debug, Clone)]
pub struct Policy {
    root: PathBuf,
    capabilities: BTreeMap<String, Capability>,
    rules: Vec<Rule>,
    gates: Gates,
}

/// Why a policy file was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    /// Not valid JSON, or not the policy shape.
    #[error("policy is not valid: {0}")]
    Parse(String),
    /// A version this build doesn't read.
    #[error("policy version {0} is not supported; this build reads version 1")]
    Version(u32),
    /// A rule names a capability that isn't defined.
    #[error("rule {index} names capability {name:?}, which is not defined under capabilities")]
    UnknownCapability {
        /// Position of the rule, from 0.
        index: usize,
        /// The capability it names.
        name: String,
    },
    /// A rule has neither paths nor commands, so it would match every target of its tools.
    #[error("rule {index} has no paths and no commands; give one or the other")]
    EmptyRule {
        /// Position of the rule, from 0.
        index: usize,
    },
    /// A rule has both paths and commands.
    #[error("rule {index} has both paths and commands; split it into two rules")]
    MixedRule {
        /// Position of the rule, from 0.
        index: usize,
    },
    /// A ceiling above the highest level.
    #[error("capability {name:?} has ceiling {ceiling}; the highest level is 2")]
    Ceiling {
        /// The capability.
        name: String,
        /// The ceiling it was given.
        ceiling: u8,
    },
    /// A high-risk irreversible capability with a ceiling of 2, which the design forbids.
    #[error("capability {name:?} is high risk and irreversible, so its ceiling can't be above 1")]
    IrreversibleCeiling {
        /// The capability.
        name: String,
    },
    /// A gate names a capability that isn't defined.
    #[error("gates.deny_capabilities names {name:?}, which is not defined under capabilities")]
    UnknownGateCapability {
        /// The name.
        name: String,
    },
    /// The reserved name used for actions that match nothing.
    #[error("capability name \"unclassified\" is reserved")]
    Reserved,
}

impl Policy {
    /// Parse and validate a policy file. `base` is the directory relative roots resolve against.
    pub fn from_json(text: &str, base: &Path) -> Result<Self, PolicyError> {
        let file: File =
            serde_json::from_str(text).map_err(|e| PolicyError::Parse(e.to_string()))?;
        if file.version != 1 {
            return Err(PolicyError::Version(file.version));
        }
        for (name, c) in &file.capabilities {
            if name == UNCLASSIFIED {
                return Err(PolicyError::Reserved);
            }
            if c.ceiling > 2 {
                return Err(PolicyError::Ceiling {
                    name: name.clone(),
                    ceiling: c.ceiling,
                });
            }
            if c.risk == Risk::High && !c.reversible && c.ceiling > 1 {
                return Err(PolicyError::IrreversibleCeiling { name: name.clone() });
            }
        }
        for (index, r) in file.rules.iter().enumerate() {
            if !file.capabilities.contains_key(&r.capability) {
                return Err(PolicyError::UnknownCapability {
                    index,
                    name: r.capability.clone(),
                });
            }
            match (r.paths.is_empty(), r.commands.is_empty()) {
                (true, true) => return Err(PolicyError::EmptyRule { index }),
                (false, false) => return Err(PolicyError::MixedRule { index }),
                _ => {}
            }
        }
        let root = match file.root {
            Some(r) if r.is_absolute() => r,
            Some(r) => base.join(r),
            None => base.to_path_buf(),
        };
        for name in &file.gates.deny_capabilities {
            if !file.capabilities.contains_key(name) {
                return Err(PolicyError::UnknownGateCapability { name: name.clone() });
            }
        }
        Ok(Self {
            root: resolve(&root),
            capabilities: file.capabilities,
            rules: file.rules,
            gates: file.gates,
        })
    }

    /// The policy used when a project has none: reads run, edits and commands are classified by
    /// kind, and everything else is unclassified.
    pub fn builtin(root: &Path) -> Self {
        // A fixed, valid document; a failure here is a bug caught by the tests.
        Self::from_json(BUILTIN, root).unwrap_or_else(|e| unreachable!("built-in policy: {e}"))
    }

    /// What a capability is, by name; an unknown name (a policy changed since) is unclassified.
    pub fn spec(&self, capability: &str) -> Capability {
        self.capabilities
            .get(capability)
            .cloned()
            .unwrap_or(UNCLASSIFIED_SPEC)
    }

    /// Check the hard gates. `Some` means the action is refused, whatever the agent's record. A gate
    /// that can't tell (a write with no path, a URL it can't parse) refuses too.
    pub fn gate(&self, tool: &str, target: &str, capability: &str) -> Option<GateStop> {
        if self.gates.deny_capabilities.iter().any(|c| c == capability) {
            return Some(GateStop {
                gate: "denied_capability",
                reason: format!("no agent may use {capability}; a person has to do it"),
            });
        }
        if WRITE_TOOLS.contains(&tool) {
            let Some(rel) = self.relative(target) else {
                return Some(if target.is_empty() {
                    GateStop {
                        gate: "undecidable",
                        reason: "a write with no path".into(),
                    }
                } else {
                    GateStop {
                        gate: "outside_root",
                        reason: format!("{target} is outside the project"),
                    }
                });
            };
            if self
                .gates
                .protected_paths
                .iter()
                .any(|g| glob(g.as_bytes(), rel.as_bytes(), true))
            {
                return Some(GateStop {
                    gate: "protected_path",
                    reason: format!("{rel} is protected"),
                });
            }
        }
        if let Some(allowed) = &self.gates.allowed_hosts {
            let hosts = if URL_TOOLS.contains(&tool) {
                match url_host(target) {
                    Some(h) => vec![h],
                    None => {
                        return Some(GateStop {
                            gate: "undecidable",
                            reason: format!("can't tell which host {target} reaches"),
                        });
                    }
                }
            } else {
                // A command line: every URL in it must go to an allowed host.
                target.split_whitespace().filter_map(url_host).collect()
            };
            if let Some(h) = hosts.iter().find(|h| !host_allowed(h, allowed)) {
                return Some(GateStop {
                    gate: "unlisted_host",
                    reason: format!("{h} is not an allowed host"),
                });
            }
        }
        None
    }

    /// Classify an action by host tool and target. Path targets are resolved against the root.
    pub fn classify(&self, tool: &str, target: &str) -> Classified {
        let rel = self.relative(target);
        for r in &self.rules {
            if !r.tools.is_empty() && !r.tools.iter().any(|t| t == tool) {
                continue;
            }
            let hit = if r.paths.is_empty() {
                r.commands
                    .iter()
                    .any(|g| glob(g.as_bytes(), target.as_bytes(), false))
            } else {
                rel.as_deref().is_some_and(|p| {
                    r.paths
                        .iter()
                        .any(|g| glob(g.as_bytes(), p.as_bytes(), true))
                })
            };
            if hit && let Some(spec) = self.capabilities.get(&r.capability) {
                return Classified {
                    capability: r.capability.clone(),
                    spec: spec.clone(),
                };
            }
        }
        Classified {
            capability: UNCLASSIFIED.to_string(),
            spec: UNCLASSIFIED_SPEC,
        }
    }

    /// The target as a `/`-separated path inside the root, or `None` if it is outside it.
    fn relative(&self, target: &str) -> Option<String> {
        if target.is_empty() {
            return None;
        }
        let p = Path::new(target);
        let full = if p.is_absolute() {
            resolve(p)
        } else {
            resolve(&self.root.join(p))
        };
        let rel = full.strip_prefix(&self.root).ok()?;
        let parts: Vec<String> = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        Some(parts.join("/"))
    }
}

/// Resolve a path the way the file system will: `.` and `..` first, then symlinks through the deepest
/// part of it that exists. Without this, a symlink inside the root that points outside it (docs/link to
/// /etc) would be classified as inside, and the same directory reached by two paths (/var and
/// /private/var on macOS) would look like two places.
fn resolve(p: &Path) -> PathBuf {
    let lexical = normalize(p);
    let mut existing = lexical.clone();
    let mut rest = Vec::new();
    loop {
        if let Ok(real) = std::fs::canonicalize(&existing) {
            let mut out = real;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match existing.file_name() {
            Some(name) => rest.push(name.to_os_string()),
            None => return lexical,
        }
        if !existing.pop() {
            return lexical;
        }
    }
}

/// Resolve `.` and `..` without touching the file system, so a path can't climb out of the root.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The host of an http or https URL, lower-cased, without a port or credentials.
fn url_host(s: &str) -> Option<String> {
    let s = s.trim_matches(|c| c == '"' || c == '\'');
    let rest = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = if let Some(v6) = host.strip_prefix('[') {
        v6.split(']').next()?
    } else {
        host.split(':').next()?
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// An allowed entry matches the host itself, and `*.example.com` matches its subdomains.
fn host_allowed(host: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| {
        let a = a.to_ascii_lowercase();
        match a.strip_prefix("*.") {
            Some(base) => host.len() > base.len() + 1 && host.ends_with(&format!(".{base}")),
            None => host == a,
        }
    })
}

/// Glob match. In path mode `*` and `?` stop at `/` and `**` crosses it; in command mode `*` matches
/// anything.
fn glob(pat: &[u8], text: &[u8], path: bool) -> bool {
    match pat.first() {
        None => text.is_empty(),
        Some(b'*') if path && pat.get(1) == Some(&b'*') => {
            // `**/` also matches zero directories.
            let rest = if pat.get(2) == Some(&b'/') {
                &pat[3..]
            } else {
                &pat[2..]
            };
            (0..=text.len()).any(|i| glob(rest, &text[i..], path))
                || (pat.get(2) == Some(&b'/') && glob(&pat[2..], text, path))
        }
        Some(b'*') => {
            let rest = &pat[1..];
            for i in 0..=text.len() {
                if glob(rest, &text[i..], path) {
                    return true;
                }
                if path && text.get(i) == Some(&b'/') {
                    return false;
                }
            }
            false
        }
        Some(b'?') => match text.first() {
            Some(c) if !(path && *c == b'/') => glob(&pat[1..], &text[1..], path),
            _ => false,
        },
        Some(c) => text.first() == Some(c) && glob(&pat[1..], &text[1..], path),
    }
}

/// The default policy, also a worked example of the format.
pub const BUILTIN: &str = r#"{
  "version": 1,
  "capabilities": {
    "fs.read":            { "risk": "none",   "reversible": true,  "ceiling": 2 },
    "fs.edit.docs":       { "risk": "low",    "reversible": true,  "ceiling": 2 },
    "fs.edit.tests":      { "risk": "medium", "reversible": true,  "ceiling": 2 },
    "fs.edit.code":       { "risk": "medium", "reversible": true,  "ceiling": 2 },
    "fs.edit.config":     { "risk": "high",   "reversible": true,  "ceiling": 1 },
    "shell.run.readonly": { "risk": "low",    "reversible": true,  "ceiling": 2 },
    "shell.run":          { "risk": "high",   "reversible": false, "ceiling": 1 },
    "git.push.branch":    { "risk": "medium", "reversible": true,  "ceiling": 2 },
    "git.push.main":      { "risk": "high",   "reversible": false, "ceiling": 1 },
    "net.fetch":          { "risk": "low",    "reversible": true,  "ceiling": 2 }
  },
  "rules": [
    { "tools": ["Read", "Glob", "Grep", "LS", "NotebookRead"], "paths": ["**"], "capability": "fs.read" },
    { "tools": ["Edit", "MultiEdit", "Write", "NotebookEdit"], "paths": [".mohar/**", ".claude/**", ".github/**", "**/.env*"], "capability": "fs.edit.config" },
    { "tools": ["Edit", "MultiEdit", "Write", "NotebookEdit"], "paths": ["docs/**", "**/*.md"], "capability": "fs.edit.docs" },
    { "tools": ["Edit", "MultiEdit", "Write", "NotebookEdit"], "paths": ["tests/**", "**/tests/**", "**/*_test.*", "**/*.test.*", "**/test_*"], "capability": "fs.edit.tests" },
    { "tools": ["Edit", "MultiEdit", "Write", "NotebookEdit"], "paths": ["**"], "capability": "fs.edit.code" },
    { "tools": ["Bash"], "commands": ["git push * main", "git push * main *", "git push * master", "git push * master *"], "capability": "git.push.main" },
    { "tools": ["Bash"], "commands": ["git push*"], "capability": "git.push.branch" },
    { "tools": ["Bash"], "commands": ["ls", "ls *", "pwd", "git status*", "git diff*", "git log*", "cat *", "cargo test*", "npm test*", "pytest*"], "capability": "shell.run.readonly" },
    { "tools": ["Bash"], "commands": ["*"], "capability": "shell.run" },
    { "tools": ["WebFetch", "WebSearch"], "commands": ["*"], "capability": "net.fetch" }
  ],
  "gates": {
    "deny_capabilities": ["git.push.main"],
    "protected_paths": [".mohar/**"]
  }
}"#;

#[cfg(test)]
mod tests {
    use super::glob;

    #[test]
    fn globs() {
        let p = |g: &str, t: &str| glob(g.as_bytes(), t.as_bytes(), true);
        assert!(p("docs/**", "docs/a/b.md"));
        assert!(p("**/*.md", "README.md"), "**/ matches zero directories");
        assert!(p("**/*.md", "a/b/c.md"));
        assert!(!p("*.md", "a/b.md"), "* stops at /");
        assert!(p("src/?.rs", "src/a.rs"));
        assert!(!p("src/?.rs", "src/ab.rs"));
        assert!(!p("docs/**", "docsx/a.md"));
        let c = |g: &str, t: &str| glob(g.as_bytes(), t.as_bytes(), false);
        assert!(
            c("git push*", "git push origin feat/x"),
            "* crosses / in commands"
        );
        assert!(c("git push * main", "git push origin main"));
        assert!(!c("git push * main", "git push origin main-2"));
    }
}
