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
    #[serde(default)]
    verify: Verify,
    /// Named groups of capabilities that touch the same paths, hosts or database. A serious failure on
    /// one member drops the others with it.
    #[serde(default)]
    scopes: BTreeMap<String, Vec<String>>,
    /// Who decides an action that is outside what an agent has earned.
    #[serde(default)]
    people: Option<People>,
}

/// The people an escalation can go to: who holds which capabilities, who reports to whom, who handed
/// authority to which agents, and the owners who answer when nobody else does.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct People {
    owners: Vec<String>,
    #[serde(default)]
    members: BTreeMap<String, Member>,
    /// Matched against the agent id in order; the first match wins.
    #[serde(default)]
    delegations: Vec<Delegation>,
    /// How long each level has to answer before the question moves up. Absent means it never moves.
    #[serde(default)]
    escalation_timeout_secs: Option<u64>,
    /// A SCIM 2.0 user export from the identity provider, relative to the project root. Members'
    /// reporting lines are read from its enterprise `manager` links.
    #[serde(default)]
    directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    /// Capability names or globs (`fs.edit.*`, `*`) this person may approve.
    #[serde(default)]
    holds: Vec<String>,
    #[serde(default)]
    reports_to: Option<String>,
    /// Capabilities this person lets their answers be predicted on, with the limits they set.
    #[serde(default)]
    predict: BTreeMap<String, crate::predict::Limits>,
    /// The most new requests this person may be asked in an hour. Absent means no limit.
    #[serde(default)]
    escalations_per_hour: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Delegation {
    /// Glob over the agent id; `*` matches anything.
    agent: String,
    /// The person who handed this agent its authority.
    from: String,
}

/// Who an escalated action goes to, and which step of the routing picked them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The people any one of whom may answer: the one person picked, or every owner.
    pub to: Vec<String>,
    /// `delegator`, `reporting_tree` or `owners`.
    pub via: &'static str,
}

/// How work is verified.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verify {
    /// The tests verifier.
    #[serde(default)]
    pub tests: Option<TestsVerifier>,
}

/// The project's test command, run from the root after a task.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestsVerifier {
    /// Program and arguments, run directly with no shell.
    pub command: Vec<String>,
    /// How long the run may take before the result is `unknown`.
    #[serde(default = "default_test_timeout")]
    pub timeout_secs: u64,
    /// Globs (relative to the root) for test files. An agent that changes one of these in a task
    /// fails verification for that task, whatever the tests say.
    #[serde(default)]
    pub test_paths: Vec<String>,
}

fn default_test_timeout() -> u64 {
    600
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
    /// Capabilities whose escalations need two different people to approve.
    #[serde(default)]
    pub two_person: Vec<String>,
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
/// Tools whose target is a shell command line, split into its commands before classifying.
const SHELL_TOOLS: [&str; 1] = ["Bash"];
/// Redirection targets that are not files in the project, so writing them changes nothing.
const DEVICES: [&str; 3] = ["/dev/null", "/dev/stdout", "/dev/stderr"];
/// Programs that reach other hosts. A variable near one of them hides which host.
const NETWORK_PROGRAMS: [&str; 14] = [
    "curl", "wget", "http", "https", "nc", "ncat", "netcat", "ssh", "scp", "sftp", "rsync", "ftp",
    "telnet", "git",
];

/// A loaded, validated policy.
#[derive(Debug, Clone)]
pub struct Policy {
    root: PathBuf,
    capabilities: BTreeMap<String, Capability>,
    rules: Vec<Rule>,
    gates: Gates,
    verify: Verify,
    scopes: BTreeMap<String, Vec<String>>,
    people: Option<People>,
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
    /// A test command with no program in it.
    #[error("verify.tests.command is empty; give the program and its arguments")]
    EmptyTestCommand,
    /// A gate names a capability that isn't defined.
    #[error("gates names {name:?}, which is not defined under capabilities")]
    UnknownGateCapability {
        /// The name.
        name: String,
    },
    /// A scope names a capability that isn't defined.
    #[error("scope {scope:?} names {name:?}, which is not defined under capabilities")]
    UnknownScopeCapability {
        /// The scope.
        scope: String,
        /// The name.
        name: String,
    },
    /// The reserved name used for actions that match nothing.
    #[error("capability name \"unclassified\" is reserved")]
    Reserved,
    /// A `people` section with nobody to fall back on.
    #[error("people.owners is empty; an escalation nobody else holds goes to the owners")]
    NoOwners,
    /// A person id that is empty, or has the form of a strict-privacy pseudonym.
    #[error(
        "people names {0:?}, which is empty or has the form of a pseudonym; use the person's own id"
    )]
    BadPersonId(String),
    /// A reporting line or delegation names someone not listed under `people.members`.
    #[error("{field} names {name:?}, who is not listed under people.members")]
    UnknownPerson {
        /// Where the name appears.
        field: String,
        /// The name.
        name: String,
    },
    /// An hourly budget of 0, which would hold everything meant for that person.
    #[error("people.members.{0}.escalations_per_hour is 0; give a number above 0, or leave it out")]
    BadBudget(String),
    /// A timeout of 0, which would move every question the moment it was asked again.
    #[error("people.escalation_timeout_secs is 0; give a number above 0, or leave it out")]
    BadTimeout,
    /// A capability a person asked to have predicted that can never be.
    #[error("people.members.{person}.predict names {name:?}, {why}")]
    BadPrediction {
        /// The person.
        person: String,
        /// The capability.
        name: String,
        /// Why it can't be predicted.
        why: &'static str,
    },
    /// The identity provider export named by `people.directory` can't be read or doesn't settle who
    /// reports to whom.
    #[error("people.directory {file}: {why}")]
    Directory {
        /// The export file.
        file: String,
        /// What is wrong with it.
        why: String,
    },
    /// Following `reports_to` from this person comes back to them.
    #[error("people.members: the reporting line from {0:?} goes round in a circle")]
    ReportingCycle(String),
}

impl Policy {
    /// Parse and validate a policy file. `base` is the directory relative roots resolve against.
    pub fn from_json(text: &str, base: &Path) -> Result<Self, PolicyError> {
        let mut file: File =
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
        if file
            .verify
            .tests
            .as_ref()
            .is_some_and(|t| t.command.is_empty())
        {
            return Err(PolicyError::EmptyTestCommand);
        }
        for name in file
            .gates
            .deny_capabilities
            .iter()
            .chain(&file.gates.two_person)
        {
            if !file.capabilities.contains_key(name) {
                return Err(PolicyError::UnknownGateCapability { name: name.clone() });
            }
        }
        for (scope, names) in &file.scopes {
            if let Some(name) = names.iter().find(|n| !file.capabilities.contains_key(*n)) {
                return Err(PolicyError::UnknownScopeCapability {
                    scope: scope.clone(),
                    name: name.clone(),
                });
            }
        }
        if let Some(p) = &mut file.people
            && let Some(dir) = p.directory.clone()
        {
            let path = if dir.is_absolute() {
                dir
            } else {
                base.join(dir)
            };
            apply_directory(p, &path).map_err(|why| PolicyError::Directory {
                file: path.display().to_string(),
                why,
            })?;
        }
        if let Some(p) = &file.people {
            check_people(p)?;
            check_predictions(p, &file.capabilities, &file.gates)?;
        }
        Ok(Self {
            root: resolve(&root),
            capabilities: file.capabilities,
            rules: file.rules,
            gates: file.gates,
            verify: file.verify,
            scopes: file.scopes,
            people: file.people,
        })
    }

    /// The policy used when a project has none: reads run, edits and commands are classified by
    /// kind, and everything else is unclassified.
    pub fn builtin(root: &Path) -> Self {
        // A fixed, valid document; a failure here is a bug caught by the tests.
        Self::from_json(BUILTIN, root).unwrap_or_else(|e| unreachable!("built-in policy: {e}"))
    }

    /// The project root every relative path is resolved against.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The capabilities that share a scope with `capability`, sorted, without itself. An S3 failure on
    /// `capability` drops all of them.
    pub fn related(&self, capability: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .scopes
            .values()
            .filter(|names| names.iter().any(|n| n == capability))
            .flatten()
            .filter(|n| *n != capability)
            .cloned()
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// How many different people must approve an escalation on this capability: 2 for the ones listed
    /// under `gates.two_person`, otherwise 1.
    pub fn approvals_needed(&self, capability: &str) -> usize {
        if self.gates.two_person.iter().any(|c| c == capability) {
            2
        } else {
            1
        }
    }

    /// The person who handed this agent its authority, by the first matching delegation.
    pub fn sponsor(&self, agent: &str) -> Option<&str> {
        self.people
            .as_ref()?
            .delegations
            .iter()
            .find(|d| glob(d.agent.as_bytes(), agent.as_bytes(), false))
            .map(|d| d.from.as_str())
    }

    /// Who decides an escalated action, or `None` when the policy names no people, in which case the
    /// host's own prompt does. The person who delegated to the agent if they hold the capability, else
    /// the first one up their reporting tree who does, else every owner.
    pub fn route(&self, agent: &str, capability: &str) -> Option<Route> {
        let mut r = self.route_one(agent, capability)?;
        // A capability that needs two people also goes to the owners, so there are two to ask.
        if self.approvals_needed(capability) > 1
            && let Some(p) = &self.people
        {
            for o in &p.owners {
                if !r.to.contains(o) {
                    r.to.push(o.clone());
                }
            }
        }
        Some(r)
    }

    fn route_one(&self, agent: &str, capability: &str) -> Option<Route> {
        let people = self.people.as_ref()?;
        let mut next = self.sponsor(agent);
        let mut via = "delegator";
        // Loading refused cycles and unlisted names, so this walk ends; the bound only makes that
        // visible here.
        for _ in 0..=people.members.len() {
            let Some((id, m)) = next.and_then(|id| people.members.get_key_value(id)) else {
                break;
            };
            if m.holds
                .iter()
                .any(|h| glob(h.as_bytes(), capability.as_bytes(), false))
            {
                return Some(Route {
                    to: vec![id.clone()],
                    via,
                });
            }
            via = "reporting_tree";
            next = m.reports_to.as_deref();
        }
        Some(Route {
            to: people.owners.clone(),
            via: "owners",
        })
    }

    /// How long each level has to answer before a question moves up, if the policy sets it.
    pub fn escalation_timeout(&self) -> Option<u64> {
        self.people.as_ref()?.escalation_timeout_secs
    }

    /// Who a question goes to as each level times out: everyone up the chain from the first person
    /// who holds the capability, then the owners not already on it. The first level is what
    /// [`Policy::route`] answers. A capability needing two people has that one level, since it already
    /// went to the owners.
    pub fn escalation_levels(&self, agent: &str, capability: &str) -> Vec<Route> {
        let Some(first) = self.route(agent, capability) else {
            return Vec::new();
        };
        let Some(people) = self.people.as_ref() else {
            return vec![first];
        };
        if self.approvals_needed(capability) > 1 || first.via == "owners" {
            return vec![first];
        }
        let mut levels = vec![first];
        let mut next = levels[0]
            .to
            .first()
            .and_then(|id| people.members.get(id))
            .and_then(|m| m.reports_to.as_deref());
        // Loading refused cycles and unlisted names, so this walk ends; the bound only makes that
        // visible here.
        for _ in 0..=people.members.len() {
            let Some((id, m)) = next.and_then(|id| people.members.get_key_value(id)) else {
                break;
            };
            if m.holds
                .iter()
                .any(|h| glob(h.as_bytes(), capability.as_bytes(), false))
            {
                levels.push(Route {
                    to: vec![id.clone()],
                    via: "reporting_tree",
                });
            }
            next = m.reports_to.as_deref();
        }
        let owners: Vec<String> = people
            .owners
            .iter()
            .filter(|o| !levels.iter().any(|l| l.to.contains(o)))
            .cloned()
            .collect();
        if !owners.is_empty() {
            levels.push(Route {
                to: owners,
                via: "owners",
            });
        }
        levels
    }

    /// The capabilities `person` lets their answers be predicted on, with their limits. Empty for anyone
    /// not listed under `people.members`.
    pub fn predict_limits(&self, person: &str) -> BTreeMap<String, crate::predict::Limits> {
        self.people
            .as_ref()
            .and_then(|p| p.members.get(person))
            .map(|m| m.predict.clone())
            .unwrap_or_default()
    }

    /// How many new requests `person` may be asked in an hour; `None` when they set no limit or aren't
    /// listed under `people.members`.
    pub fn escalation_budget(&self, person: &str) -> Option<u32> {
        self.people
            .as_ref()?
            .members
            .get(person)?
            .escalations_per_hour
    }

    /// Everyone with an hourly budget and what it is, by id.
    pub fn escalation_budgets(&self) -> Vec<(&str, u32)> {
        self.people
            .iter()
            .flat_map(|p| &p.members)
            .filter_map(|(id, m)| Some((id.as_str(), m.escalations_per_hour?)))
            .collect()
    }

    /// A target as a path relative to the root, with `.` and `..` resolved, or `None` when it is
    /// empty or outside the root.
    pub fn relative_path(&self, target: &str) -> Option<String> {
        self.relative(target)
    }

    /// The tests verifier, if the project configured one.
    pub fn tests_verifier(&self) -> Option<&TestsVerifier> {
        self.verify.tests.as_ref()
    }

    /// Whether a target is one of the project's test files.
    pub fn is_test_path(&self, target: &str) -> bool {
        let Some(t) = &self.verify.tests else {
            return false;
        };
        self.relative(target).is_some_and(|rel| {
            t.test_paths
                .iter()
                .any(|g| glob(g.as_bytes(), rel.as_bytes(), true))
        })
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
        if SHELL_TOOLS.contains(&tool) {
            let parts = match crate::shell::split(target) {
                Ok(parts) => parts,
                Err(why) => {
                    return Some(GateStop {
                        gate: "undecidable",
                        reason: format!("can't tell what this command runs: {why}"),
                    });
                }
            };
            // A denied capability anywhere in the line stops it, whichever part decides the class.
            for p in &parts {
                let c = self.classify_one(tool, &p.text()).capability;
                if self.gates.deny_capabilities.contains(&c) {
                    return Some(GateStop {
                        gate: "denied_capability",
                        reason: format!("no agent may use {c}; a person has to do it"),
                    });
                }
            }
            // A redirection is a write to its target, held to the same gates as an edit.
            for w in parts.iter().flat_map(|p| p.writes.iter()) {
                let Some(path) = w else {
                    return Some(GateStop {
                        gate: "undecidable",
                        reason: "can't tell which file this command writes".into(),
                    });
                };
                if DEVICES.contains(&path.as_str()) {
                    continue;
                }
                if let Some(stop) =
                    self.gate("Write", path, &self.classify_one("Write", path).capability)
                {
                    return Some(stop);
                }
            }
            if self.gates.allowed_hosts.is_some()
                && let Some(p) = parts.iter().find(|p| {
                    p.expands
                        && p.words.iter().any(|w| {
                            w.contains("://")
                                || NETWORK_PROGRAMS.contains(&w.rsplit('/').next().unwrap_or(""))
                        })
                })
            {
                return Some(GateStop {
                    gate: "undecidable",
                    reason: format!("can't tell which host `{}` reaches", p.text()),
                });
            }
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
                // A command line: every URL in it must go to an allowed host. Shell lines were
                // checked above to be readable, so their words are what the shell would see.
                match crate::shell::split(target) {
                    Ok(parts) => parts
                        .iter()
                        .flat_map(|p| p.words.iter())
                        .filter_map(|w| url_host(w))
                        .collect(),
                    Err(_) => target.split_whitespace().filter_map(url_host).collect(),
                }
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

    /// Classify an action by host tool and target. Path targets are resolved against the root. A
    /// shell command line is split into its commands and the riskiest one decides; a line that can't
    /// be read is unclassified, the highest risk.
    pub fn classify(&self, tool: &str, target: &str) -> Classified {
        if !SHELL_TOOLS.contains(&tool) {
            return self.classify_one(tool, target);
        }
        let parts = match crate::shell::split(target) {
            Ok(parts) if !parts.is_empty() => parts,
            Ok(_) => return self.classify_one(tool, target),
            Err(_) => {
                return Classified {
                    capability: UNCLASSIFIED.to_string(),
                    spec: UNCLASSIFIED_SPEC,
                };
            }
        };
        // Riskier first; between equally risky parts, the one an earlier (more specific) rule named.
        let rank = |(c, rule): &(Classified, usize)| {
            (
                c.spec.risk,
                !c.spec.reversible,
                std::cmp::Reverse(c.spec.ceiling),
                std::cmp::Reverse(*rule),
            )
        };
        let mut worst: Option<(Classified, usize)> = None;
        for p in &parts {
            // A part that is only a redirection (`> file`) runs no command.
            let command = (!p.words.is_empty()).then(|| self.classify_ranked(tool, &p.text()));
            // Each file it writes counts as an edit of that file; a target only the shell knows is
            // unclassified.
            let written = p.writes.iter().filter_map(|w| match w {
                Some(path) if DEVICES.contains(&path.as_str()) => None,
                Some(path) => Some(self.classify_ranked("Write", path)),
                None => Some((
                    Classified {
                        capability: UNCLASSIFIED.to_string(),
                        spec: UNCLASSIFIED_SPEC,
                    },
                    usize::MAX,
                )),
            });
            for c in command.into_iter().chain(written) {
                if worst.as_ref().is_none_or(|w| rank(&c) > rank(w)) {
                    worst = Some(c);
                }
            }
        }
        worst.map_or(
            Classified {
                capability: UNCLASSIFIED.to_string(),
                spec: UNCLASSIFIED_SPEC,
            },
            |(c, _)| c,
        )
    }

    /// Classify one target against the rules, in order.
    fn classify_one(&self, tool: &str, target: &str) -> Classified {
        self.classify_ranked(tool, target).0
    }

    /// [`classify_one`](Self::classify_one), with the index of the rule that matched (`usize::MAX`
    /// when none did).
    fn classify_ranked(&self, tool: &str, target: &str) -> (Classified, usize) {
        let rel = self.relative(target);
        for (index, r) in self.rules.iter().enumerate() {
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
                return (
                    Classified {
                        capability: r.capability.clone(),
                        spec: spec.clone(),
                    },
                    index,
                );
            }
        }
        (
            Classified {
                capability: UNCLASSIFIED.to_string(),
                spec: UNCLASSIFIED_SPEC,
            },
            usize::MAX,
        )
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
        // Nothing left to strip (an empty or root path that doesn't resolve): keep the lexical form.
        let Some(name) = existing.file_name() else {
            return lexical;
        };
        rest.push(name.to_os_string());
        existing.pop();
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
            // Only a leading `.` survives `components()`; dropping it keeps the path as written.
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

/// The one field of `obj` named `name` without regard to case, as SCIM matches attribute names. Two
/// spellings of one name can't be told apart, so they are refused.
fn scim_field<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<Option<&'a serde_json::Value>, String> {
    let mut found = obj.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name));
    let first = found.next().map(|(_, v)| v);
    if found.next().is_some() {
        return Err(format!("{name:?} appears twice with different case"));
    }
    Ok(first)
}

/// A string field that is absent, null, or a non-empty string; anything else is refused.
fn scim_text(
    obj: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<Option<String>, String> {
    match scim_field(obj, name)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) if !s.is_empty() => Ok(Some(s.clone())),
        Some(_) => Err(format!("{name} is not a non-empty string")),
    }
}

/// One user from the export: their userName, whether they are active, and their manager's SCIM id.
struct ScimUser {
    name: String,
    active: bool,
    manager: Option<String>,
}

/// One entry of the export's Resources list.
fn scim_user(u: &serde_json::Value) -> Result<(String, ScimUser), String> {
    use serde_json::Value;
    let u = u.as_object().ok_or("not an object")?;
    let id = scim_text(u, "id")?.ok_or("no id")?;
    let name = scim_text(u, "userName")?.ok_or("no userName")?;
    let active = match scim_field(u, "active")? {
        // RFC 7643 leaves a missing `active` to the provider; exports that omit it list live users.
        None => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err("active is not true or false".into()),
    };
    let ext = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    let manager = match scim_field(u, ext)? {
        None | Some(Value::Null) => None,
        Some(Value::Object(e)) => match scim_field(e, "manager")? {
            None | Some(Value::Null) => None,
            Some(Value::Object(m)) => scim_text(m, "value")?,
            Some(_) => return Err("manager is not an object".into()),
        },
        Some(_) => return Err("the enterprise extension is not an object".into()),
    };
    Ok((
        id,
        ScimUser {
            name,
            active,
            manager,
        },
    ))
}

/// Reads a SCIM 2.0 ListResponse of users and gives each listed member the nearest listed, active
/// person up their manager chain as `reports_to`. Unlisted managers are passed over, inactive or not. A
/// member the export doesn't name keeps the policy's line. Anything the export leaves open is an error:
/// a manager it doesn't contain, a repeated id or userName, a loop, an inactive member, or a line in
/// the policy that disagrees with it.
fn apply_directory(p: &mut People, path: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let doc: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let obj = doc.as_object().ok_or("not a JSON object")?;
    let list = scim_field(obj, "Resources")?
        .and_then(serde_json::Value::as_array)
        .ok_or("no Resources list")?;
    let mut by_id: BTreeMap<String, ScimUser> = BTreeMap::new();
    let mut names = std::collections::BTreeSet::new();
    for (i, u) in list.iter().enumerate() {
        let (id, user) = scim_user(u).map_err(|e| format!("Resources[{i}]: {e}"))?;
        if !names.insert(user.name.clone()) {
            return Err(format!("two users have userName {:?}", user.name));
        }
        if by_id.insert(id.clone(), user).is_some() {
            return Err(format!("two users have id {id:?}"));
        }
    }
    let by_name: BTreeMap<&str, &ScimUser> = by_id.values().map(|u| (u.name.as_str(), u)).collect();
    let listed: std::collections::BTreeSet<String> = p.members.keys().cloned().collect();
    for (member, entry) in p.members.iter_mut() {
        let Some(u) = by_name.get(member.as_str()) else {
            continue;
        };
        if !u.active {
            return Err(format!("{member:?} is inactive in the directory"));
        }
        let mut next = u.manager.as_deref();
        let mut found = None;
        // A chain longer than the export has visited someone twice.
        for _ in 0..=by_id.len() {
            let Some(id) = next else { break };
            let m = by_id
                .get(id)
                .ok_or_else(|| format!("{member:?} has manager id {id:?}, who is not in it"))?;
            // No activity check: a listed person who is inactive already stops the policy loading.
            if listed.contains(&m.name) {
                found = Some(m.name.clone());
                break;
            }
            next = m.manager.as_deref();
        }
        if found.is_none() && next.is_some() {
            return Err(format!(
                "the manager chain from {member:?} goes round in a circle"
            ));
        }
        match (&entry.reports_to, found) {
            (Some(a), Some(b)) if *a != b => {
                return Err(format!(
                    "the policy says {member:?} reports to {a:?}, the directory says {b:?}"
                ));
            }
            (None, Some(b)) => entry.reports_to = Some(b),
            _ => {}
        }
    }
    Ok(())
}

/// Every person named exists, nobody's id is empty or a pseudonym, and no reporting line loops.
fn check_people(p: &People) -> Result<(), PolicyError> {
    if p.owners.is_empty() {
        return Err(PolicyError::NoOwners);
    }
    let named = p
        .owners
        .iter()
        .chain(p.members.keys())
        .chain(p.members.values().filter_map(|m| m.reports_to.as_ref()))
        .chain(p.delegations.iter().map(|d| &d.from));
    for id in named {
        if id.is_empty() || crate::privacy::is_pseudonym(id) {
            return Err(PolicyError::BadPersonId(id.clone()));
        }
    }
    let unknown = |field: String, name: &str| {
        (!p.members.contains_key(name)).then(|| PolicyError::UnknownPerson {
            field,
            name: name.to_string(),
        })
    };
    if p.escalation_timeout_secs == Some(0) {
        return Err(PolicyError::BadTimeout);
    }
    for (id, m) in &p.members {
        if m.escalations_per_hour == Some(0) {
            return Err(PolicyError::BadBudget(id.clone()));
        }
        if let Some(e) = m
            .reports_to
            .as_deref()
            .and_then(|b| unknown(format!("people.members.{id}.reports_to"), b))
        {
            return Err(e);
        }
    }
    for (i, d) in p.delegations.iter().enumerate() {
        if let Some(e) = unknown(format!("people.delegations[{i}].from"), &d.from) {
            return Err(e);
        }
    }
    for start in p.members.keys() {
        let mut at = start;
        // A line longer than the list of members has visited someone twice.
        for _ in 0..=p.members.len() {
            match p.members.get(at).and_then(|m| m.reports_to.as_ref()) {
                Some(b) if b == start => return Err(PolicyError::ReportingCycle(start.clone())),
                Some(b) => at = b,
                None => break,
            }
        }
    }
    Ok(())
}

/// Every capability a person asked to have predicted is one the model may ever answer: defined, low
/// risk, reversible, needing one person, and held by them, with at least one path and one answer a day.
fn check_predictions(
    p: &People,
    capabilities: &BTreeMap<String, Capability>,
    gates: &Gates,
) -> Result<(), PolicyError> {
    for (person, m) in &p.members {
        for (name, l) in &m.predict {
            let held = m
                .holds
                .iter()
                .any(|h| glob(h.as_bytes(), name.as_bytes(), false));
            let why = match capabilities.get(name) {
                None => "which is not defined under capabilities",
                Some(c) if c.risk > Risk::Low || !c.reversible => {
                    "which is above low risk or can't be undone, so it is never predicted"
                }
                Some(_) if gates.two_person.contains(name) => {
                    "which needs two people, so it is never predicted"
                }
                Some(_) if !held => "which they don't hold, so nothing on it is routed to them",
                Some(_) if l.paths.is_empty() || l.per_day == 0 => {
                    "with no paths or a daily count of 0; give both, or leave it out"
                }
                Some(_) => continue,
            };
            return Err(PolicyError::BadPrediction {
                person: person.clone(),
                name: name.clone(),
                why,
            });
        }
    }
    Ok(())
}

/// Glob match. In path mode `*` and `?` stop at `/` and `**` crosses it; in command mode `*` matches
/// anything.
pub(crate) fn glob(pat: &[u8], text: &[u8], path: bool) -> bool {
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
    use super::{glob, resolve};

    #[test]
    fn a_relative_path_that_resolves_nowhere_keeps_its_lexical_form() {
        let p = std::path::Path::new("no-such-dir-mohar/a/../b.md");
        assert_eq!(
            resolve(p),
            std::path::PathBuf::from("no-such-dir-mohar/b.md")
        );
    }

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
