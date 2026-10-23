//! The capability policy: matching order, the unmatched default, paths outside the root, and every
//! way a policy file is refused.
#![allow(clippy::expect_used)]

use std::path::Path;

use mohar_core::policy::{Policy, PolicyError, Risk, UNCLASSIFIED};

const ROOT: &str = "/repo";

fn policy(rules: &str) -> Result<Policy, PolicyError> {
    Policy::from_json(
        &format!(
            r#"{{"version": 1,
                "capabilities": {{
                  "fs.edit.docs": {{"risk": "low", "reversible": true, "ceiling": 2}},
                  "fs.edit.code": {{"risk": "medium", "reversible": true, "ceiling": 2}},
                  "db.migrate":   {{"risk": "high", "reversible": false, "ceiling": 1}}
                }},
                "rules": [{rules}]}}"#
        ),
        Path::new(ROOT),
    )
}

#[test]
fn the_first_matching_rule_wins() {
    let p = policy(
        r#"{"tools": ["Edit"], "paths": ["docs/**"], "capability": "fs.edit.docs"},
           {"tools": ["Edit"], "paths": ["**"], "capability": "fs.edit.code"}"#,
    )
    .expect("valid");
    assert_eq!(
        p.classify("Edit", "/repo/docs/a.md").capability,
        "fs.edit.docs"
    );
    assert_eq!(
        p.classify("Edit", "docs/a.md").capability,
        "fs.edit.docs",
        "relative to the root"
    );
    assert_eq!(
        p.classify("Edit", "/repo/src/a.rs").capability,
        "fs.edit.code"
    );
    // Reversed, the broad rule shadows the narrow one: order is the author's decision.
    let r = policy(
        r#"{"tools": ["Edit"], "paths": ["**"], "capability": "fs.edit.code"},
           {"tools": ["Edit"], "paths": ["docs/**"], "capability": "fs.edit.docs"}"#,
    )
    .expect("valid");
    assert_eq!(
        r.classify("Edit", "/repo/docs/a.md").capability,
        "fs.edit.code"
    );
}

#[test]
fn an_action_that_matches_nothing_is_the_highest_risk() {
    let p = policy(r#"{"tools": ["Edit"], "paths": ["docs/**"], "capability": "fs.edit.docs"}"#)
        .expect("valid");
    for (tool, target) in [
        ("Write", "/repo/docs/a.md"),
        ("Edit", "/repo/src/a.rs"),
        ("Bash", "rm -rf /"),
    ] {
        let c = p.classify(tool, target);
        assert_eq!(c.capability, UNCLASSIFIED, "{tool} {target}");
        assert_eq!(
            (c.spec.risk, c.spec.reversible, c.spec.ceiling),
            (Risk::High, false, 0)
        );
    }
}

#[test]
fn paths_outside_the_root_are_never_classified_by_path_rules() {
    let p = policy(r#"{"tools": ["Edit"], "paths": ["**"], "capability": "fs.edit.code"}"#)
        .expect("valid");
    assert_eq!(p.classify("Edit", "/etc/passwd").capability, UNCLASSIFIED);
    assert_eq!(
        p.classify("Edit", "/repo/../etc/passwd").capability,
        UNCLASSIFIED,
        ".. can't climb out"
    );
    assert_eq!(
        p.classify("Edit", "src/../../outside.rs").capability,
        UNCLASSIFIED
    );
    assert_eq!(
        p.classify("Edit", "/repository/a.rs").capability,
        UNCLASSIFIED,
        "a sibling with the same prefix"
    );
    assert_eq!(p.classify("Edit", "").capability, UNCLASSIFIED);
}

#[test]
fn commands_are_matched_as_whole_command_lines() {
    let p = policy(r#"{"tools": ["Bash"], "commands": ["*migrate*"], "capability": "db.migrate"}"#)
        .expect("valid");
    assert_eq!(
        p.classify("Bash", "npm run migrate -- --env=prod")
            .capability,
        "db.migrate"
    );
    assert_eq!(p.classify("Bash", "ls").capability, UNCLASSIFIED);
    assert_eq!(
        p.classify("Edit", "migrate.sql").capability,
        UNCLASSIFIED,
        "rules apply only to their tools"
    );
}

#[test]
fn invalid_files_are_refused_with_a_reason() {
    assert!(matches!(
        Policy::from_json("{", Path::new(ROOT)),
        Err(PolicyError::Parse(_))
    ));
    assert!(matches!(
        Policy::from_json(
            r#"{"version": 2, "capabilities": {}, "rules": []}"#,
            Path::new(ROOT)
        ),
        Err(PolicyError::Version(2))
    ));
    assert_eq!(
        policy(r#"{"tools": ["Edit"], "paths": ["**"], "capability": "fs.nope"}"#).err(),
        Some(PolicyError::UnknownCapability {
            index: 0,
            name: "fs.nope".into()
        })
    );
    assert_eq!(
        policy(r#"{"tools": ["Edit"], "capability": "fs.edit.code"}"#).err(),
        Some(PolicyError::EmptyRule { index: 0 })
    );
    assert_eq!(
        policy(r#"{"tools": ["Edit"], "paths": ["**"], "commands": ["*"], "capability": "fs.edit.code"}"#).err(),
        Some(PolicyError::MixedRule { index: 0 })
    );
    assert!(
        matches!(
            policy(
                r#"{"tools": ["Edit"], "paths": ["**"], "capability": "fs.edit.code", "allow": true}"#
            ),
            Err(PolicyError::Parse(_))
        ),
        "unknown fields are refused, not ignored"
    );
    let cap = |c: &str| {
        Policy::from_json(
            &format!(r#"{{"version": 1, "capabilities": {{{c}}}, "rules": []}}"#),
            Path::new(ROOT),
        )
        .err()
    };
    assert_eq!(
        cap(r#""x": {"risk": "low", "reversible": true, "ceiling": 3}"#),
        Some(PolicyError::Ceiling {
            name: "x".into(),
            ceiling: 3
        })
    );
    assert_eq!(
        cap(r#""x": {"risk": "high", "reversible": false, "ceiling": 2}"#),
        Some(PolicyError::IrreversibleCeiling { name: "x".into() })
    );
    assert_eq!(
        cap(r#""unclassified": {"risk": "low", "reversible": true, "ceiling": 0}"#),
        Some(PolicyError::Reserved)
    );
    assert!(matches!(
        cap(r#""x": {"risk": "extreme", "reversible": true, "ceiling": 0}"#),
        Some(PolicyError::Parse(_))
    ));
}

#[test]
fn the_builtin_policy_is_valid_and_sensible() {
    let p = Policy::builtin(Path::new(ROOT));
    let c = |tool: &str, target: &str| p.classify(tool, target).capability;
    assert_eq!(c("Read", "/repo/src/main.rs"), "fs.read");
    assert_eq!(
        c("Read", "/home/u/.ssh/id_ed25519"),
        UNCLASSIFIED,
        "reads outside the project aren't free"
    );
    assert_eq!(c("Edit", "/repo/docs/design.md"), "fs.edit.docs");
    assert_eq!(c("Edit", "/repo/crates/x/tests/a.rs"), "fs.edit.tests");
    assert_eq!(c("Edit", "/repo/src/lib.rs"), "fs.edit.code");
    assert_eq!(
        c("Edit", "/repo/.mohar/policy.json"),
        "fs.edit.config",
        "the policy itself is config"
    );
    assert_eq!(c("Write", "/repo/.claude/settings.json"), "fs.edit.config");
    assert_eq!(c("Edit", "/repo/.env.local"), "fs.edit.config");
    assert_eq!(c("Bash", "git push origin main"), "git.push.main");
    assert_eq!(c("Bash", "git push origin main --force"), "git.push.main");
    assert_eq!(c("Bash", "git push origin feat/x"), "git.push.branch");
    assert_eq!(c("Bash", "git status"), "shell.run.readonly");
    assert_eq!(c("Bash", "curl -X POST https://x"), "shell.run");
    assert_eq!(c("WebFetch", "https://example.com"), "net.fetch");
    assert_eq!(c("mcp__github__create_issue", "x"), UNCLASSIFIED);
}
