//! Escalation routing: who decides an action that is outside what an agent has earned. The person who
//! delegated to the agent if they hold the capability, then the first one up their reporting tree who
//! does, then the project's owners. And every way a `people` section is refused.
#![allow(clippy::expect_used)]

use std::path::Path;

use mohar_core::policy::{Policy, PolicyError, Route};

fn with_people(people: &str) -> Result<Policy, PolicyError> {
    Policy::from_json(
        &format!(
            r#"{{"version": 1,
                "capabilities": {{
                  "fs.edit.docs": {{"risk": "low", "reversible": true, "ceiling": 2}},
                  "fs.edit.code": {{"risk": "medium", "reversible": true, "ceiling": 2}},
                  "db.migrate":   {{"risk": "high", "reversible": false, "ceiling": 1}}
                }},
                "rules": [{{"tools": ["Edit"], "paths": ["**"], "capability": "fs.edit.code"}}],
                "people": {people}}}"#
        ),
        Path::new("/repo"),
    )
}

/// A dev who holds docs edits, reporting to a lead who holds every edit, reporting to a director who
/// holds nothing listed; one owner. The docs agents were handed authority by the dev, the ops agent by
/// the lead, and nobody delegated to anything else.
const TEAM: &str = r#"{
  "owners": ["user:owner-1"],
  "members": {
    "user:dev-1":  {"holds": ["fs.edit.docs"], "reports_to": "user:lead-1"},
    "user:lead-1": {"holds": ["fs.edit.*"], "reports_to": "user:dir-1"},
    "user:dir-1":  {}
  },
  "delegations": [
    {"agent": "agent:claude-code/docs-*", "from": "user:dev-1"},
    {"agent": "agent:ops/*", "from": "user:lead-1"}
  ]
}"#;

fn route(agent: &str, capability: &str) -> Route {
    with_people(TEAM)
        .expect("valid")
        .route(agent, capability)
        .expect("people are configured")
}

#[test]
fn the_delegator_decides_when_they_hold_the_capability() {
    let r = route("agent:claude-code/docs-writer", "fs.edit.docs");
    assert_eq!(r.to, ["user:dev-1"]);
    assert_eq!(r.via, "delegator");
}

#[test]
fn otherwise_the_first_person_up_the_reporting_tree_who_holds_it() {
    let r = route("agent:claude-code/docs-writer", "fs.edit.code");
    assert_eq!(r.to, ["user:lead-1"], "the dev doesn't hold code edits");
    assert_eq!(r.via, "reporting_tree");
    let r = route("agent:ops/deploy", "fs.edit.code");
    assert_eq!(
        (r.to, r.via),
        (vec!["user:lead-1".to_string()], "delegator"),
        "the lead delegated to this one and holds it"
    );
}

#[test]
fn otherwise_the_owners() {
    for (agent, capability) in [
        // Nobody up the tree holds it: the dev, the lead and the director are all passed over.
        ("agent:claude-code/docs-writer", "db.migrate"),
        // Nobody delegated to this agent.
        ("agent:other/1", "fs.edit.docs"),
        // An action that matched no rule is held by no one.
        ("agent:ops/deploy", "unclassified"),
    ] {
        let r = route(agent, capability);
        assert_eq!(r.to, ["user:owner-1"], "{agent} {capability}");
        assert_eq!(r.via, "owners", "{agent} {capability}");
    }
}

#[test]
fn the_first_matching_delegation_wins() {
    let p = with_people(
        r#"{"owners": ["user:o"],
            "members": {"user:a": {"holds": ["*"]}, "user:b": {"holds": ["*"]}},
            "delegations": [{"agent": "agent:x/*", "from": "user:a"}, {"agent": "agent:*", "from": "user:b"}]}"#,
    )
    .expect("valid");
    assert_eq!(
        p.route("agent:x/1", "fs.edit.code").expect("route").to,
        ["user:a"]
    );
    assert_eq!(
        p.route("agent:y/1", "fs.edit.code").expect("route").to,
        ["user:b"]
    );
}

#[test]
fn without_a_people_section_there_is_no_route() {
    let p = Policy::builtin(Path::new("/repo"));
    assert_eq!(p.route("agent:x/1", "fs.edit.code"), None);
}

#[test]
fn invalid_people_sections_are_refused_with_a_reason() {
    let cases = [
        (r#"{"owners": []}"#, "no owners"),
        (r#"{}"#, "owners missing"),
        (
            r#"{"owners": ["user:o"], "members": {"user:a": {"reports_to": "user:nobody"}}}"#,
            "reports to someone unlisted",
        ),
        (
            r#"{"owners": ["user:o"], "delegations": [{"agent": "*", "from": "user:nobody"}]}"#,
            "delegation from someone unlisted",
        ),
        (
            r#"{"owners": ["user:o"], "members": {"user:a": {"reports_to": "user:b"}, "user:b": {"reports_to": "user:a"}}}"#,
            "a reporting cycle",
        ),
        (
            r#"{"owners": ["user:o"], "members": {"user:a": {"reports_to": "user:a"}}}"#,
            "reporting to oneself",
        ),
        (r#"{"owners": [""]}"#, "an empty id"),
        (
            r#"{"owners": ["user:o"], "members": {"user:a": {"holds": ["x"], "boss": "user:o"}}}"#,
            "an unknown field",
        ),
        (
            r#"{"owners": ["hmac-sha256:c41b77d0c41b77d0c41b77d0c41b77d0c41b77d0c41b77d0c41b77d0c41b77d0"]}"#,
            "a pseudonym in place of a person",
        ),
    ];
    for (people, why) in cases {
        assert!(with_people(people).is_err(), "accepted {why}: {people}");
    }
    let e = with_people(r#"{"owners": ["user:o"], "members": {"user:a": {"reports_to": "user:b"}, "user:b": {"reports_to": "user:a"}}}"#)
        .expect_err("cycle");
    assert!(e.to_string().contains("user:a"), "{e}");
}
