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
                  "db.migrate":   {{"risk": "high", "reversible": false, "ceiling": 1}},
                  "fs.rm.tmp":    {{"risk": "low", "reversible": false, "ceiling": 1}}
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

fn two_person(gates: &str) -> Result<Policy, PolicyError> {
    Policy::from_json(
        &format!(
            r#"{{"version": 1,
                "capabilities": {{
                  "fs.edit.code": {{"risk": "medium", "reversible": true, "ceiling": 2}},
                  "db.migrate":   {{"risk": "high", "reversible": false, "ceiling": 1}}
                }},
                "rules": [{{"tools": ["Edit"], "paths": ["**"], "capability": "fs.edit.code"}}],
                "gates": {gates},
                "people": {TEAM}}}"#
        ),
        Path::new("/repo"),
    )
}

#[test]
fn a_two_person_capability_needs_two_approvals_and_reaches_the_owners_too() {
    let p = two_person(r#"{"two_person": ["db.migrate"]}"#).expect("valid");
    assert_eq!(p.approvals_needed("db.migrate"), 2);
    assert_eq!(p.approvals_needed("fs.edit.code"), 1);
    // A two-person code edit goes to the lead, who holds it, and to the owner as the second person.
    let p = two_person(r#"{"two_person": ["fs.edit.code"]}"#).expect("valid");
    let r = p
        .route("agent:claude-code/docs-writer", "fs.edit.code")
        .expect("route");
    assert_eq!(r.to, ["user:lead-1", "user:owner-1"]);
    assert_eq!(r.via, "reporting_tree");
    assert!(
        two_person(r#"{"two_person": ["no.such"]}"#).is_err(),
        "an undefined capability is refused"
    );
}

#[test]
fn the_sponsor_is_the_person_who_delegated_to_the_agent() {
    let p = with_people(TEAM).expect("valid");
    assert_eq!(
        p.sponsor("agent:claude-code/docs-writer"),
        Some("user:dev-1")
    );
    assert_eq!(p.sponsor("agent:ops/deploy"), Some("user:lead-1"));
    assert_eq!(p.sponsor("agent:other/1"), None);
    assert_eq!(Policy::builtin(Path::new("/repo")).sponsor("agent:x"), None);
}

/// The team, with the dev's answers on docs edits predicted inside `docs/guide/`.
fn predicting(dev: &str) -> Result<Policy, PolicyError> {
    with_people(&format!(
        r#"{{"owners": ["user:owner-1"],
            "members": {{"user:dev-1": {{"holds": ["fs.edit.*", "db.migrate", "fs.rm.tmp"], "predict": {dev}}}}}}}"#
    ))
}

#[test]
fn a_person_s_prediction_limits_are_read_and_nobody_else_has_any() {
    let p = predicting(r#"{"fs.edit.docs": {"paths": ["docs/guide/**"], "per_day": 20}}"#)
        .expect("valid");
    let mine = p.predict_limits("user:dev-1");
    assert_eq!(mine.len(), 1);
    assert_eq!(mine["fs.edit.docs"].paths, ["docs/guide/**"]);
    assert_eq!(mine["fs.edit.docs"].per_day, 20);
    assert!(p.predict_limits("user:owner-1").is_empty());
    assert!(p.predict_limits("user:nobody").is_empty());
}

#[test]
fn a_capability_that_can_never_be_predicted_is_refused_by_name() {
    let docs = r#"{"paths": ["docs/**"], "per_day": 5}"#;
    for (predict, name, why) in [
        (
            format!(r#"{{"fs.edit.code": {docs}}}"#),
            "fs.edit.code",
            "above low risk",
        ),
        (
            format!(r#"{{"db.migrate": {docs}}}"#),
            "db.migrate",
            "above low risk",
        ),
        (
            format!(r#"{{"fs.rm.tmp": {docs}}}"#),
            "fs.rm.tmp",
            "can't be undone",
        ),
        (
            format!(r#"{{"fs.edit.nope": {docs}}}"#),
            "fs.edit.nope",
            "not defined",
        ),
        (
            r#"{"fs.edit.docs": {"paths": [], "per_day": 5}}"#.to_string(),
            "fs.edit.docs",
            "no paths",
        ),
        (
            r#"{"fs.edit.docs": {"paths": ["docs/**"], "per_day": 0}}"#.to_string(),
            "fs.edit.docs",
            "daily count of 0",
        ),
    ] {
        match predicting(&predict) {
            Err(e @ PolicyError::BadPrediction { .. }) => {
                let text = e.to_string();
                assert!(text.contains(name) && text.contains(why), "{text}");
            }
            other => panic!("{predict}: {other:?}"),
        }
    }
    // An unknown key in the limits is refused like anywhere else in the file.
    assert!(matches!(
        predicting(r#"{"fs.edit.docs": {"paths": ["docs/**"], "per_day": 5, "p": 0.5}}"#),
        Err(PolicyError::Parse(_))
    ));
}

#[test]
fn a_capability_the_person_does_not_hold_or_that_needs_two_people_is_refused() {
    let limits = r#"{"fs.edit.docs": {"paths": ["docs/**"], "per_day": 5}}"#;
    let not_held = with_people(&format!(
        r#"{{"owners": ["user:owner-1"],
            "members": {{"user:dev-1": {{"holds": ["fs.edit.code"], "predict": {limits}}}}}}}"#
    ));
    assert!(
        matches!(&not_held, Err(PolicyError::BadPrediction { why, .. }) if why.contains("don't hold")),
        "{not_held:?}"
    );
    let two = Policy::from_json(
        &format!(
            r#"{{"version": 1,
                "capabilities": {{"fs.edit.docs": {{"risk": "low", "reversible": true, "ceiling": 2}}}},
                "rules": [{{"tools": ["Edit"], "paths": ["**"], "capability": "fs.edit.docs"}}],
                "gates": {{"two_person": ["fs.edit.docs"]}},
                "people": {{"owners": ["user:owner-1"],
                  "members": {{"user:dev-1": {{"holds": ["*"], "predict": {limits}}}}}}}}}"#
        ),
        Path::new("/repo"),
    );
    assert!(
        matches!(&two, Err(PolicyError::BadPrediction { why, .. }) if why.contains("two people")),
        "{two:?}"
    );
}

#[test]
fn a_person_s_hourly_budget_is_read_and_a_budget_of_zero_is_refused() {
    let team = |dev: &str| {
        with_people(&format!(
            r#"{{"owners": ["user:owner-1"], "members": {{"user:dev-1": {dev}}}}}"#
        ))
    };
    let p = team(r#"{"escalations_per_hour": 7}"#).expect("valid");
    assert_eq!(p.escalation_budget("user:dev-1"), Some(7));
    assert_eq!(
        p.escalation_budget("user:owner-1"),
        None,
        "not listed under members"
    );
    assert_eq!(p.escalation_budgets(), [("user:dev-1", 7)]);
    let none = team("{}").expect("valid");
    assert_eq!(none.escalation_budget("user:dev-1"), None);
    assert!(none.escalation_budgets().is_empty());
    let builtin = Policy::builtin(Path::new("/repo"));
    assert_eq!(builtin.escalation_budget("user:dev-1"), None);
    assert!(builtin.escalation_budgets().is_empty());

    let err = team(r#"{"escalations_per_hour": 0}"#).expect_err("zero");
    assert!(
        matches!(&err, PolicyError::BadBudget(who) if who == "user:dev-1"),
        "{err}"
    );
    assert!(err.to_string().contains("user:dev-1"), "{err}");
}
