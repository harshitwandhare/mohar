//! Reporting lines read from an identity provider's SCIM 2.0 user export (`people.directory`). Each
//! listed member reports to the nearest listed, active person up their manager chain in the export, and
//! anything the export can't settle stops the policy from loading.
#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use mohar_core::policy::{Policy, PolicyError, Route};

static N: AtomicU32 = AtomicU32::new(0);

/// A fresh directory holding `users.json` with `users` as its Resources.
fn project(users: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mohar-directory-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    std::fs::write(
        dir.join("users.json"),
        format!(
            r#"{{"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                "totalResults": 0, "Resources": {users}}}"#
        ),
    )
    .expect("write export");
    dir
}

fn user(id: &str, name: &str, manager: Option<&str>, active: bool) -> String {
    let manager = manager.map_or(String::new(), |m| {
        format!(
            r#", "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {{"manager": {{"value": "{m}"}}}}"#
        )
    });
    format!(r#"{{"id": "{id}", "userName": "{name}", "active": {active}{manager}}}"#)
}

fn load(users: &str, members: &str) -> Result<Policy, PolicyError> {
    let dir = project(users);
    Policy::from_json(
        &format!(
            r#"{{"version": 1,
                "capabilities": {{
                  "fs.edit.docs": {{"risk": "low", "reversible": true, "ceiling": 2}},
                  "fs.edit.code": {{"risk": "medium", "reversible": true, "ceiling": 2}}
                }},
                "rules": [{{"tools": ["Edit"], "paths": ["**"], "capability": "fs.edit.code"}}],
                "people": {{
                  "owners": ["user:owner-1"],
                  "directory": "users.json",
                  "members": {members},
                  "delegations": [{{"agent": "agent:docs/*", "from": "user:dev-1"}}]
                }}}}"#
        ),
        &dir,
    )
}

/// The dev reports to a manager Mohar doesn't list, who reports to the lead.
fn org() -> String {
    format!(
        "[{}, {}, {}, {}]",
        user("1", "user:dev-1", Some("2"), true),
        user("2", "user:mgr-1", Some("3"), true),
        user("3", "user:lead-1", Some("4"), true),
        user("4", "user:vp-1", None, true),
    )
}

const MEMBERS: &str =
    r#"{"user:dev-1": {"holds": ["fs.edit.docs"]}, "user:lead-1": {"holds": ["fs.edit.*"]}}"#;

#[test]
fn a_member_reports_to_the_nearest_listed_person_up_the_directory_chain() {
    let p = load(&org(), MEMBERS).expect("valid");
    assert_eq!(
        p.route("agent:docs/w", "fs.edit.code"),
        Some(Route {
            to: vec!["user:lead-1".into()],
            via: "reporting_tree"
        }),
        "the unlisted manager is passed over, not a dead end"
    );
    let levels = p.escalation_levels("agent:docs/w", "fs.edit.docs");
    let to: Vec<_> = levels.iter().map(|l| l.to.clone()).collect();
    assert_eq!(
        to,
        [
            vec!["user:dev-1".to_string()],
            vec!["user:lead-1".to_string()],
            vec!["user:owner-1".to_string()]
        ]
    );
}

#[test]
fn an_inactive_manager_is_passed_over() {
    let users = format!(
        "[{}, {}, {}]",
        user("1", "user:dev-1", Some("3"), true),
        user("3", "user:lead-1", Some("4"), false),
        user("4", "user:vp-1", None, true),
    );
    let members = r#"{"user:dev-1": {"holds": ["fs.edit.docs"]}, "user:lead-1": {"holds": ["fs.edit.*"]}, "user:vp-1": {"holds": ["fs.edit.*"]}}"#;
    // lead-1 is inactive but listed: refused, below. Unlisted and inactive is passed over here.
    let members_no_lead =
        r#"{"user:dev-1": {"holds": ["fs.edit.docs"]}, "user:vp-1": {"holds": ["fs.edit.*"]}}"#;
    let p = load(&users, members_no_lead).expect("valid");
    assert_eq!(
        p.route("agent:docs/w", "fs.edit.code").expect("route").to,
        ["user:vp-1"]
    );
    let e = load(&users, members).expect_err("an inactive member can't approve");
    assert!(e.to_string().contains("user:lead-1"), "{e}");
}

#[test]
fn a_reporting_line_in_the_policy_must_agree_with_the_directory() {
    let same = r#"{"user:dev-1": {"holds": ["fs.edit.docs"], "reports_to": "user:lead-1"}, "user:lead-1": {"holds": ["fs.edit.*"]}}"#;
    load(&org(), same).expect("agreeing line is fine");
    let other = r#"{"user:dev-1": {"holds": ["fs.edit.docs"], "reports_to": "user:vp-1"}, "user:lead-1": {"holds": ["fs.edit.*"]}, "user:vp-1": {}}"#;
    let e = load(&org(), other).expect_err("two answers to who the dev reports to");
    assert!(e.to_string().contains("user:dev-1"), "{e}");
}

#[test]
fn a_member_missing_from_the_directory_keeps_the_policy_line() {
    let members = r#"{"user:dev-1": {"holds": ["fs.edit.docs"]}, "user:lead-1": {"holds": ["fs.edit.*"]}, "user:contractor-1": {"reports_to": "user:lead-1"}}"#;
    let p = load(&org(), members).expect("valid");
    let to = p
        .escalation_levels("agent:none", "fs.edit.docs")
        .last()
        .expect("owners")
        .to
        .clone();
    assert_eq!(to, ["user:owner-1"]);
}

#[test]
fn field_names_are_matched_without_case_as_scim_says() {
    let users = r#"[{"ID": "1", "username": "user:dev-1", "Active": true,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:user": {"Manager": {"Value": "3"}}},
        {"id": "3", "userName": "user:lead-1", "active": false}]"#;
    let e = load(users, MEMBERS).expect_err("lead-1 is inactive even with odd casing");
    assert!(e.to_string().contains("user:lead-1"), "{e}");
}

#[test]
fn an_export_that_cannot_be_settled_is_refused() {
    let cases = [
        ("[".to_string(), "not JSON"),
        (r#"{"id": "1"}"#.to_string(), "Resources not a list"),
        (
            format!("[{}]", user("1", "user:dev-1", Some("9"), true)),
            "a manager who isn't in the export",
        ),
        (
            format!(
                "[{}, {}]",
                user("1", "user:dev-1", None, true),
                user("1", "user:lead-1", None, true)
            ),
            "two users with one id",
        ),
        (
            format!(
                "[{}, {}]",
                user("1", "user:dev-1", None, true),
                user("2", "user:dev-1", None, true)
            ),
            "two users with one userName",
        ),
        (
            format!(
                "[{}, {}, {}]",
                user("1", "user:dev-1", Some("2"), true),
                user("2", "user:a", Some("5"), true),
                user("5", "user:b", Some("2"), true)
            ),
            "a manager loop among unlisted people",
        ),
        (
            format!("[{}]", user("1", "user:dev-1", Some("1"), true)),
            "a member who manages themself",
        ),
        (
            r#"[{"id": "1", "userName": "user:dev-1", "active": "yes"}]"#.to_string(),
            "active that isn't true or false",
        ),
        (
            r#"[{"id": "1", "userName": "user:dev-1", "username": "user:dev-1"}]"#.to_string(),
            "the same field twice in different case",
        ),
        (
            r#"[{"userName": "user:dev-1"}]"#.to_string(),
            "a user without an id",
        ),
        ("[1]".to_string(), "a user that isn't an object"),
        (
            r#"[{"id": "", "userName": "user:dev-1"}]"#.to_string(),
            "an empty id",
        ),
        (
            r#"[{"id": "1", "userName": "user:dev-1",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"manager": "2"}}]"#
                .to_string(),
            "a manager that isn't an object",
        ),
        (
            r#"[{"id": "1", "userName": "user:dev-1",
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": "x"}]"#
                .to_string(),
            "an enterprise extension that isn't an object",
        ),
    ];
    for (users, why) in cases {
        assert!(load(&users, MEMBERS).is_err(), "accepted {why}: {users}");
    }
    let e = load(
        &format!("[{}]", user("1", "user:dev-1", Some("9"), true)),
        MEMBERS,
    )
    .expect_err("unknown manager");
    assert!(e.to_string().contains("\"9\""), "names the missing id: {e}");
}

#[test]
fn a_directory_file_that_is_missing_is_refused() {
    let dir = project("[]");
    std::fs::remove_file(dir.join("users.json")).expect("remove");
    let e = Policy::from_json(
        r#"{"version": 1, "capabilities": {}, "rules": [],
            "people": {"owners": ["user:o"], "directory": "users.json"}}"#,
        &dir,
    )
    .expect_err("missing export");
    assert!(e.to_string().contains("users.json"), "{e}");
}
