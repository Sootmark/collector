//! What to collect: a plan of rules, each naming files by path pattern.
//! A plan is JSON, closed and typed (no query language), and identified by
//! the SHA-256 of its text, recorded with what it collected.
//!
//! ```json
//! { "name": "triage",
//!   "rules": [
//!     { "id": "evtx", "title": "Event logs",
//!       "paths": ["\\Windows\\System32\\winevt\\Logs\\*.evtx"] },
//!     { "id": "usn", "title": "USN journal",
//!       "paths": ["\\$Extend\\$UsnJrnl:$J"], "max_bytes": 4294967296 } ] }
//! ```

use common::json::{self, Json};
use common::sha256::{hex, Sha256};

use crate::pattern::Pattern;

/// The plan the collector runs without `--plan`: a Windows triage.
pub const DEFAULT: &str = include_str!("default-plan.json");

/// A collection plan.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Its name.
    pub name: String,
    /// SHA-256 of its text, hex.
    pub sha256: String,
    /// Its rules, in order.
    pub rules: Vec<Rule>,
}

/// Files to collect.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Short identifier, unique in the plan (`evtx`).
    pub id: String,
    /// What it collects, for people.
    pub title: String,
    /// The files, by path pattern.
    pub paths: Vec<Pattern>,
    /// Most bytes kept of each file: the rest is cut, and the file marked
    /// partial. `None`: whole files.
    pub max_bytes: Option<u64>,
}

/// Why a plan was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanError(pub String);

impl Plan {
    /// Read a plan's JSON text.
    ///
    /// # Errors
    /// When it isn't JSON, misses a member, repeats a rule id, or has a
    /// pattern that doesn't parse.
    pub fn parse(text: &str) -> Result<Self, PlanError> {
        let fail = |why: String| PlanError(why);
        let plan = json::parse(text).map_err(|e| fail(format!("not JSON: {e:?}")))?;
        let text_of =
            |value: &Json, name: &str| value.get(name).and_then(Json::as_str).map(str::to_owned);
        let name = text_of(&plan, "name").ok_or_else(|| fail("a plan needs a name".to_owned()))?;
        let mut rules: Vec<Rule> = Vec::new();
        for rule in plan
            .get("rules")
            .and_then(Json::as_array)
            .unwrap_or_default()
        {
            let id = text_of(rule, "id").ok_or_else(|| fail("a rule needs an id".to_owned()))?;
            if rules.iter().any(|r| r.id == id) {
                return Err(fail(format!("rule {id} appears twice")));
            }
            let paths = rule
                .get("paths")
                .and_then(Json::as_array)
                .unwrap_or_default()
                .iter()
                .map(|p| {
                    let text = p
                        .as_str()
                        .ok_or_else(|| fail(format!("{id}: a path is not text")))?;
                    Pattern::parse(text).map_err(|e| fail(format!("{id}: {}", e.0)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if paths.is_empty() {
                return Err(fail(format!("{id}: no paths")));
            }
            rules.push(Rule {
                title: text_of(rule, "title").unwrap_or_else(|| id.clone()),
                id,
                paths,
                max_bytes: rule.get("max_bytes").and_then(Json::as_u64),
            });
        }
        if rules.is_empty() {
            return Err(fail("a plan needs rules".to_owned()));
        }
        Ok(Self {
            name,
            sha256: hex(&Sha256::digest(text.as_bytes())),
            rules,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_plan_parses() {
        let plan = Plan::parse(DEFAULT).unwrap();
        assert_eq!(plan.name, "windows-triage");
        assert!(plan.rules.iter().any(|r| r.id == "mft"));
        assert_eq!(plan.sha256.len(), 64);
    }

    #[test]
    fn bad_plans_are_refused() {
        for (text, why) in [
            ("{", "not JSON"),
            (r#"{"rules":[]}"#, "needs a name"),
            (r#"{"name":"x","rules":[]}"#, "needs rules"),
            (r#"{"name":"x","rules":[{"id":"a"}]}"#, "no paths"),
            (
                r#"{"name":"x","rules":[{"id":"a","paths":["x"]}]}"#,
                "volume root",
            ),
            (
                r#"{"name":"x","rules":[{"id":"a","paths":["\\a"]},{"id":"a","paths":["\\b"]}]}"#,
                "twice",
            ),
        ] {
            let error = Plan::parse(text).unwrap_err();
            assert!(error.0.contains(why), "{text}: {}", error.0);
        }
    }
}
