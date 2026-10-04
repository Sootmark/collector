//! What to collect: a plan of rules, each naming files by path pattern.
//! A rule names files by path pattern, or a command whose output is the
//! live host's state. A plan is JSON, closed and typed (no query language),
//! and identified by the SHA-256 of its text, recorded with what it
//! collected.
//!
//! ```json
//! { "name": "triage",
//!   "rules": [
//!     { "id": "evtx", "title": "Event logs",
//!       "paths": ["\\Windows\\System32\\winevt\\Logs\\*.evtx"] },
//!     { "id": "usn", "title": "USN journal",
//!       "paths": ["\\$Extend\\$UsnJrnl:$J"], "skip_leading_zeros": true },
//!     { "id": "processes", "title": "Running processes",
//!       "command": ["powershell.exe", "-NoProfile", "-Command", "…"],
//!       "output": "processes.json", "timeout_seconds": 120 } ] }
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

/// What to collect: files, or the output of a command on the live host.
#[derive(Debug, Clone)]
pub struct Rule {
    /// Short identifier, unique in the plan (`evtx`).
    pub id: String,
    /// What it collects, for people.
    pub title: String,
    /// Files, or a command.
    pub what: What,
}

/// What a rule collects.
#[derive(Debug, Clone)]
pub enum What {
    /// Files from the volume.
    Files {
        /// The files, by path pattern.
        paths: Vec<Pattern>,
        /// Most bytes kept of each file: the rest is cut, and the file
        /// marked partial. `None`: whole files.
        max_bytes: Option<u64>,
        /// Drop the whole zero pages a file starts with (a USN journal's
        /// freed start), recording how many: the stored copy starts there.
        skip_leading_zeros: bool,
    },
    /// What a command prints, on a live host only (state that is gone
    /// once the host is off: processes, connections, services).
    Command {
        /// The program and its arguments, run as given (no shell).
        argv: Vec<String>,
        /// The file its output is stored as, under `live/`.
        output: String,
        /// When to give up on it.
        timeout_seconds: u64,
    },
}

/// A command that hasn't finished by then is stopped.
const DEFAULT_TIMEOUT_SECONDS: u64 = 120;

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
            let what = if let Some(argv) = rule.get("command") {
                command(&id, rule, argv)?
            } else {
                files(&id, rule)?
            };
            rules.push(Rule {
                title: text_of(rule, "title").unwrap_or_else(|| id.clone()),
                id,
                what,
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

/// A files rule: `paths`, and optionally `max_bytes` and
/// `skip_leading_zeros`.
fn files(id: &str, rule: &Json) -> Result<What, PlanError> {
    let paths = rule
        .get("paths")
        .and_then(Json::as_array)
        .unwrap_or_default()
        .iter()
        .map(|p| {
            let text = p
                .as_str()
                .ok_or_else(|| PlanError(format!("{id}: a path is not text")))?;
            Pattern::parse(text).map_err(|e| PlanError(format!("{id}: {}", e.0)))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if paths.is_empty() {
        return Err(PlanError(format!("{id}: no paths")));
    }
    Ok(What::Files {
        paths,
        max_bytes: rule.get("max_bytes").and_then(Json::as_u64),
        skip_leading_zeros: rule.get("skip_leading_zeros") == Some(&Json::Bool(true)),
    })
}

/// A command rule: `command` (the program and its arguments), `output`
/// (a plain file name) and optionally `timeout_seconds`.
fn command(id: &str, rule: &Json, argv: &Json) -> Result<What, PlanError> {
    let argv: Vec<String> = argv
        .as_array()
        .unwrap_or_default()
        .iter()
        .map(|a| a.as_str().map(str::to_owned))
        .collect::<Option<_>>()
        .filter(|argv: &Vec<String>| !argv.is_empty())
        .ok_or_else(|| {
            PlanError(format!(
                "{id}: command is a list of strings, the program first"
            ))
        })?;
    let output = rule
        .get("output")
        .and_then(Json::as_str)
        .unwrap_or_default();
    let plain = !output.is_empty()
        && !output.starts_with('.')
        && output
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    if !plain {
        return Err(PlanError(format!("{id}: output must be a plain file name")));
    }
    Ok(What::Command {
        argv,
        output: output.to_owned(),
        timeout_seconds: rule
            .get("timeout_seconds")
            .and_then(Json::as_u64)
            .unwrap_or(DEFAULT_TIMEOUT_SECONDS),
    })
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
