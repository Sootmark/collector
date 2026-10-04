//! Plans from ForensicArtifacts definitions
//! (<https://github.com/ForensicArtifacts/artifacts>, Apache-2.0): the
//! artifacts named, their groups followed, each one's Windows files a rule
//! of the plan.
//!
//! A `FILE` source's paths become patterns: their variables
//! (`%%environ_systemroot%%`, `%%users.localappdata%%`, …) replaced by the
//! folders they stand for on a Windows volume, every account's at once
//! (`\Users\*\AppData\Local`), and `**N` (ForensicArtifacts' recursion to
//! depth N) by `**`. `ARTIFACT_GROUP` sources name other artifacts, by
//! name or alias. What the collector can't gather from a volume (registry
//! keys and values, commands, WMI queries) and paths with variables it
//! doesn't know are left out and listed, as are artifacts not for
//! Windows.

use std::collections::HashMap;

use common::json::Json;

use crate::pattern::Pattern;
use crate::plan::Plan;
use crate::yaml::{self, Yaml};

/// Variables of ForensicArtifacts paths, and the volume folders they stand
/// for. `%%users.…%%` are every account's (`*`).
const VARIABLES: [(&str, &str); 17] = [
    ("%%environ_systemroot%%", r"\Windows"),
    ("%%environ_windir%%", r"\Windows"),
    ("%%environ_systemdrive%%", ""),
    ("%%environ_programfiles%%", r"\Program Files"),
    ("%%environ_programfilesx86%%", r"\Program Files (x86)"),
    ("%%environ_programdata%%", r"\ProgramData"),
    ("%%environ_allusersappdata%%", r"\ProgramData"),
    ("%%environ_allusersprofile%%", r"\ProgramData"),
    ("%%users.homedir%%", r"\Users\*"),
    ("%%users.userprofile%%", r"\Users\*"),
    ("%%users.appdata%%", r"\Users\*\AppData\Roaming"),
    ("%%users.localappdata%%", r"\Users\*\AppData\Local"),
    ("%%users.localappdata_low%%", r"\Users\*\AppData\LocalLow"),
    ("%%users.temp%%", r"\Users\*\AppData\Local\Temp"),
    ("%%users.desktop%%", r"\Users\*\Desktop"),
    ("%%users.username%%", "*"),
    ("%%users.sid%%", "*"),
];

/// A plan built from definitions, and what was left out of it.
#[derive(Debug, Clone, PartialEq)]
pub struct Built {
    /// The plan, as JSON text (what `--plan` reads).
    pub plan: String,
    /// What wasn't taken, and why: one line each.
    pub left_out: Vec<String>,
}

/// Why no plan could be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportError(pub String);

/// The definitions read, by name.
type Artifacts = HashMap<String, Artifact>;
/// Every name and alias, to the name it stands for.
type Aliases = HashMap<String, String>;

/// One definition, as read.
struct Artifact {
    name: String,
    title: String,
    windows: bool,
    sources: Vec<Yaml>,
}

/// A plan named `name` collecting the artifacts `wanted` (names or
/// aliases) and those their groups name, from the definition files'
/// texts `definitions`.
///
/// # Errors
/// When a file doesn't read, a wanted artifact isn't defined, or nothing
/// is left to collect.
pub fn build(name: &str, definitions: &[&str], wanted: &[&str]) -> Result<Built, ImportError> {
    let (artifacts, aliases) = read_all(definitions)?;
    let mut left_out = Vec::new();
    let mut order: Vec<&str> = Vec::new();
    let mut pending: Vec<(String, Option<String>)> = wanted
        .iter()
        .rev()
        .map(|w| ((*w).to_owned(), None))
        .collect();
    while let Some((wanted, from)) = pending.pop() {
        let Some(found) = aliases.get(wanted.as_str()).and_then(|n| artifacts.get(n)) else {
            match from {
                None => return Err(ImportError(format!("{wanted}: no such artifact"))),
                Some(group) => left_out.push(format!("{wanted} (named by {group}): not defined")),
            }
            continue;
        };
        if order.contains(&found.name.as_str()) {
            continue;
        }
        order.push(&found.name);
        for source in found.sources.iter().filter(|s| for_windows(s)) {
            if text_of(source, "type") == Some("ARTIFACT_GROUP") {
                let names = source.get("attributes").and_then(|a| a.get("names"));
                let names = names.map(Yaml::items).unwrap_or_default();
                for named in names.iter().rev().filter_map(|n| n.as_text()) {
                    pending.push((named.to_owned(), Some(found.name.clone())));
                }
            }
        }
    }
    let rules: Vec<Json> = order
        .iter()
        .filter_map(|name| rule(&artifacts[*name], &mut left_out))
        .collect();
    if rules.is_empty() {
        return Err(ImportError(
            "nothing to collect: none of these artifacts has Windows files".to_owned(),
        ));
    }
    let plan = Json::object([
        ("name", Json::String(name.to_owned())),
        ("rules", Json::Array(rules)),
    ])
    .to_pretty();
    // What the collector will read back: refused here, not at collection.
    Plan::parse(&plan).map_err(|e| ImportError(e.0))?;
    Ok(Built { plan, left_out })
}

/// Every artifact by name, and every name and alias to its name.
fn read_all(definitions: &[&str]) -> Result<(Artifacts, Aliases), ImportError> {
    let mut artifacts = HashMap::new();
    let mut aliases = HashMap::new();
    for (file, text) in definitions.iter().enumerate() {
        let documents =
            yaml::documents(text).map_err(|e| ImportError(format!("file {}: {e}", file + 1)))?;
        for document in documents {
            let Some(name) = text_of(&document, "name") else {
                continue;
            };
            let names = document.get("aliases").map(Yaml::items).unwrap_or_default();
            for alias in names.iter().filter_map(|a| a.as_text()) {
                aliases.insert(alias.to_owned(), name.to_owned());
            }
            aliases.insert(name.to_owned(), name.to_owned());
            let artifact = Artifact {
                name: name.to_owned(),
                title: text_of(&document, "doc")
                    .and_then(|doc| doc.lines().next())
                    .unwrap_or(name)
                    .trim()
                    .to_owned(),
                // No list: for every system.
                windows: for_windows(&document),
                sources: document
                    .get("sources")
                    .map(Yaml::items)
                    .unwrap_or_default()
                    .into_iter()
                    .cloned()
                    .collect(),
            };
            artifacts.insert(name.to_owned(), artifact);
        }
    }
    Ok((artifacts, aliases))
}

/// The plan's rule for `artifact`'s Windows files, if it has some; what is
/// left out goes to `left_out`.
fn rule(artifact: &Artifact, left_out: &mut Vec<String>) -> Option<Json> {
    let name = &artifact.name;
    if !artifact.windows {
        left_out.push(format!("{name}: not for Windows"));
        return None;
    }
    let mut paths: Vec<String> = Vec::new();
    for source in artifact.sources.iter().filter(|s| for_windows(s)) {
        match text_of(source, "type") {
            Some("FILE") => {
                let listed = source.get("attributes").and_then(|a| a.get("paths"));
                for path in listed.map(Yaml::items).unwrap_or_default() {
                    let Some(path) = path.as_text() else {
                        continue;
                    };
                    match pattern(path) {
                        Ok(pattern) if !paths.contains(&pattern) => paths.push(pattern),
                        Ok(_) => {}
                        Err(why) => left_out.push(format!("{name}: {path}: {why}")),
                    }
                }
            }
            Some("ARTIFACT_GROUP") => {}
            Some(other) => left_out.push(format!("{name}: a {other} source (not files)")),
            None => left_out.push(format!("{name}: a source without a type")),
        }
    }
    if paths.is_empty() {
        return None;
    }
    Some(Json::object([
        ("id", Json::String(name.clone())),
        ("title", Json::String(artifact.title.clone())),
        (
            "paths",
            Json::Array(paths.into_iter().map(Json::String).collect()),
        ),
    ]))
}

/// A ForensicArtifacts path as a collector pattern.
fn pattern(path: &str) -> Result<String, String> {
    let mut text = path.replace('/', "\\");
    for (variable, folder) in VARIABLES {
        if text.len() >= variable.len() {
            text = replace_ignoring_case(&text, variable, folder);
        }
    }
    if let Some(at) = text.find("%%") {
        let end = text[at + 2..].find("%%").map_or(text.len(), |e| at + e + 4);
        return Err(format!("{} is not known", &text[at..end]));
    }
    // A drive letter: the volume collected is the system's.
    if text.as_bytes().get(1) == Some(&b':') {
        text.replace_range(..2, "");
    }
    let components: Vec<&str> = text
        .split('\\')
        .map(|part| {
            let depth = part.strip_prefix("**");
            if depth.is_some_and(|d| d.chars().all(|c| c.is_ascii_digit())) {
                "**"
            } else {
                part
            }
        })
        .collect();
    let text = components.join("\\");
    Pattern::parse(&text).map_err(|e| e.0)?;
    Ok(text)
}

fn replace_ignoring_case(text: &str, from: &str, to: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::new();
    let mut last = 0;
    for (at, _) in lower.match_indices(from) {
        out.push_str(&text[last..at]);
        out.push_str(to);
        last = at + from.len();
    }
    out.push_str(&text[last..]);
    out
}

/// Whether a definition or one of its sources is for Windows: its
/// `supported_os` names it, or it has none (for every system; a source
/// without one is for its artifact's).
fn for_windows(value: &Yaml) -> bool {
    value.get("supported_os").is_none_or(|systems| {
        systems
            .items()
            .iter()
            .any(|system| system.as_text() == Some("Windows"))
    })
}

fn text_of<'a>(value: &'a Yaml, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Yaml::as_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFINITIONS: &str = r"
name: WindowsPrefetchFiles
aliases: [Prefetch]
doc: Windows Prefetch files.
sources:
- type: FILE
  attributes:
    paths: ['%%environ_systemroot%%\Prefetch\*.pf']
    separator: '\'
supported_os: [Windows]
---
name: WindowsTriage
doc: |
  A few things.

  More words.
sources:
- type: ARTIFACT_GROUP
  attributes: {names: ['Prefetch', 'WindowsRunKeys', 'ChromeHistory', 'Missing']}
- type: FILE
  attributes:
    paths:
    - '%%users.localappdata%%\Temp\**5'
    - '%%users.homedir%%\%%users.username%%.log'
    - 'C:\x.txt'
    - '%%environ_mystery%%\y'
---
name: WindowsRunKeys
sources:
- type: REGISTRY_KEY
  attributes: {keys: ['HKEY_USERS\%%users.sid%%\Software\Microsoft\Windows\CurrentVersion\Run']}
supported_os: [Windows]
---
name: ChromeHistory
sources:
- type: FILE
  attributes: {paths: ['%%users.homedir%%/.config/google-chrome/*/History']}
supported_os: [Linux]
---
name: RedisConfigFile
sources:
- type: FILE
  attributes:
    paths: ['%%environ_programfiles%%\Redis\conf\redis.conf']
    separator: '\'
  supported_os: [Windows]
- type: FILE
  attributes: {paths: ['/etc/redis/redis.conf']}
  supported_os: [Linux]
supported_os: [Linux, Windows]
";

    #[test]
    fn groups_variables_and_what_is_left_out() {
        let built = build("triage", &[DEFINITIONS], &["WindowsTriage"]).unwrap();
        let plan = Plan::parse(&built.plan).unwrap();
        let rules: Vec<(&str, &str)> = plan
            .rules
            .iter()
            .map(|r| (r.id.as_str(), r.title.as_str()))
            .collect();
        assert_eq!(
            rules,
            [
                ("WindowsTriage", "A few things."),
                ("WindowsPrefetchFiles", "Windows Prefetch files.")
            ]
        );
        let json = common::json::parse(&built.plan).unwrap();
        let paths: Vec<&str> = json.get("rules").and_then(Json::as_array).unwrap()[0]
            .get("paths")
            .and_then(Json::as_array)
            .unwrap()
            .iter()
            .filter_map(Json::as_str)
            .collect();
        assert_eq!(
            paths,
            [
                r"\Users\*\AppData\Local\Temp\**",
                r"\Users\*\*.log",
                r"\x.txt"
            ]
        );
        assert_eq!(
            built.left_out,
            [
                "Missing (named by WindowsTriage): not defined",
                r"WindowsTriage: %%environ_mystery%%\y: %%environ_mystery%% is not known",
                "WindowsRunKeys: a REGISTRY_KEY source (not files)",
                "ChromeHistory: not for Windows",
            ]
        );
    }

    #[test]
    fn unknown_names_and_nothing_to_collect_are_errors() {
        assert!(build("x", &[DEFINITIONS], &["Nope"]).is_err());
        assert!(build("x", &[DEFINITIONS], &["WindowsRunKeys"]).is_err());
        assert!(build("x", &["a: [1,\n"], &["A"]).is_err());
    }

    #[test]
    fn only_a_sources_windows_paths() {
        let built = build("x", &[DEFINITIONS], &["RedisConfigFile"]).unwrap();
        assert!(built
            .plan
            .contains(r"\\Program Files\\Redis\\conf\\redis.conf"));
        assert!(!built.plan.contains("etc"));
        assert_eq!(built.left_out, Vec::<String>::new());
    }
}
