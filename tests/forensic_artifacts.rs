//! Plans from ForensicArtifacts' own definitions (Apache-2.0, downloaded
//! by `tests/fetch-forensic-artifacts.sh` at a pinned commit; skipped
//! without them): every file reads, the triage groups give a plan the
//! collector accepts, and only what isn't files is left out.

use std::fs;
use std::path::Path;

use collector::{plan_from_artifacts, Plan, What};

/// The definition files' texts, when downloaded.
fn definitions() -> Option<Vec<String>> {
    let folder = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/forensic-artifacts");
    let mut files: Vec<_> = fs::read_dir(folder)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    let texts: Vec<String> = files
        .iter()
        .filter_map(|f| fs::read_to_string(f).ok())
        .collect();
    (texts.len() == 32).then_some(texts)
}

/// The artifacts a file defines, by its `name:` lines.
fn names(text: &str) -> Vec<&str> {
    text.lines()
        .filter_map(|line| line.strip_prefix("name: "))
        .map(str::trim)
        .collect()
}

#[test]
fn the_triage_groups() {
    let Some(texts) = definitions() else {
        return;
    };
    let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
    let triage = texts
        .iter()
        .find(|t| t.contains("name: TriageExecution"))
        .unwrap();
    let groups = names(triage);
    assert_eq!(groups.len(), 15);
    let built = plan_from_artifacts("triage", &texts, &groups).unwrap();
    let plan = Plan::parse(&built.plan).unwrap();
    assert_eq!(plan.rules.len(), 76);
    let ids: Vec<&str> = plan.rules.iter().map(|r| r.id.as_str()).collect();
    for expected in [
        "WindowsPrefetchFiles",
        "WindowsEventLogs",
        "WindowsAMCacheHveFile",
        "WindowsSystemRegistryFiles",
        "WindowsUserRegistryFiles",
        "WindowsScheduledTasks",
        "WindowsPowerShellHistory",
        "WindowsSearchDatabaseFile",
        "NTFSMFTFiles",
        "ChromiumBasedBrowsersHistoryDatabaseFile",
    ] {
        assert!(ids.contains(&expected), "{expected} missing");
    }
    assert!(plan
        .rules
        .iter()
        .all(|r| matches!(&r.what, What::Files { paths, .. } if !paths.is_empty())));
    // Besides artifacts for other systems, only registry values and WMI
    // queries.
    let not_files: Vec<&String> = built
        .left_out
        .iter()
        .filter(|l| !l.ends_with(": not for Windows"))
        .collect();
    assert_eq!(not_files.len(), 4, "{not_files:?}");
    assert!(not_files
        .iter()
        .all(|l| l.ends_with("a WMI source (not files)")
            || l.ends_with("a REGISTRY_VALUE source (not files)")));
}

#[test]
fn every_definition() {
    let Some(texts) = definitions() else {
        return;
    };
    let texts: Vec<&str> = texts.iter().map(String::as_str).collect();
    let all: Vec<&str> = texts.iter().flat_map(|t| names(t)).collect();
    assert_eq!(all.len(), 732);
    let built = plan_from_artifacts("everything", &texts, &all).unwrap();
    let plan = Plan::parse(&built.plan).unwrap();
    assert_eq!(plan.rules.len(), 149);
    // No path is lost to a variable this crate doesn't know.
    let unknown: Vec<&String> = built
        .left_out
        .iter()
        .filter(|l| l.contains("is not known"))
        .collect();
    assert_eq!(unknown, Vec::<&String>::new());
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

    /// Any text gives a plan or an error, never a panic.
    #[test]
    fn arbitrary_definitions(text in "[a-z:\\-\\[\\]{}',\"|>#\n %\\\\]{0,200}") {
        let _ = plan_from_artifacts("x", &[&text], &["a"]);
    }
}
