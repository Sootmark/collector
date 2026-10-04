//! A collection from the synthetic FIN-WKS-07 disk (made by
//! `sootmark-disk`'s `make-samples.py`; `tests/fixtures/`): files read raw
//! into the archive with their hashes, a stream stored apart, rules that
//! found nothing listed, and the run recorded.

use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use collector::{collect, Options, Plan, Volume, DEFAULT_PLAN, MANIFEST, OUTCOME};
use common::json::{self, Json};

/// `icat -o 256 fin-wks-07.img 34 | shasum -a 256`
const RCLONE_CONF_SHA256: &str = "8c4dc8c2ac27226bb585cff90ecec13394bd51e792296d1333ef178df5a2f57f";

fn image() -> PathBuf {
    // One file per call: tests run at once.
    static IMAGES: AtomicUsize = AtomicUsize::new(0);
    let compressed = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/fin-wks-07.img.zlib"
    ))
    .unwrap();
    let n = IMAGES.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "collector-fin-wks-07-{}-{n}.img",
        std::process::id()
    ));
    std::fs::write(
        &path,
        common::deflate::zlib_decompress(&compressed, 16 << 20).unwrap(),
    )
    .unwrap();
    path
}

fn run(plan: &str) -> (zip::Archive<Cursor<Vec<u8>>>, collector::Summary) {
    let path = image();
    let mut volume = Volume::open_image(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let options = Options {
        drive: 'C',
        host: "FIN-WKS-07".to_owned(),
        deadline: None,
        job: None,
        recipients: Vec::new(),
        live: false,
        limits: None,
    };
    let (out, summary) = collect(
        &mut volume,
        &Plan::parse(plan).unwrap(),
        &options,
        Vec::new(),
    )
    .unwrap();
    (zip::Archive::open(Cursor::new(out)).unwrap(), summary)
}

fn content(archive: &mut zip::Archive<Cursor<Vec<u8>>>, name: &str) -> Vec<u8> {
    let index = archive
        .entries()
        .iter()
        .position(|e| e.name == name)
        .unwrap_or_else(|| panic!("{name} not in the archive"));
    let mut bytes = Vec::new();
    archive
        .reader(index)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

fn manifest(archive: &mut zip::Archive<Cursor<Vec<u8>>>) -> Vec<Json> {
    String::from_utf8(content(archive, MANIFEST))
        .unwrap()
        .lines()
        .map(|line| json::parse(line).unwrap())
        .collect()
}

fn text<'j>(line: &'j Json, name: &str) -> Option<&'j str> {
    line.get(name).and_then(Json::as_str)
}

#[test]
fn the_default_plan_collects_what_the_volume_has() {
    let (mut archive, summary) = run(DEFAULT_PLAN);
    assert_eq!(summary.errors, 0);
    let lines = manifest(&mut archive);
    let mft = lines
        .iter()
        .find(|l| text(l, "rule") == Some("mft"))
        .unwrap();
    assert_eq!(text(mft, "status"), Some("ok"));
    assert_eq!(text(mft, "stored"), Some("C/$MFT"));
    assert_eq!(text(mft, "method"), Some("raw-ntfs"));
    assert!(!content(&mut archive, "C/$MFT").is_empty());
    let history = "C/Users/svc_backup/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt";
    assert!(!content(&mut archive, history).is_empty());
    // An image, not a running host: commands are listed, not run.
    let processes = lines
        .iter()
        .find(|l| text(l, "rule") == Some("processes"))
        .unwrap();
    assert_eq!(text(processes, "status"), Some("skipped"));
    assert!(text(processes, "why")
        .unwrap()
        .contains("not a live collection"));
    // No Windows folder on this volume: every such rule says so.
    let evtx = lines
        .iter()
        .find(|l| text(l, "rule") == Some("evtx"))
        .unwrap();
    assert_eq!(text(evtx, "status"), Some("not_found"));
    let outcome =
        json::parse(std::str::from_utf8(&content(&mut archive, OUTCOME)).unwrap()).unwrap();
    assert_eq!(
        outcome.get("host").and_then(Json::as_str),
        Some("FIN-WKS-07")
    );
    assert_eq!(
        outcome.get("collected").and_then(Json::as_u64),
        Some(summary.collected)
    );
}

#[test]
fn files_streams_hashes_and_limits() {
    let plan = r#"{ "name": "test", "rules": [
        { "id": "rclone", "paths": ["\\Users\\*\\AppData\\Roaming\\rclone\\rclone.conf"] },
        { "id": "zone", "paths": ["\\Users\\*\\Downloads\\*:Zone.Identifier"] },
        { "id": "cut", "paths": ["\\ProgramData\\Intel\\m64.exe"], "max_bytes": 1000 },
        { "id": "again", "paths": ["\\Users\\**\\rclone.conf"] },
        { "id": "nothing", "paths": ["\\nowhere\\*"] } ] }"#;
    let (mut archive, summary) = run(plan);
    let lines = manifest(&mut archive);
    let by_rule = |id: &str| {
        lines
            .iter()
            .filter(|l| text(l, "rule") == Some(id))
            .collect::<Vec<_>>()
    };
    let rclone = by_rule("rclone")[0];
    assert_eq!(text(rclone, "sha256"), Some(RCLONE_CONF_SHA256));
    assert_eq!(
        text(rclone, "path"),
        Some(r"C:\Users\svc_backup\AppData\Roaming\rclone\rclone.conf")
    );
    assert!(text(rclone, "modified").is_some());
    let zone = by_rule("zone")[0];
    assert_eq!(
        text(zone, "stored"),
        Some("C/Users/svc_backup/Downloads/tools.zip%3AZone.Identifier")
    );
    assert!(content(
        &mut archive,
        "C/Users/svc_backup/Downloads/tools.zip%3AZone.Identifier"
    )
    .starts_with(b"[ZoneTransfer]"));
    let cut = by_rule("cut")[0];
    assert_eq!(text(cut, "status"), Some("partial"));
    assert_eq!(
        cut.get("collected_bytes").and_then(Json::as_u64),
        Some(1000)
    );
    assert!(
        by_rule("again").is_empty(),
        "collected once, by the first rule"
    );
    assert_eq!(text(by_rule("nothing")[0], "status"), Some("not_found"));
    assert_eq!(
        (summary.collected, summary.partial, summary.not_found),
        (2, 1, 1)
    );
}

#[test]
fn an_encrypted_archive_opens_with_the_case_key_only() {
    let identity = age::Identity::generate();
    let recipient = identity.to_public();
    let path = image();
    let mut volume = Volume::open_image(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let options = Options {
        drive: 'C',
        host: "FIN-WKS-07".to_owned(),
        deadline: None,
        job: Some(collector::JobRecord {
            case: "case-1".to_owned(),
            issuer: "Alice".to_owned(),
            fingerprint: "0123456789abcdef".to_owned(),
        }),
        recipients: vec![recipient.to_string()],
        live: false,
        limits: None,
    };
    let encryptor = age::Encryptor::new(Vec::new(), &[recipient]).unwrap();
    let (encryptor, _) = collect(
        &mut volume,
        &Plan::parse(DEFAULT_PLAN).unwrap(),
        &options,
        encryptor,
    )
    .unwrap();
    let sealed = encryptor.finish().unwrap();
    assert!(
        zip::Archive::open(Cursor::new(sealed.clone())).is_err(),
        "not readable as is"
    );
    let stranger = age::Identity::generate();
    assert!(age::decrypt(sealed.as_slice(), &[stranger]).is_err());

    let mut plain = Vec::new();
    age::decrypt(sealed.as_slice(), &[identity])
        .unwrap()
        .read_to_end(&mut plain)
        .unwrap();
    let mut archive = zip::Archive::open(Cursor::new(plain)).unwrap();
    let outcome =
        json::parse(std::str::from_utf8(&content(&mut archive, OUTCOME)).unwrap()).unwrap();
    let job = outcome.get("job").unwrap();
    assert_eq!(job.get("case").and_then(Json::as_str), Some("case-1"));
    assert_eq!(
        outcome
            .get("encrypted_to")
            .and_then(Json::as_array)
            .map(<[Json]>::len),
        Some(1)
    );
    assert!(!content(&mut archive, "C/$MFT").is_empty());
}

#[test]
fn a_folder_through_the_file_api() {
    let root = std::env::temp_dir().join(format!("collector-folder-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let history = root.join("Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine");
    std::fs::create_dir_all(&history).unwrap();
    std::fs::write(history.join("ConsoleHost_history.txt"), b"whoami\n").unwrap();
    let mut volume = Volume::open_directory(&root).unwrap();
    let options = Options {
        drive: 'E',
        host: "WS-042".to_owned(),
        deadline: None,
        job: None,
        recipients: Vec::new(),
        live: false,
        limits: None,
    };
    let plan = r#"{ "name": "p", "rules": [
        { "id": "powershell", "paths": ["\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\*.txt"] } ] }"#;
    let (out, summary) = collect(
        &mut volume,
        &Plan::parse(plan).unwrap(),
        &options,
        Vec::new(),
    )
    .unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(summary.collected, 1);
    let mut archive = zip::Archive::open(Cursor::new(out)).unwrap();
    let stored = "E/Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt";
    assert_eq!(content(&mut archive, stored), b"whoami\n");
    let line = &manifest(&mut archive)[0];
    assert_eq!(text(line, "method"), Some("os-api"));
    assert!(line.get("mft_record").is_none(), "no MFT here");
    assert!(text(line, "modified").is_some());
}

/// A follow rule on an output shaped as the processes command's: the
/// executables it names are collected from the volume, the excluded ones
/// and those not on it aside.
#[cfg(unix)]
#[test]
fn executables_named_by_live_outputs_are_collected() {
    let path = image();
    let mut volume = Volume::open_image(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let options = Options {
        drive: 'C',
        host: "FIN-WKS-07".to_owned(),
        deadline: None,
        job: None,
        recipients: Vec::new(),
        live: true,
        limits: None,
    };
    let processes = r#"[{"ExecutablePath":"C:\\ProgramData\\Intel\\m64.exe"},{"ExecutablePath":"C:\\Windows\\System32\\svchost.exe"},{"ExecutablePath":"C:\\Users\\Public\\gone.exe"}]"#;
    let plan = format!(
        r#"{{ "name": "p", "rules": [
            {{ "id": "processes", "command": ["printf", "%s", {}], "output": "processes.json" }},
            {{ "id": "binaries", "follow": ["processes"], "exclude": ["\\Windows\\**"] }} ] }}"#,
        Json::from(processes)
    );
    let (out, _) = collect(
        &mut volume,
        &Plan::parse(&plan).unwrap(),
        &options,
        Vec::new(),
    )
    .unwrap();
    let mut archive = zip::Archive::open(Cursor::new(out)).unwrap();
    let lines = manifest(&mut archive);
    let binaries: Vec<&Json> = lines
        .iter()
        .filter(|l| text(l, "rule") == Some("binaries"))
        .collect();
    assert_eq!(binaries.len(), 2, "{binaries:?}");
    assert_eq!(
        text(binaries[0], "stored"),
        Some("C/ProgramData/Intel/m64.exe")
    );
    assert_eq!(text(binaries[0], "status"), Some("ok"));
    assert_eq!(text(binaries[1], "status"), Some("not_found"));
    assert!(!content(&mut archive, "C/ProgramData/Intel/m64.exe").is_empty());
}

/// A follow rule on the volume's scheduled tasks: a task's program is
/// collected (from an image or a folder too: no live host needed).
#[test]
fn programs_scheduled_tasks_run_are_collected() {
    let root = std::env::temp_dir().join(format!("collector-tasks-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("Windows/System32/Tasks/Microsoft")).unwrap();
    std::fs::create_dir_all(root.join("ProgramData/Updater")).unwrap();
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Actions><Exec><Command>%ProgramData%\\Updater\\update.exe</Command><Arguments>-q</Arguments></Exec></Actions></Task>";
    let utf16: Vec<u8> = [0xff, 0xfe]
        .into_iter()
        .chain(xml.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    std::fs::write(root.join("Windows/System32/Tasks/Updater"), utf16).unwrap();
    std::fs::write(
        root.join("Windows/System32/Tasks/Microsoft/Defrag"),
        "<Task><Exec><Command>%windir%\\system32\\defrag.exe</Command></Exec></Task>",
    )
    .unwrap();
    std::fs::write(root.join("ProgramData/Updater/update.exe"), b"MZ").unwrap();
    let mut volume = Volume::open_directory(&root).unwrap();
    let options = Options {
        drive: 'C',
        host: "WS-042".to_owned(),
        deadline: None,
        job: None,
        recipients: Vec::new(),
        live: false,
        limits: None,
    };
    let plan = r#"{ "name": "p", "rules": [
        { "id": "persistence", "follow": ["scheduled-tasks", "run-keys"], "exclude": ["\\Windows\\**"] } ] }"#;
    let (out, summary) = collect(
        &mut volume,
        &Plan::parse(plan).unwrap(),
        &options,
        Vec::new(),
    )
    .unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(summary.collected, 1);
    let mut archive = zip::Archive::open(Cursor::new(out)).unwrap();
    assert_eq!(
        content(&mut archive, "C/ProgramData/Updater/update.exe"),
        b"MZ"
    );
}

/// A follow rule on Prefetch: the program a Prefetch file records as run
/// (plaso's `ONEDRIVE.EXE-7E152375.pf`, Apache-2.0) is collected, its
/// upper-case path matched without case.
#[test]
fn programs_prefetch_records_are_collected() {
    let root = std::env::temp_dir().join(format!("collector-prefetch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("Windows/Prefetch")).unwrap();
    std::fs::create_dir_all(root.join("Users/test/AppData/Local/Microsoft/OneDrive")).unwrap();
    std::fs::copy(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/prefetch/ONEDRIVE.EXE-7E152375.pf"
        ),
        root.join("Windows/Prefetch/ONEDRIVE.EXE-7E152375.pf"),
    )
    .unwrap();
    std::fs::write(
        root.join("Users/test/AppData/Local/Microsoft/OneDrive/OneDrive.exe"),
        b"MZ",
    )
    .unwrap();
    let mut volume = Volume::open_directory(&root).unwrap();
    let options = Options {
        drive: 'C',
        host: "WS-042".to_owned(),
        deadline: None,
        job: None,
        recipients: Vec::new(),
        live: false,
        limits: None,
    };
    let plan = r#"{ "name": "p", "rules": [ { "id": "ran", "follow": ["prefetch"] } ] }"#;
    let (out, summary) = collect(
        &mut volume,
        &Plan::parse(plan).unwrap(),
        &options,
        Vec::new(),
    )
    .unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(summary.collected, 1);
    let mut archive = zip::Archive::open(Cursor::new(out)).unwrap();
    assert_eq!(
        content(
            &mut archive,
            "C/Users/test/AppData/Local/Microsoft/OneDrive/OneDrive.exe"
        ),
        b"MZ"
    );
}
