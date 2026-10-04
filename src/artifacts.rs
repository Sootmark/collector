//! Executables named by the collected volume itself, for follow rules:
//! what scheduled tasks run (`\Windows\System32\Tasks`) and what the
//! registry starts at logon (the `Run` and `RunOnce` keys, machine-wide in
//! `SOFTWARE` and per user in each `NTUSER.DAT`). Unlike the live outputs,
//! these come from files, so they work on a disk image too.

use std::io::Read;

use disk::FileEntry;

use crate::follow::program;
use crate::pattern::Pattern;
use crate::volume::Volume;

/// The sources a follow rule may name besides command rules.
pub(crate) const SOURCES: [&str; 2] = ["scheduled-tasks", "run-keys"];

/// Largest task file or hive read.
const MAX_TASK: u64 = 1 << 20;
const MAX_HIVE: u64 = 512 << 20;

/// The keys whose values start programs at logon, in `SOFTWARE`.
const MACHINE_KEYS: [&str; 4] = [
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
];
/// The same, in a user's `NTUSER.DAT`.
const USER_KEYS: [&str; 2] = [
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
];

/// The programs `source` names on `volume` (at `drive`), as host paths.
pub(crate) fn named(
    source: &str,
    volume: &mut Volume,
    files: &[FileEntry],
    drive: char,
) -> Vec<String> {
    match source {
        "scheduled-tasks" => scheduled_tasks(volume, files, drive),
        "run-keys" => run_keys(volume, files, drive),
        _ => Vec::new(),
    }
}

/// What each task file's `<Command>` runs.
fn scheduled_tasks(volume: &mut Volume, files: &[FileEntry], drive: char) -> Vec<String> {
    let tasks = Pattern::parse(r"\Windows\System32\Tasks\**").expect("a valid pattern");
    let mut programs = Vec::new();
    for file in files
        .iter()
        .filter(|f| f.stream.is_none() && tasks.matches(&f.path, None))
    {
        let Some(bytes) = read(volume, file, MAX_TASK) else {
            continue;
        };
        let xml = text(&bytes);
        let mut rest = xml.as_str();
        while let Some(start) = rest.find("<Command>") {
            rest = &rest[start + "<Command>".len()..];
            let Some(end) = rest.find("</Command>") else {
                break;
            };
            let command = unescape(rest[..end].trim());
            if let Some(path) = program(&expand(&command, drive, None)) {
                programs.push(path.to_owned());
            }
            rest = &rest[end..];
        }
    }
    programs
}

/// What the `Run` and `RunOnce` values start: machine-wide, then each
/// user's, their `%APPDATA%` and the like expanded to that user's folders.
fn run_keys(volume: &mut Volume, files: &[FileEntry], drive: char) -> Vec<String> {
    let machine = Pattern::parse(r"\Windows\System32\config\SOFTWARE").expect("a valid pattern");
    let users = Pattern::parse(r"\Users\*\NTUSER.DAT").expect("a valid pattern");
    let mut programs = Vec::new();
    for file in files.iter().filter(|f| f.stream.is_none()) {
        let (keys, profile): (&[&str], Option<String>) = if machine.matches(&file.path, None) {
            (&MACHINE_KEYS, None)
        } else if users.matches(&file.path, None) {
            (
                &USER_KEYS,
                Some(format!(r"{drive}:\Users\{}", file.path[1])),
            )
        } else {
            continue;
        };
        let Some(bytes) = read(volume, file, MAX_HIVE) else {
            continue;
        };
        let Ok(hive) = registry::Hive::parse(&bytes) else {
            continue;
        };
        for key in keys {
            let Ok(Some(key)) = hive.open(key) else {
                continue;
            };
            let Ok(values) = key.values() else { continue };
            for value in values.into_iter().flatten() {
                if let registry::Data::String(command) = value.data() {
                    if let Some(path) = program(&expand(&command, drive, profile.as_deref())) {
                        programs.push(path.to_owned());
                    }
                }
            }
        }
    }
    programs
}

/// `file`'s content, up to `limit` bytes; `None` when it can't be read.
fn read(volume: &mut Volume, file: &FileEntry, limit: u64) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    volume
        .read(file, &mut |content| {
            content.take(limit).read_to_end(&mut bytes).map(|_| ())
        })
        .ok()?;
    Some(bytes)
}

/// A task file's text: UTF-16 (little-endian, as Windows writes them) when
/// it starts with its byte order mark, UTF-8 otherwise.
fn text(bytes: &[u8]) -> String {
    match bytes.strip_prefix(&[0xff, 0xfe]) {
        Some(utf16) => {
            let units: Vec<u16> = utf16
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        None => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// XML's five escapes.
fn unescape(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// The environment variables a command line commonly starts with, as the
/// volume at `drive` has them; a user's folders when `profile` is known.
fn expand(command: &str, drive: char, profile: Option<&str>) -> String {
    let mut expanded = command.to_owned();
    let system = [
        ("%SystemRoot%", format!(r"{drive}:\Windows")),
        ("%windir%", format!(r"{drive}:\Windows")),
        ("%ProgramFiles%", format!(r"{drive}:\Program Files")),
        (
            "%ProgramFiles(x86)%",
            format!(r"{drive}:\Program Files (x86)"),
        ),
        ("%ProgramData%", format!(r"{drive}:\ProgramData")),
        ("%SystemDrive%", format!("{drive}:")),
    ];
    let user = profile.map(|profile| {
        [
            ("%USERPROFILE%", profile.to_owned()),
            ("%APPDATA%", format!(r"{profile}\AppData\Roaming")),
            ("%LOCALAPPDATA%", format!(r"{profile}\AppData\Local")),
            ("%TEMP%", format!(r"{profile}\AppData\Local\Temp")),
        ]
    });
    for (name, value) in system.iter().chain(user.iter().flatten()) {
        expanded = replace_ignore_case(&expanded, name, value);
    }
    expanded
}

fn replace_ignore_case(text: &str, name: &str, value: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let needle = name.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    while let Some(found) = lower[at..].find(&needle) {
        out.push_str(&text[at..at + found]);
        out.push_str(value);
        at += found + needle.len();
    }
    out.push_str(&text[at..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variables_expand_without_case() {
        assert_eq!(
            expand(r"%WINDIR%\system32\x.exe /q", 'C', None),
            r"C:\Windows\system32\x.exe /q"
        );
        assert_eq!(
            expand(r"%AppData%\u.exe", 'C', Some(r"C:\Users\alice")),
            r"C:\Users\alice\AppData\Roaming\u.exe"
        );
        assert_eq!(expand(r"%AppData%\u.exe", 'C', None), r"%AppData%\u.exe");
    }

    #[test]
    fn task_files_in_either_encoding() {
        let xml = "<Task><Actions><Exec><Command>&quot;C:\\a b\\x.exe&quot;</Command></Exec></Actions></Task>";
        let utf16: Vec<u8> = [0xff, 0xfe]
            .into_iter()
            .chain(xml.encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(text(&utf16), xml);
        assert_eq!(unescape("&quot;C:\\a&amp;b&quot;"), "\"C:\\a&b\"");
    }
}
