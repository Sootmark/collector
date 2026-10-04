//! What a follow rule collects: the executables the live outputs name, the
//! running processes' images (`ExecutablePath`) and the services' binaries
//! (the program in `PathName`), as paths on the collected volume. The
//! volume's own sources are in `artifacts`.

use common::json::{self, Json};

/// The executable paths `output` (a command rule's JSON) names, as
/// written on the host (`C:\Users\…\a.exe`).
pub(crate) fn named(output: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(output);
    let text = text.trim_start_matches('\u{feff}').trim();
    let items = match json::parse(text) {
        Ok(Json::Array(items)) => items,
        Ok(item @ Json::Object(_)) => vec![item],
        _ => return Vec::new(),
    };
    items
        .iter()
        .filter_map(|item| {
            let text = |name: &str| {
                item.get(name)
                    .and_then(Json::as_str)
                    .filter(|t| !t.is_empty())
            };
            text("ExecutablePath")
                .map(str::to_owned)
                .or_else(|| text("PathName").and_then(program).map(str::to_owned))
        })
        .collect()
}

/// What a command line runs: its quoted program (`"C:\a b\x.exe" -k`),
/// or up to the first program or script extension (`C:\a b\x.exe -k`,
/// spaces and all; `C:\x\run.ps1`).
pub(crate) fn program(command_line: &str) -> Option<&str> {
    let line = command_line.trim();
    if let Some(quoted) = line.strip_prefix('"') {
        return quoted.split('"').next().filter(|p| !p.is_empty());
    }
    let lower = line.to_ascii_lowercase();
    let end = PROGRAMS
        .iter()
        .filter_map(|extension| lower.find(extension).map(|at| at + extension.len()))
        .min()?;
    Some(&line[..end])
}

/// What a command line may run directly: programs and scripts.
const PROGRAMS: [&str; 7] = [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta"];

/// `path`'s components on the volume at `drive`, when it is on it:
/// `C:\Users\a.exe` → `["Users", "a.exe"]`. `\??\` and `%SystemRoot%`
/// (the volume's `\Windows`) are understood.
pub(crate) fn on_volume(path: &str, drive: char) -> Option<Vec<String>> {
    let path = path.strip_prefix(r"\??\").unwrap_or(path);
    let rest = if let Some(rest) = strip_prefix_ignore_case(path, "%SystemRoot%") {
        format!(r"\Windows{rest}")
    } else {
        let (letter, rest) = path.split_once(':')?;
        if !letter.eq_ignore_ascii_case(&drive.to_string()) {
            return None;
        }
        rest.to_owned()
    };
    let parts: Vec<String> = rest
        .split(['\\', '/'])
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect();
    let climbs = parts.iter().any(|p| p == "." || p == "..");
    (!parts.is_empty() && !climbs).then_some(parts)
}

fn strip_prefix_ignore_case<'p>(text: &'p str, prefix: &str) -> Option<&'p str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processes_and_services_name_their_programs() {
        let processes = br#"[{"Name":"a","ExecutablePath":"C:\\Users\\alice\\AppData\\Roaming\\u.exe"},{"Name":"System","ExecutablePath":null}]"#;
        assert_eq!(named(processes), [r"C:\Users\alice\AppData\Roaming\u.exe"]);
        let services = br#"{"Name":"svc","PathName":"\"C:\\Program Data\\x y\\svc.exe\" -run"}"#;
        assert_eq!(named(services), [r"C:\Program Data\x y\svc.exe"]);
        assert!(named(b"").is_empty() && named(b"not json").is_empty());
    }

    #[test]
    fn command_lines() {
        assert_eq!(
            program(r"C:\Windows\system32\svchost.exe -k netsvcs"),
            Some(r"C:\Windows\system32\svchost.exe")
        );
        assert_eq!(
            program(r"C:\Program Files\A B\x.EXE /service"),
            Some(r"C:\Program Files\A B\x.EXE")
        );
        assert_eq!(program(r#""C:\a b\x.exe" -k"#), Some(r"C:\a b\x.exe"));
        assert_eq!(program("rundll32 x.dll"), None);
    }

    #[test]
    fn paths_on_the_volume() {
        assert_eq!(
            on_volume(r"C:\Users\a.exe", 'C'),
            Some(vec!["Users".to_owned(), "a.exe".to_owned()])
        );
        assert_eq!(on_volume(r"c:\Users\a.exe", 'C').map(|p| p.len()), Some(2));
        assert_eq!(on_volume(r"\??\C:\x\a.exe", 'C').map(|p| p.len()), Some(2));
        assert_eq!(
            on_volume(r"%SystemRoot%\system32\a.exe", 'C'),
            Some(vec![
                "Windows".to_owned(),
                "system32".to_owned(),
                "a.exe".to_owned()
            ])
        );
        assert_eq!(on_volume(r"D:\a.exe", 'C'), None);
        assert_eq!(on_volume(r"C:\a\..\b.exe", 'C'), None);
        assert_eq!(on_volume("a.exe", 'C'), None);
    }
}
