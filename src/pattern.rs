//! Path patterns: a volume path (`\Windows\Prefetch\*.pf`) whose
//! components may hold `*` (any run of characters) and `?` (one), and may
//! be `**` (any number of folders; last, everything under). A last
//! component ending in `:name` names an alternate data stream
//! (`\$Extend\$UsnJrnl:$J`). Components compare without case, as Windows
//! compares names.

/// A parsed pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    components: Vec<Component>,
    stream: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Component {
    /// `**`: any number of components, none included.
    AnyDepth,
    /// A name, with `*` and `?` wildcards, case folded.
    Name(Vec<char>),
}

/// Why a pattern was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError(pub String);

impl Pattern {
    /// Parse a pattern: it starts at the volume root (`\`), uses `\` (or
    /// `/`) between components, and has no `.` or `..` components.
    ///
    /// # Errors
    /// When it doesn't start at the root, is empty, or walks up.
    pub fn parse(text: &str) -> Result<Self, PatternError> {
        let refuse = |why: &str| Err(PatternError(format!("{text}: {why}")));
        let Some(rest) = text.strip_prefix(['\\', '/']) else {
            return refuse("must start at the volume root (\\)");
        };
        let mut parts: Vec<&str> = rest.split(['\\', '/']).collect();
        let last = parts.pop().unwrap_or_default();
        let (last, stream) = match last.split_once(':') {
            Some((name, stream)) if !stream.is_empty() => (name, Some(stream.to_owned())),
            _ => (last, None),
        };
        parts.push(last);
        if parts
            .iter()
            .any(|p| p.is_empty() || *p == "." || *p == "..")
        {
            return refuse("empty, '.' or '..' component");
        }
        let components = parts
            .into_iter()
            .map(|part| match part {
                "**" => Component::AnyDepth,
                name => Component::Name(fold(name)),
            })
            .collect();
        Ok(Self { components, stream })
    }

    /// Whether the file at `path` (components from the volume root),
    /// stream `stream` (`None` for the default one), matches.
    #[must_use]
    pub fn matches(&self, path: &[String], stream: Option<&str>) -> bool {
        let same_stream = match (&self.stream, stream) {
            (None, None) => true,
            (Some(wanted), Some(stream)) => wanted.eq_ignore_ascii_case(stream),
            _ => false,
        };
        let path: Vec<Vec<char>> = path.iter().map(|c| fold(c)).collect();
        same_stream && components_match(&self.components, &path)
    }
}

/// `name` as compared: lower case.
fn fold(name: &str) -> Vec<char> {
    name.chars().flat_map(char::to_lowercase).collect()
}

fn components_match(pattern: &[Component], path: &[Vec<char>]) -> bool {
    match pattern.split_first() {
        None => path.is_empty(),
        // Last, `**` is everything under: at least one component.
        Some((Component::AnyDepth, [])) => !path.is_empty(),
        Some((Component::AnyDepth, rest)) => {
            (0..=path.len()).any(|skip| components_match(rest, &path[skip..]))
        }
        Some((Component::Name(name), rest)) => path
            .split_first()
            .is_some_and(|(first, others)| wildcard(name, first) && components_match(rest, others)),
    }
}

/// `*` and `?` matching, iteratively (no backtracking blow-up).
fn wildcard(pattern: &[char], name: &[char]) -> bool {
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        match pattern.get(p) {
            Some('*') => {
                star = Some((p, n));
                p += 1;
            }
            Some(&c) if c == '?' || c == name[n] => {
                p += 1;
                n += 1;
            }
            _ => match star {
                Some((star_p, star_n)) => {
                    p = star_p + 1;
                    n = star_n + 1;
                    star = Some((star_p, star_n + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> Vec<String> {
        text.split('\\').map(str::to_owned).collect()
    }

    fn matches(pattern: &str, file: &str, stream: Option<&str>) -> bool {
        Pattern::parse(pattern)
            .unwrap()
            .matches(&path(file), stream)
    }

    #[test]
    fn names_and_wildcards_without_case() {
        assert!(matches(
            r"\Windows\Prefetch\*.pf",
            r"Windows\Prefetch\CMD.EXE-0BD30981.pf",
            None
        ));
        assert!(matches(
            r"\windows\system32\config\SAM*",
            r"Windows\System32\config\SAM.LOG1",
            None
        ));
        assert!(!matches(
            r"\Windows\Prefetch\*.pf",
            r"Windows\Prefetch\Layout.ini",
            None
        ));
        assert!(matches(
            r"\Users\*\NTUSER.DAT",
            r"Users\alice\ntuser.dat",
            None
        ));
        assert!(!matches(
            r"\Users\*\NTUSER.DAT",
            r"Users\alice\Documents\NTUSER.DAT",
            None
        ));
        assert!(matches(r"\a\?b*c", r"a\xbYYc", None));
    }

    #[test]
    fn any_depth() {
        let pattern = r"\Windows\System32\Tasks\**";
        assert!(matches(pattern, r"Windows\System32\Tasks\Updater", None));
        assert!(matches(
            pattern,
            r"Windows\System32\Tasks\Microsoft\Windows\Defrag\ScheduledDefrag",
            None
        ));
        assert!(!matches(pattern, r"Windows\System32\Tasks", None));
        assert!(matches(r"\Users\**\*.lnk", r"Users\a\Desktop\x.lnk", None));
    }

    #[test]
    fn streams() {
        assert!(matches(
            r"\$Extend\$UsnJrnl:$J",
            r"$Extend\$UsnJrnl",
            Some("$J")
        ));
        assert!(!matches(
            r"\$Extend\$UsnJrnl:$J",
            r"$Extend\$UsnJrnl",
            Some("$Max")
        ));
        assert!(!matches(r"\$Extend\$UsnJrnl:$J", r"$Extend\$UsnJrnl", None));
        assert!(!matches(
            r"\Users\a\x.zip",
            r"Users\a\x.zip",
            Some("Zone.Identifier")
        ));
    }

    #[test]
    fn refused() {
        for bad in [r"Windows\x", r"\a\..\b", r"\a\\b", r"\"] {
            assert!(Pattern::parse(bad).is_err(), "{bad}");
        }
    }
}
