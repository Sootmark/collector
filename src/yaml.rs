//! Enough YAML for ForensicArtifacts' definition files: documents
//! separated by `---`, block mappings and sequences by indentation, flow
//! sequences and mappings on one line (`[Windows]`, `{key: 'a', value:
//! 'b'}`), plain, single- and double-quoted scalars, literal and folded
//! block scalars (`|`, `>`), and `#` comments. Every scalar is text;
//! anchors, tags and multi-line flow collections are refused.

/// A YAML value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Yaml {
    /// A scalar, as text.
    Text(String),
    /// A sequence.
    List(Vec<Yaml>),
    /// A mapping, keys in order.
    Map(Vec<(String, Yaml)>),
}

impl Yaml {
    /// The value of `key`, if this is a mapping that has it.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Self::Map(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The text, if this is a scalar.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    /// The items, if this is a sequence; a scalar reads as one item.
    #[must_use]
    pub fn items(&self) -> Vec<&Yaml> {
        match self {
            Self::List(items) => items.iter().collect(),
            Self::Text(_) => vec![self],
            Self::Map(_) => Vec::new(),
        }
    }
}

/// A line of a document: its indentation and its text, comments and
/// trailing blanks removed (block scalars keep theirs, from `raw`).
#[derive(Debug, Clone, Copy)]
struct Line<'a> {
    number: usize,
    indent: usize,
    text: &'a str,
    raw: &'a str,
}

/// The documents of `text`; empty ones are left out.
///
/// # Errors
/// At the first line this reader can't read, with its number.
pub fn documents(text: &str) -> Result<Vec<Yaml>, String> {
    let mut documents = Vec::new();
    let mut lines = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        if raw.trim_end() == "---" || raw.starts_with("--- ") {
            documents.extend(document(&lines)?);
            lines.clear();
            continue;
        }
        let indent = raw.len() - raw.trim_start_matches(' ').len();
        lines.push(Line {
            number,
            indent,
            text: strip_comment(raw[indent..].trim_end()),
            raw,
        });
    }
    documents.extend(document(&lines)?);
    Ok(documents)
}

fn document(lines: &[Line<'_>]) -> Result<Option<Yaml>, String> {
    let mut parser = Parser { lines, at: 0 };
    parser.skip_blank();
    if parser.at == lines.len() {
        return Ok(None);
    }
    let indent = lines[parser.at].indent;
    let value = parser.block(indent)?;
    parser.skip_blank();
    match lines.get(parser.at) {
        Some(line) => Err(format!("line {}: unexpected indentation", line.number)),
        None => Ok(Some(value)),
    }
}

struct Parser<'l, 'a> {
    lines: &'l [Line<'a>],
    at: usize,
}

impl Parser<'_, '_> {
    fn skip_blank(&mut self) {
        while self.lines.get(self.at).is_some_and(|l| l.text.is_empty()) {
            self.at += 1;
        }
    }

    /// The block at `indent`: a sequence if it starts with `- `, else a
    /// mapping, else a scalar alone.
    fn block(&mut self, indent: usize) -> Result<Yaml, String> {
        self.skip_blank();
        let line = self.lines[self.at];
        if line.text == "-" || line.text.starts_with("- ") {
            self.sequence(indent)
        } else if key_value(line.text).is_some() {
            self.mapping(indent)
        } else {
            self.at += 1;
            scalar(line.text, line.number)
        }
    }

    fn sequence(&mut self, indent: usize) -> Result<Yaml, String> {
        let mut items = Vec::new();
        loop {
            self.skip_blank();
            let Some(&line) = self.lines.get(self.at) else {
                break;
            };
            if line.indent != indent || !(line.text == "-" || line.text.starts_with("- ")) {
                break;
            }
            let rest = line.text[1..].trim_start();
            if rest.is_empty() {
                self.at += 1;
                items.push(self.nested(indent)?);
            } else if key_value(rest).is_some() {
                // `- key: value` opens a mapping indented where `key` is.
                let inner = indent + (line.text.len() - rest.len());
                self.at += 1;
                items.push(self.mapping_from(inner, Some((rest, line)))?);
            } else {
                self.at += 1;
                items.push(self.value(rest, line, indent)?);
            }
        }
        Ok(Yaml::List(items))
    }

    fn mapping(&mut self, indent: usize) -> Result<Yaml, String> {
        self.mapping_from(indent, None)
    }

    /// A mapping at `indent`, its first pair perhaps already read (after
    /// a sequence's `- `).
    fn mapping_from(
        &mut self,
        indent: usize,
        first: Option<(&str, Line<'_>)>,
    ) -> Result<Yaml, String> {
        let mut pairs = Vec::new();
        if let Some((text, line)) = first {
            pairs.push(self.pair(text, line, indent)?);
        }
        loop {
            self.skip_blank();
            let Some(&line) = self.lines.get(self.at) else {
                break;
            };
            if line.indent != indent || line.text.starts_with("- ") {
                break;
            }
            self.at += 1;
            pairs.push(self.pair(line.text, line, indent)?);
        }
        Ok(Yaml::Map(pairs))
    }

    fn pair(
        &mut self,
        text: &str,
        line: Line<'_>,
        indent: usize,
    ) -> Result<(String, Yaml), String> {
        let (key, rest) = key_value(text)
            .ok_or_else(|| format!("line {}: expected `key: value`", line.number))?;
        let Yaml::Text(key) = scalar(key, line.number)? else {
            return Err(format!("line {}: a key must be text", line.number));
        };
        let value = if rest.is_empty() {
            self.nested(indent)?
        } else {
            self.value(rest, line, indent)?
        };
        Ok((key, value))
    }

    /// The value after `key:` or `- ` on a line of its own: a block more
    /// indented, or a sequence at the same indentation (YAML lets a
    /// mapping's sequence start level with its key), or empty text.
    fn nested(&mut self, indent: usize) -> Result<Yaml, String> {
        self.skip_blank();
        match self.lines.get(self.at) {
            Some(next) if next.indent > indent => self.block(next.indent),
            Some(next) if next.indent == indent && next.text.starts_with("- ") => {
                self.sequence(indent)
            }
            _ => Ok(Yaml::Text(String::new())),
        }
    }

    /// A value given on the line: a block scalar, or one inline.
    fn value(&mut self, text: &str, line: Line<'_>, indent: usize) -> Result<Yaml, String> {
        match text {
            "|" | "|-" | ">" | ">-" => Ok(Yaml::Text(self.block_scalar(text, indent))),
            _ => scalar(text, line.number),
        }
    }

    /// The lines more indented than `indent`, as text: kept as they are
    /// (`|`) or folded into one line per paragraph (`>`).
    fn block_scalar(&mut self, style: &str, indent: usize) -> String {
        let start = self.at;
        while self
            .lines
            .get(self.at)
            .is_some_and(|l| l.raw.trim().is_empty() || l.indent > indent)
        {
            self.at += 1;
        }
        // Trailing blank lines belong to what follows.
        while self.at > start && self.lines[self.at - 1].raw.trim().is_empty() {
            self.at -= 1;
        }
        let body = &self.lines[start..self.at];
        let margin = body
            .iter()
            .filter(|l| !l.raw.trim().is_empty())
            .map(|l| l.indent)
            .min()
            .unwrap_or(0);
        let lines: Vec<&str> = body
            .iter()
            .map(|l| l.raw.get(margin..).unwrap_or("").trim_end())
            .collect();
        let mut text = if style.starts_with('>') {
            lines
                .split(|l| l.is_empty())
                .map(|paragraph| paragraph.join(" "))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            lines.join("\n")
        };
        if !style.ends_with('-') && !text.is_empty() {
            text.push('\n');
        }
        text
    }
}

/// `key: value` (or `key:` alone) outside quotes and flow collections:
/// the key and the rest, trimmed.
fn key_value(text: &str) -> Option<(&str, &str)> {
    let mut quote = None;
    let mut depth = 0usize;
    for (at, c) in text.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            // Quotes open a quoted key, or text inside a flow collection.
            (None, '\'' | '"') if at == 0 || depth > 0 => quote = Some(c),
            (None, '[' | '{') if at == 0 || depth > 0 => depth += 1,
            (None, ']' | '}') => depth = depth.saturating_sub(1),
            (None, ':') if depth == 0 => {
                let rest = &text[at + 1..];
                if rest.is_empty() || rest.starts_with(' ') {
                    return Some((text[..at].trim(), rest.trim()));
                }
            }
            _ => {}
        }
    }
    None
}

/// The line without a `#` comment (one after a blank, outside quotes).
fn strip_comment(text: &str) -> &str {
    let mut quote = None;
    let mut previous = ' ';
    for (at, c) in text.char_indices() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '\'' | '"') => quote = Some(c),
            (None, '#') if previous == ' ' => return text[..at].trim_end(),
            _ => {}
        }
        previous = c;
    }
    text
}

/// An inline value: a flow collection or a scalar.
fn scalar(text: &str, number: usize) -> Result<Yaml, String> {
    let mut flow = Flow {
        chars: text.chars().collect(),
        at: 0,
        number,
    };
    let value = flow.value(false)?;
    flow.blanks();
    if flow.at != flow.chars.len() {
        return Err(format!("line {number}: unexpected text after a value"));
    }
    Ok(value)
}

/// A one-line flow value, read character by character.
struct Flow {
    chars: Vec<char>,
    at: usize,
    number: usize,
}

impl Flow {
    fn fail<T>(&self, why: &str) -> Result<T, String> {
        Err(format!("line {}: {why}", self.number))
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn blanks(&mut self) {
        while self.peek() == Some(' ') {
            self.at += 1;
        }
    }

    /// A value; `inner`: inside a flow collection, where `,`, `]`, `}`
    /// and `:` end a plain scalar.
    fn value(&mut self, inner: bool) -> Result<Yaml, String> {
        self.blanks();
        match self.peek() {
            Some('[') => self.list(),
            Some('{') => self.map(),
            Some('\'') => self.single_quoted().map(Yaml::Text),
            Some('"') => self.double_quoted().map(Yaml::Text),
            Some('&' | '*' | '!') => self.fail("anchors, aliases and tags are not read"),
            _ => Ok(Yaml::Text(self.plain(inner))),
        }
    }

    fn plain(&mut self, inner: bool) -> String {
        let start = self.at;
        while let Some(c) = self.peek() {
            let ends = inner
                && (matches!(c, ',' | ']' | '}')
                    || (c == ':' && matches!(self.chars.get(self.at + 1), None | Some(' '))));
            if ends {
                break;
            }
            self.at += 1;
        }
        self.chars[start..self.at]
            .iter()
            .collect::<String>()
            .trim_end()
            .to_owned()
    }

    fn single_quoted(&mut self) -> Result<String, String> {
        self.at += 1;
        let mut text = String::new();
        loop {
            match self.peek() {
                None => return self.fail("unterminated quoted text"),
                Some('\'') if self.chars.get(self.at + 1) == Some(&'\'') => {
                    text.push('\'');
                    self.at += 2;
                }
                Some('\'') => {
                    self.at += 1;
                    return Ok(text);
                }
                Some(c) => {
                    text.push(c);
                    self.at += 1;
                }
            }
        }
    }

    fn double_quoted(&mut self) -> Result<String, String> {
        self.at += 1;
        let mut text = String::new();
        loop {
            let Some(c) = self.peek() else {
                return self.fail("unterminated quoted text");
            };
            self.at += 1;
            match c {
                '"' => return Ok(text),
                '\\' => {
                    let Some(escaped) = self.peek() else {
                        return self.fail("unterminated quoted text");
                    };
                    self.at += 1;
                    text.push(match escaped {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        '0' => '\0',
                        other => other,
                    });
                }
                c => text.push(c),
            }
        }
    }

    fn list(&mut self) -> Result<Yaml, String> {
        self.at += 1;
        let mut items = Vec::new();
        loop {
            self.blanks();
            if self.peek() == Some(']') {
                self.at += 1;
                return Ok(Yaml::List(items));
            }
            items.push(self.value(true)?);
            self.blanks();
            match self.peek() {
                Some(',') => self.at += 1,
                Some(']') => {}
                _ => {
                    return self
                        .fail("expected `,` or `]` (multi-line flow sequences are not read)")
                }
            }
        }
    }

    fn map(&mut self) -> Result<Yaml, String> {
        self.at += 1;
        let mut pairs = Vec::new();
        loop {
            self.blanks();
            if self.peek() == Some('}') {
                self.at += 1;
                return Ok(Yaml::Map(pairs));
            }
            let Yaml::Text(key) = self.value(true)? else {
                return self.fail("a key must be text");
            };
            self.blanks();
            if self.peek() != Some(':') {
                return self.fail("expected `:` in a flow mapping");
            }
            self.at += 1;
            let value = self.value(true)?;
            pairs.push((key, value));
            self.blanks();
            match self.peek() {
                Some(',') => self.at += 1,
                Some('}') => {}
                _ => {
                    return self.fail("expected `,` or `}` (multi-line flow mappings are not read)")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> Yaml {
        Yaml::Text(value.to_owned())
    }

    #[test]
    fn a_definition() {
        let docs = documents(
            "# Comment.\n---\nname: WindowsPrefetchFiles\ndoc: |\n  Prefetch.\n\n  Second paragraph.\nsources:\n- type: FILE\n  attributes:\n    paths: ['%%environ_systemroot%%\\Prefetch\\*.pf']\n    separator: '\\'\nsupported_os: [Windows]\n---\nname: B\nsources:\n- type: ARTIFACT_GROUP\n  attributes: {names: ['A', \"B\"]}\n",
        )
        .unwrap();
        assert_eq!(docs.len(), 2);
        let first = &docs[0];
        assert_eq!(first.get("name"), Some(&text("WindowsPrefetchFiles")));
        assert_eq!(
            first.get("doc"),
            Some(&text("Prefetch.\n\nSecond paragraph.\n"))
        );
        let source = first.get("sources").unwrap().items()[0];
        assert_eq!(source.get("type"), Some(&text("FILE")));
        let attributes = source.get("attributes").unwrap();
        assert_eq!(
            attributes.get("paths"),
            Some(&Yaml::List(vec![text(
                r"%%environ_systemroot%%\Prefetch\*.pf"
            )]))
        );
        assert_eq!(attributes.get("separator"), Some(&text("\\")));
        assert_eq!(
            first.get("supported_os"),
            Some(&Yaml::List(vec![text("Windows")]))
        );
        let group = docs[1].get("sources").unwrap().items()[0];
        assert_eq!(
            group.get("attributes").and_then(|a| a.get("names")),
            Some(&Yaml::List(vec![text("A"), text("B")]))
        );
    }

    #[test]
    fn nested_sequences_and_quotes() {
        let docs = documents(
            "urls:\n  - 'it''s'\n  - plain text: no # a comment\nkey_value_pairs:\n- {key: 'HKEY_USERS\\%%users.sid%%\\{AB}', value: 'v'}\n- {a: [x], b: y}\ndoc: >\n  folded\n  lines\n",
        )
        .unwrap();
        let urls = docs[0].get("urls").unwrap().items();
        assert_eq!(urls[0], &text("it's"));
        assert_eq!(urls[1].get("plain text"), Some(&text("no")));
        let pairs = docs[0].get("key_value_pairs").unwrap().items();
        assert_eq!(pairs[0].get("value"), Some(&text("v")));
        assert_eq!(pairs[1].get("b"), Some(&text("y")));
        assert_eq!(docs[0].get("doc"), Some(&text("folded lines\n")));
    }

    #[test]
    fn what_isnt_read_is_an_error() {
        assert!(documents("a: [1,\n  2]\n").is_err());
        assert!(documents("a: &anchor x\n").is_err());
        assert!(documents("a: 'open\n").is_err());
        assert!(documents("a: b\n    c: d\n").is_err());
        assert_eq!(
            documents("---\n# only a comment\n---\n").unwrap(),
            Vec::new()
        );
    }
}
