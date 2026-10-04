//! Running a plan: every file a rule names, streamed from the volume into
//! the archive under `<drive>/<path>` (the layout KAPE uses, so tools that
//! read KAPE output read this), hashed on the way, and listed in
//! `manifest.jsonl`; then `outcome.json`, what the run was.
//!
//! Every rule appears in the manifest: what it collected, or that it found
//! nothing. A file two rules name is collected once, by the first.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use common::json::Json;
use common::sha256::{hex, Sha256};
use common::time::Ts;
use disk::{FileEntry, Times};

use crate::plan::{Plan, Rule};
use crate::volume::Volume;

/// The archive's record of each file.
pub const MANIFEST: &str = "manifest.jsonl";
/// The archive's record of the run.
pub const OUTCOME: &str = "outcome.json";

/// How a run is done.
#[derive(Debug, Clone)]
pub struct Options {
    /// The volume's drive letter, for paths and the archive layout.
    pub drive: char,
    /// The host's name, for the record.
    pub host: String,
    /// When to stop collecting: files not reached by then are listed as
    /// skipped, and the archive closed.
    pub deadline: Option<Instant>,
}

/// What a run collected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Files collected whole.
    pub collected: u64,
    /// Files stored incomplete: cut at their rule's `max_bytes`, or a
    /// read that stopped part-way.
    pub partial: u64,
    /// Bytes written.
    pub bytes: u64,
    /// Files that couldn't be read.
    pub errors: u64,
    /// Files not reached before the deadline.
    pub skipped: u64,
    /// Rules that found nothing.
    pub not_found: u64,
}

/// Run `plan` on `volume`, writing the archive to `out`.
///
/// # Errors
/// When the volume can't be listed or the archive can't be written. A file
/// that can't be read is not an error: it is listed with why.
pub fn collect<W: Write>(
    volume: &mut Volume,
    plan: &Plan,
    options: &Options,
    out: W,
) -> io::Result<(W, Summary)> {
    let started = now();
    let files = volume.files()?;
    let mut archive = zip::Writer::new(out);
    let mut manifest = Vec::new();
    let mut summary = Summary::default();
    let mut taken: HashSet<(u64, Option<String>)> = HashSet::new();
    for rule in &plan.rules {
        let mut matched: Vec<&FileEntry> = files
            .iter()
            .filter(|f| {
                rule.paths
                    .iter()
                    .any(|p| p.matches(&f.path, f.stream.as_deref()))
            })
            .collect();
        matched.sort_by_key(|f| f.display_path());
        if matched.is_empty() {
            summary.not_found += 1;
            manifest.push(Json::object([
                ("rule", Json::from(rule.id.as_str())),
                ("status", Json::from("not_found")),
            ]));
        }
        for file in matched {
            if !taken.insert((file.record, file.stream.clone())) {
                continue;
            }
            let line = if options.deadline.is_some_and(|d| Instant::now() >= d) {
                summary.skipped += 1;
                listing(
                    rule,
                    file,
                    options.drive,
                    "skipped_limit",
                    None,
                    Some("deadline reached"),
                )
            } else {
                copy(
                    volume,
                    &mut archive,
                    rule,
                    file,
                    options.drive,
                    &mut summary,
                )
            };
            manifest.push(line);
        }
    }
    let mut lines = String::new();
    for line in &manifest {
        lines.push_str(&line.to_string());
        lines.push('\n');
    }
    archive.add(MANIFEST, None, &mut lines.as_bytes())?;
    let outcome = outcome(plan, options, volume, &summary, started);
    archive.add(OUTCOME, None, &mut outcome.to_pretty().as_bytes())?;
    Ok((archive.finish()?, summary))
}

/// Stream `file` into the archive; its manifest line.
fn copy<W: Write>(
    volume: &mut Volume,
    archive: &mut zip::Writer<W>,
    rule: &Rule,
    file: &FileEntry,
    drive: char,
    summary: &mut Summary,
) -> Json {
    let name = stored_name(drive, file);
    let limit = rule.max_bytes.unwrap_or(u64::MAX);
    // What reached the archive: its size and hash, and the read error
    // that cut it short, if any.
    let mut written: Option<(u64, [u8; 32], Option<String>)> = None;
    let mut skipped = 0;
    let read = volume.read(file, &mut |content| {
        let limited = content.take(limit);
        let mut zeros = SkipZeros::new(limited, rule.skip_leading_zeros);
        let mut hashing = Hashing::new(&mut zeros);
        let added = archive.add(&name, file.times.modified, &mut hashing);
        let sha256 = hashing.finish();
        skipped = zeros.skipped;
        match added {
            Ok(entry) => written = Some((entry.size, sha256, None)),
            Err(error) => match zip::write::Truncated::of(&error) {
                Some(truncated) => {
                    written = Some((truncated.entry.size, sha256, Some(error.to_string())));
                }
                None => return Err(error),
            },
        }
        Ok(())
    });
    match (read, written) {
        (Ok(()), Some((size, sha256, read_error))) => {
            let read_bytes = skipped + size;
            let cut = read_error.is_none() && file.size > read_bytes && read_bytes == limit;
            summary.bytes += size;
            let why = match (&read_error, cut) {
                (Some(error), _) => Some(format!("read stopped: {error}")),
                (None, true) => Some("cut at the rule's max_bytes".to_owned()),
                (None, false) => None,
            };
            let status = if why.is_some() {
                summary.partial += 1;
                "partial"
            } else {
                summary.collected += 1;
                "ok"
            };
            let mut line = listing(rule, file, drive, status, Some(&name), why.as_deref());
            push(&mut line, "collected_bytes", Json::from(size));
            if skipped > 0 {
                // The stored copy starts this far into the file.
                push(&mut line, "skipped_leading_zeros", Json::from(skipped));
            }
            push(&mut line, "sha256", Json::from(hex(&sha256).as_str()));
            line
        }
        (result, _) => {
            summary.errors += 1;
            let why = result
                .err()
                .map_or_else(|| "not read".to_owned(), |e| e.to_string());
            listing(rule, file, drive, "error", None, Some(&why))
        }
    }
}

/// A manifest line for `file`: where it was, its times and size, and what
/// became of it.
fn listing(
    rule: &Rule,
    file: &FileEntry,
    drive: char,
    status: &str,
    stored: Option<&str>,
    why: Option<&str>,
) -> Json {
    let mut line = Json::object([
        ("rule", Json::from(rule.id.as_str())),
        (
            "path",
            Json::from(format!("{drive}:\\{}", file.display_path()).as_str()),
        ),
        ("method", Json::from("raw-ntfs")),
        ("mft_record", Json::from(file.record)),
        ("size", Json::from(file.size)),
        ("status", Json::from(status)),
    ]);
    if let Some(stored) = stored {
        push(&mut line, "stored", Json::from(stored));
    }
    if let Some(why) = why {
        push(&mut line, "why", Json::from(why));
    }
    times(&mut line, &file.times);
    line
}

fn times(line: &mut Json, times: &Times) {
    for (name, time) in [
        ("created", times.created),
        ("modified", times.modified),
        ("changed", times.changed),
        ("accessed", times.accessed),
    ] {
        if let Some(text) = time.and_then(|t| t.to_iso8601()) {
            push(line, name, Json::from(text.as_str()));
        }
    }
}

fn push(object: &mut Json, name: &str, value: Json) {
    if let Json::Object(members) = object {
        members.push((name.to_owned(), value));
    }
}

/// Where `file` goes in the archive: `C/Windows/…`. The USN journal is
/// `C/$Extend/$J`, as KAPE stores it; other alternate data streams get
/// `%3A` and their name (`x.zip%3AZone.Identifier`).
fn stored_name(drive: char, file: &FileEntry) -> String {
    let mut path = file.path.join("/");
    match file.stream.as_deref() {
        Some("$J")
            if file
                .path
                .last()
                .is_some_and(|n| n.eq_ignore_ascii_case("$UsnJrnl")) =>
        {
            let folder = file.path[..file.path.len() - 1].join("/");
            path = format!("{folder}/$J");
        }
        Some(stream) => path = format!("{path}%3A{stream}"),
        None => {}
    }
    format!("{drive}/{path}")
}

fn outcome(
    plan: &Plan,
    options: &Options,
    volume: &Volume,
    summary: &Summary,
    started: Ts,
) -> Json {
    let text = |ts: Ts| Json::from(ts.to_iso8601().unwrap_or_default().as_str());
    Json::object([
        ("collector", Json::from("sootmark-collector")),
        ("version", Json::from(crate::VERSION)),
        (
            "plan",
            Json::object([
                ("name", Json::from(plan.name.as_str())),
                ("sha256", Json::from(plan.sha256.as_str())),
            ]),
        ),
        ("host", Json::from(options.host.as_str())),
        ("source", Json::from(volume.source.as_str())),
        ("drive", Json::from(options.drive.to_string().as_str())),
        ("started", text(started)),
        ("finished", text(now())),
        ("collected", Json::from(summary.collected)),
        ("partial", Json::from(summary.partial)),
        ("bytes", Json::from(summary.bytes)),
        ("errors", Json::from(summary.errors)),
        ("skipped_limit", Json::from(summary.skipped)),
        ("rules_not_found", Json::from(summary.not_found)),
    ])
}

fn now() -> Ts {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros());
    Ts::from_unix_micros(i64::try_from(micros).unwrap_or(i64::MAX))
}

/// Pages a file's leading zeros are skipped in: a USN journal's freed
/// pages are whole 4 KiB pages.
const PAGE: usize = 4096;

/// A reader that, when asked, drops the whole zero pages its content
/// starts with (a USN journal's freed, sparse start: often gigabytes),
/// counting them.
struct SkipZeros<R> {
    inner: R,
    /// Still looking for the first page that isn't zeros.
    skipping: bool,
    /// Bytes dropped.
    skipped: u64,
    /// The first page with data, not yet handed on.
    pending: Vec<u8>,
}

impl<R: Read> SkipZeros<R> {
    fn new(inner: R, skip: bool) -> Self {
        Self {
            inner,
            skipping: skip,
            skipped: 0,
            pending: Vec::new(),
        }
    }

    /// Drop zero pages up to the first that holds data, kept in `pending`.
    fn skip(&mut self) -> io::Result<()> {
        let mut page = vec![0; PAGE];
        while self.skipping {
            let mut filled = 0;
            while filled < PAGE {
                match self.inner.read(&mut page[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            let page = &page[..filled];
            if filled == PAGE && page.iter().all(|&b| b == 0) {
                self.skipped += PAGE as u64;
                continue;
            }
            self.pending = page.to_vec();
            self.skipping = false;
        }
        Ok(())
    }
}

impl<R: Read> Read for SkipZeros<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.skip()?;
        if self.pending.is_empty() {
            return self.inner.read(buf);
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

/// A reader that hashes what passes through it.
struct Hashing<R> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> Hashing<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finish(self) -> [u8; 32] {
        self.hasher.finalize()
    }
}

impl<R: Read> Read for Hashing<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn through(content: &[u8], skip: bool) -> (Vec<u8>, u64) {
        let mut reader = SkipZeros::new(content, skip);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        (out, reader.skipped)
    }

    #[test]
    fn leading_zero_pages_are_dropped_and_counted() {
        let mut journal = vec![0; 3 * PAGE];
        journal.extend_from_slice(&[0, 0, 7, 8]);
        journal.extend(std::iter::repeat(0).take(PAGE));
        let (out, skipped) = through(&journal, true);
        assert_eq!(skipped, 3 * PAGE as u64);
        assert_eq!(
            out,
            &journal[3 * PAGE..],
            "zeros after the first data are kept"
        );
    }

    #[test]
    fn only_when_asked_and_only_whole_pages() {
        let journal = vec![0; 2 * PAGE + 10];
        assert_eq!(through(&journal, false), (journal.clone(), 0));
        let (out, skipped) = through(&journal, true);
        assert_eq!((out.len(), skipped), (10, 2 * PAGE as u64));
        assert_eq!(through(&[], true), (Vec::new(), 0));
    }
}
