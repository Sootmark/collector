//! Running a plan: every file a rule names, streamed from the volume into
//! the archive under `<drive>/<path>` (the layout KAPE uses, so tools that
//! read KAPE output read this), hashed on the way, and listed in
//! `manifest.jsonl`; then `outcome.json`, what the run was.
//!
//! Every rule appears in the manifest: what it collected, or that it found
//! nothing. A file two rules name is collected once, by the first.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::json::Json;
use common::sha256::{hex, Sha256};
use common::time::Ts;
use disk::{FileEntry, Times};

use crate::command::{self, Ran};
use crate::limits::{Applied, Limits};
use crate::plan::{Plan, Rule, What};
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
    /// The signed job run, for the record: its case, signer and the
    /// signer's key fingerprint.
    pub job: Option<JobRecord>,
    /// The keys the archive is encrypted to (`age1…`), for the record.
    pub recipients: Vec<String>,
    /// Collecting from the running host (not a disk image): command rules
    /// run only then.
    pub live: bool,
    /// The resource limits asked for and whether they took effect, for
    /// the record.
    pub limits: Option<(Limits, Applied)>,
}

/// What `outcome.json` says of the job a run carried out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRecord {
    /// The case it was prepared for.
    pub case: String,
    /// Who signed it.
    pub issuer: String,
    /// Their key's fingerprint.
    pub fingerprint: String,
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
    let mut taken: HashSet<(Vec<String>, Option<String>)> = HashSet::new();
    for rule in &plan.rules {
        let late = options.deadline.is_some_and(|d| Instant::now() >= d);
        match &rule.what {
            What::Files {
                paths,
                max_bytes,
                skip_leading_zeros,
            } => {
                let mut matched: Vec<&FileEntry> = files
                    .iter()
                    .filter(|f| {
                        paths
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
                    if !taken.insert((file.path.clone(), file.stream.clone())) {
                        continue;
                    }
                    let line = if options.deadline.is_some_and(|d| Instant::now() >= d) {
                        summary.skipped += 1;
                        listing(
                            rule,
                            file,
                            options.drive,
                            volume.method(),
                            "skipped_limit",
                            None,
                            Some("deadline reached"),
                        )
                    } else {
                        let how = Copying {
                            limit: max_bytes.unwrap_or(u64::MAX),
                            skip_zeros: *skip_leading_zeros,
                        };
                        copy(
                            volume,
                            &mut archive,
                            rule,
                            file,
                            options.drive,
                            how,
                            &mut summary,
                        )
                    };
                    manifest.push(line);
                }
            }
            What::Command {
                argv,
                output,
                timeout_seconds,
            } => {
                let skipped = |why: &str| {
                    Json::object([
                        ("rule", Json::from(rule.id.as_str())),
                        ("command", Json::from(argv.join(" ").as_str())),
                        ("status", Json::from("skipped")),
                        ("why", Json::from(why)),
                    ])
                };
                let line = if !options.live {
                    skipped("not a live collection: a command describes the running host")
                } else if late {
                    summary.skipped += 1;
                    skipped("deadline reached")
                } else {
                    let ran = command::run(argv, Duration::from_secs(*timeout_seconds));
                    store_output(&mut archive, rule, argv, output, &ran, &mut summary)?
                };
                manifest.push(line);
            }
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

/// How a file is copied.
#[derive(Debug, Clone, Copy)]
struct Copying {
    /// Most bytes kept.
    limit: u64,
    /// Whether the whole zero pages it starts with are dropped.
    skip_zeros: bool,
}

/// What a command printed, into the archive as `live/<output>`; its
/// manifest line.
fn store_output<W: Write>(
    archive: &mut zip::Writer<W>,
    rule: &Rule,
    argv: &[String],
    output: &str,
    ran: &Ran,
    summary: &mut Summary,
) -> io::Result<Json> {
    let stored = format!("live/{output}");
    let mut line = Json::object([
        ("rule", Json::from(rule.id.as_str())),
        ("command", Json::from(argv.join(" ").as_str())),
        ("method", Json::from("command")),
    ]);
    if let Some(started) = ran.started.to_iso8601() {
        push(&mut line, "started", Json::from(started.as_str()));
    }
    push(
        &mut line,
        "duration_ms",
        Json::from(ran.duration.as_millis() as u64),
    );
    let status = match (&ran.failure, ran.exit_code) {
        (None, Some(0)) => "ok",
        _ => "error",
    };
    if let Some(code) = ran.exit_code {
        push(&mut line, "exit_code", Json::from(i64::from(code)));
    }
    if let Some(why) = &ran.failure {
        push(&mut line, "why", Json::from(why.as_str()));
    }
    if !ran.stderr.is_empty() {
        push(
            &mut line,
            "stderr",
            Json::from(String::from_utf8_lossy(&ran.stderr).trim()),
        );
    }
    if ran.stdout.is_empty() && ran.failure.is_some() {
        summary.errors += 1;
        push(&mut line, "status", Json::from(status));
        return Ok(line);
    }
    let entry = archive.add(&stored, None, &mut ran.stdout.as_slice())?;
    summary.bytes += entry.size;
    if status == "ok" {
        summary.collected += 1;
    } else {
        summary.errors += 1;
    }
    push(&mut line, "status", Json::from(status));
    push(&mut line, "stored", Json::from(stored.as_str()));
    push(&mut line, "collected_bytes", Json::from(entry.size));
    push(
        &mut line,
        "sha256",
        Json::from(hex(&Sha256::digest(&ran.stdout)).as_str()),
    );
    Ok(line)
}

/// Stream `file` into the archive; its manifest line.
fn copy<W: Write>(
    volume: &mut Volume,
    archive: &mut zip::Writer<W>,
    rule: &Rule,
    file: &FileEntry,
    drive: char,
    how: Copying,
    summary: &mut Summary,
) -> Json {
    let name = stored_name(drive, file);
    let limit = how.limit;
    // What reached the archive: its size and hash, and the read error
    // that cut it short, if any.
    let mut written: Option<(u64, [u8; 32], Option<String>)> = None;
    let mut skipped = 0;
    let read = volume.read(file, &mut |content| {
        let limited = content.take(limit);
        let mut zeros = SkipZeros::new(limited, how.skip_zeros);
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
            let mut line = listing(
                rule,
                file,
                drive,
                volume.method(),
                status,
                Some(&name),
                why.as_deref(),
            );
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
            listing(
                rule,
                file,
                drive,
                volume.method(),
                "error",
                None,
                Some(&why),
            )
        }
    }
}

/// A manifest line for `file`: where it was, its times and size, and what
/// became of it.
fn listing(
    rule: &Rule,
    file: &FileEntry,
    drive: char,
    method: &str,
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
        ("method", Json::from(method)),
    ]);
    if method == "raw-ntfs" {
        push(&mut line, "mft_record", Json::from(file.record));
    }
    push(&mut line, "size", Json::from(file.size));
    push(&mut line, "status", Json::from(status));
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
        (
            "job",
            options.job.as_ref().map_or(Json::Null, |job| {
                Json::object([
                    ("case", Json::from(job.case.as_str())),
                    ("issuer", Json::from(job.issuer.as_str())),
                    ("fingerprint", Json::from(job.fingerprint.as_str())),
                ])
            }),
        ),
        (
            "limits",
            options
                .limits
                .as_ref()
                .map_or(Json::Null, |(limits, applied)| {
                    let applied = match applied {
                        Applied::Yes => "yes".to_owned(),
                        Applied::No(why) => format!("no: {why}"),
                        Applied::NotWindows => "no: not a Windows host".to_owned(),
                    };
                    Json::object([
                        ("cpu_percent", Json::from(u64::from(limits.cpu_percent))),
                        ("max_memory_mib", Json::from(limits.max_memory_mib)),
                        ("applied", Json::from(applied.as_str())),
                    ])
                }),
        ),
        (
            "encrypted_to",
            Json::Array(
                options
                    .recipients
                    .iter()
                    .map(|r| Json::from(r.as_str()))
                    .collect(),
            ),
        ),
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

pub(crate) fn now() -> Ts {
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
        journal.extend(std::iter::repeat_n(0, PAGE));
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
