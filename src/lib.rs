//! A forensic triage collector for Windows.
//!
//! It reads the NTFS volume raw, with `sootmark-disk`'s reader, so files
//! Windows keeps open and no API copies (`$MFT`, `$UsnJrnl:$J`, the
//! registry hives and their logs) are collected like any other, with their
//! MFT times. A [`Plan`] names the files; [`collect`] streams each into one
//! zip under `C/<path>`, hashed, and lists every file and every rule in
//! `manifest.jsonl`: collected, cut, unreadable, skipped at the deadline,
//! or not found. Nothing is written to the collected volume.

mod collect;
mod command;
mod follow;
mod job;
mod limits;
mod pattern;
mod plan;
mod volume;

pub use collect::{collect, JobRecord, Options, Summary, MANIFEST, OUTCOME};
pub use job::{Job, JobError, SIGNED_PREFIX};
pub use limits::{apply as apply_limits, Applied, Limits};
pub use pattern::{Pattern, PatternError};
pub use plan::{Plan, PlanError, Rule, What, DEFAULT as DEFAULT_PLAN};
pub use volume::{Disk, Volume};

/// This collector's version, recorded in every archive.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
