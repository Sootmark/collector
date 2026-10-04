# collector

A forensic triage collector for Windows, open source so what runs on your hosts can be read. It reads the NTFS volume raw, through `sootmark-disk`'s reader, so the files Windows keeps open and no copy API reaches (`$MFT`, `$UsnJrnl:$J`, `$LogFile`, the registry hives and their transaction logs, Amcache, SRUM) are collected like any other, and streams what a plan names into one zip with a hashed manifest. Nothing is written to the collected volume.

```text
sootmark-collector collect --output E:\cases\ws042.zip
sootmark-collector collect --output E:\ws042.zip --plan my-plan.json --deadline 30
sootmark-collector collect --output triage.zip --image disk.raw
```

Run it as an administrator (raw volume access needs it), and write the archive to another volume than the one collected.

## What you get

- **The archive**, a zip (zip64 past 4 GiB or 65,535 files):
  - every collected file under `C/<path>`, the layout KAPE uses, so tools that read KAPE output read this; the USN journal as `C/$Extend/$J` (without its zeroed start), other alternate data streams as `<file>%3A<stream>`; each entry carries the file's NTFS modification time;
  - `manifest.jsonl`: one line per file — rule, path on the host, how it was read (`raw-ntfs`), MFT record, size, `$STANDARD_INFORMATION` times, SHA-256, and its status: `ok`, `partial` (cut at the rule's `max_bytes`), `error` (with why), `skipped_limit` (not reached before the deadline) — and one line for each rule that found nothing (`not_found`), so a gap is never silent;
  - `outcome.json`: the collector's version, the plan's name and SHA-256, host, source, start and end, and counts.
- **The plan**, JSON, closed and typed: rules with an id, a title, path patterns from the volume root (`*` and `?` in names, `**` for any depth, `:stream` for an alternate data stream, without case) an optional `max_bytes`, and `skip_leading_zeros` (drop the whole zero pages a file starts with, as a USN journal's freed start often is for gigabytes; the manifest records how many, and every USN record carries its own position anyway). The built-in plan (`--print-plan`) is a Windows triage: `$MFT`, `$LogFile`, `$UsnJrnl:$J`, system and user hives with their logs, Amcache, event logs, Prefetch, SRUM, scheduled tasks, LNK files and jump lists, PowerShell history, startup folders, the WMI repository. A file two rules name is collected once.
- **A deadline** (`--deadline <minutes>`): past it, files not yet reached are listed as skipped and the archive is closed, valid.
- Large files are streamed, never copied to a temporary file or held in memory; hashes are computed on the way.

Not yet: a signed job file (the plan, recipients and expiry signed by the case), encryption to the case's public key, resource limits through a Job Object and below-normal priority, volatile state (processes, connections, sessions, services), the OS API for volumes that aren't NTFS, and collecting what parsed artifacts point to.

## How it's checked

- The synthetic FIN-WKS-07 disk (made by `sootmark-disk`'s `make-samples.py`; `tests/fixtures/`): files read raw into the archive, a file's SHA-256 against The Sleuth Kit's `icat`, an alternate data stream stored apart, a file cut at `max_bytes`, a file named by two rules collected once, rules that found nothing listed.
- On a real Windows volume in CI: the runner's `C:` collected raw with the built-in plan, the archive tested with Python's `zipfile`, and `$MFT`, `$J`, the `SYSTEM` hive and event logs required.
- Unit tests for path patterns and for reading a raw device in aligned blocks (Windows refuses unaligned reads).

## Licence

MIT or Apache-2.0, at your option.
