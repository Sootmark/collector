# collector

A forensic triage collector for Windows, open source so what runs on your hosts can be read. It reads the NTFS volume raw, through `sootmark-disk`'s reader, so the files Windows keeps open and no copy API reaches (`$MFT`, `$UsnJrnl:$J`, `$LogFile`, the registry hives and their transaction logs, Amcache, SRUM) are collected like any other, and streams what a plan names into one zip with a hashed manifest. Nothing is written to the collected volume.

```text
sootmark-collector collect --job job.json --output E:\cases\ws042.zip.age
sootmark-collector collect --output E:\cases\ws042.zip
sootmark-collector collect --output E:\ws042.zip --plan my-plan.json --deadline 30
sootmark-collector collect --output triage.zip --image disk.raw
```

Run it as an administrator (raw volume access needs it), and write the archive to another volume than the one collected. A volume that isn't NTFS (ReFS, FAT, exFAT, a share) is collected with `--path E:\`, through the file API: the manifest says so (`os-api`), and files held open there are listed as unreadable, with why.

A **job** is how a case asks for a collection: the workbench writes it with the plan, the case's key and an expiry, and signs it with the analyst's key. The collector refuses a job that was changed, has expired or is dated in the future, and shows who signed it and the key's fingerprint, for whoever runs it to confirm. The archive is then encrypted to the case in the [age](https://age-encryption.org) format (`sootmark-age`): only the case can read it, with Sootmark or the standard `age` tool. Without a job, `--recipient age1…` encrypts to a key you give; with neither, the collector warns that the archive is not encrypted.

## What you get

- **The archive**, a zip (zip64 past 4 GiB or 65,535 files):
  - every collected file under `C/<path>`, the layout KAPE uses, so tools that read KAPE output read this; the USN journal as `C/$Extend/$J` (without its zeroed start), other alternate data streams as `<file>%3A<stream>`; each entry carries the file's NTFS modification time;
  - `live/…`: the running host's state, from the plan's commands, first (it changes fastest): processes with command lines, owners and start times, TCP connections and UDP endpoints with their processes, services with their binaries and accounts, the DNS cache and logon sessions (interactive, remote desktop, cached) with their accounts (JSON from PowerShell, times in UTC);
  - `manifest.jsonl`: one line per file — rule, path on the host, how it was read (`raw-ntfs`), MFT record, size, `$STANDARD_INFORMATION` times, SHA-256, and its status: `ok`, `partial` (cut at the rule's `max_bytes`), `error` (with why), `skipped_limit` (not reached before the deadline) — and one line for each rule that found nothing (`not_found`), so a gap is never silent;
  - `outcome.json`: the collector's version, the plan's name and SHA-256, host, source, start and end, and counts.
- **The plan**, JSON, closed and typed: rules with an id, a title, path patterns from the volume root (`*` and `?` in names, `**` for any depth, `:stream` for an alternate data stream, without case), an optional `max_bytes` and `skip_leading_zeros` (drop the whole zero pages a file starts with, as a USN journal's freed start often is for gigabytes; the manifest records how many, and every USN record carries its own position anyway). A rule can follow the live outputs (`follow`: the command rules whose outputs name executables, the processes' images and the services' binaries; `exclude`: path patterns; `max_bytes`): what they name is collected from the volume, so an implant's binary comes in without being named in advance; the built-in plan collects those outside `\Windows`, `\Program Files` and Windows Defender's own folder. A process reported under an 8.3 short path (`C:\Users\RUNNER~1\…`) is matched by its long name, from the volume's own names. A rule can instead run a command (`command`: the program and its arguments, run without a shell; `output`: the file name under `live/`; `timeout_seconds`): commands run on a live host only, are stopped at their time, and their exit code, error output and duration are in the manifest. The built-in plan (`--print-plan`) is a Windows triage: the live state above, then `$MFT`, `$LogFile`, `$UsnJrnl:$J`, system and user hives with their logs, Amcache, event logs, Prefetch, SRUM, scheduled tasks, LNK files and jump lists, PowerShell history, startup folders, the WMI repository. A file two rules name is collected once.
- **Light on the host**, as DFIR-ORC is: background priority (lowest CPU, disk and memory priority, so the host's own work goes first) and a Job Object capping the collector's CPU share (`--cpu`, 50 % by default) and memory (`--max-memory`, 4096 MiB), which the commands it runs inherit, and which ends them if the collector dies. `outcome.json` records the limits and whether they took effect; if they can't be applied, the run goes on and says so. These few Windows calls (`src/limits.rs`, through Microsoft's `windows-sys` declarations) are the crate's only `unsafe` code.
- **A deadline** (`--deadline <minutes>`): past it, files not yet reached are listed as skipped and the archive is closed, valid.
- Large files are streamed, never copied to a temporary file or held in memory; hashes are computed on the way.

Not yet: following what the collected artifacts themselves point to (Prefetch, scheduled tasks, Run keys), and checking binaries' signatures.

## How it's checked

- The synthetic FIN-WKS-07 disk (made by `sootmark-disk`'s `make-samples.py`; `tests/fixtures/`): files read raw into the archive, a file's SHA-256 against The Sleuth Kit's `icat`, an alternate data stream stored apart, a file cut at `max_bytes`, a file named by two rules collected once, rules that found nothing listed.
- On a real Windows volume in CI: the runner's `C:` collected raw with the built-in plan, the archive tested with Python's `zipfile`, and `$MFT`, `$J`, the `SYSTEM` hive and event logs required.
- Jobs: a signed job is read; changed, expired and future-dated jobs are refused. An archive encrypted to a key opens with that key only, and records the job and its recipients.
- Follow rules: an executable named by a process output is collected, an excluded one is not, and one missing from the volume is listed as not found; the paths in services' command lines (quoted, unquoted with spaces, `\??\`, `%SystemRoot%`) are read.
- Commands: output, exit code and error stream kept; a command stopped at its time even when a program it started holds the pipe open; a missing program reported; large output never stalls it; on an image, commands are listed as skipped. In CI on Windows, the processes, connections and services outputs are parsed as JSON.
- Unit tests for path patterns and for reading a raw device in aligned blocks (Windows refuses unaligned reads).

## Licence

MIT or Apache-2.0, at your option.
