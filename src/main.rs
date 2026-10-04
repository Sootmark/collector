//! `sootmark-collector`: collect a Windows triage into one zip, encrypted
//! to the case when a job (or `--recipient`) says to whom.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use collector::{collect, Job, JobRecord, Options, Plan, Summary, Volume, DEFAULT_PLAN};

const USAGE: &str = "sootmark-collector: collect a Windows triage into one zip

Usage:
  sootmark-collector collect --job <job.json> --output <file.zip.age> [options]
  sootmark-collector collect --output <file.zip> [--plan <file.json>] [--recipient <age1…>] [options]

Options:
  --job <job.json>        A job the case prepared and signed: its plan, the key
                          the archive is encrypted to, and its expiry. Its
                          signer and key fingerprint are shown: confirm them.
  --output <file>         Where the archive goes (never overwritten). Put it
                          on another volume than the one collected.
  --plan <file.json>      What to collect, without a job (default: the
                          built-in Windows triage).
  --recipient <age1…>     Encrypt to this key, without a job; repeatable.
  --volume <device>       The volume to read raw (default: \\\\.\\C:). Needs
                          administrator rights.
  --image <file>          Collect from a raw disk image instead.
  --drive <letter>        The volume's drive letter, for paths (default: C).
  --deadline <minutes>    Stop collecting after this long; files not reached
                          are listed as skipped.
  --print-plan            Print the built-in plan and exit.";

struct Args {
    output: PathBuf,
    job: Option<PathBuf>,
    plan: Option<PathBuf>,
    recipients: Vec<String>,
    volume: Option<String>,
    image: Option<PathBuf>,
    drive: char,
    deadline: Option<Duration>,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--print-plan") {
        print!("{DEFAULT_PLAN}");
        return ExitCode::SUCCESS;
    }
    let parsed = match parse(&args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&parsed) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut args = args.iter();
    if args.next().map(String::as_str) != Some("collect") {
        return Err("the command is `collect`".to_owned());
    }
    let mut parsed = Args {
        output: PathBuf::new(),
        job: None,
        plan: None,
        recipients: Vec::new(),
        volume: None,
        image: None,
        drive: 'C',
        deadline: None,
    };
    let mut output = None;
    while let Some(arg) = args.next() {
        let mut value = || args.next().cloned().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--output" => output = Some(PathBuf::from(value()?)),
            "--job" => parsed.job = Some(PathBuf::from(value()?)),
            "--plan" => parsed.plan = Some(PathBuf::from(value()?)),
            "--recipient" => parsed.recipients.push(value()?),
            "--volume" => parsed.volume = Some(value()?),
            "--image" => parsed.image = Some(PathBuf::from(value()?)),
            "--drive" => {
                let letter = value()?;
                parsed.drive = letter
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic() && letter.len() == 1)
                    .ok_or("--drive takes a letter")?
                    .to_ascii_uppercase();
            }
            "--deadline" => {
                let minutes: u64 = value()?.parse().map_err(|_| "--deadline takes minutes")?;
                parsed.deadline = Some(Duration::from_secs(minutes * 60));
            }
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    if parsed.volume.is_some() && parsed.image.is_some() {
        return Err("--volume or --image, not both".to_owned());
    }
    if parsed.job.is_some() && (parsed.plan.is_some() || !parsed.recipients.is_empty()) {
        return Err(
            "a job sets the plan and the keys: no --plan or --recipient with --job".to_owned(),
        );
    }
    parsed.output = output.ok_or("collect needs --output <file>")?;
    Ok(parsed)
}

fn run(args: &Args) -> Result<(), String> {
    let started = Instant::now();
    let (plan, recipients, job) = what_to_do(args)?;
    let keys = recipients
        .iter()
        .map(|r| {
            r.parse::<age::Recipient>()
                .map_err(|e| format!("recipient {r}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        eprintln!("warning: the archive is not encrypted (no job, no --recipient)");
    }
    let mut volume = match (&args.image, &args.volume) {
        (Some(image), _) => Volume::open_image(image),
        (None, Some(device)) => Volume::open_device(device),
        (None, None) => Volume::open_device(&format!(r"\\.\{}:", args.drive)),
    }
    .map_err(|e| format!("opening the volume: {e}"))?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)
        .map_err(|e| format!("{}: {e}", args.output.display()))?;
    let options = Options {
        drive: args.drive,
        host: std::env::var("COMPUTERNAME").unwrap_or_default(),
        deadline: args.deadline.map(|d| started + d),
        job,
        recipients,
        // Commands describe the running host, not an image of a disk.
        live: args.image.is_none(),
    };
    let out = BufWriter::new(file);
    let summary = if keys.is_empty() {
        let (out, summary) =
            collect(&mut volume, &plan, &options, out).map_err(|e| e.to_string())?;
        close(out)?;
        summary
    } else {
        let encrypted = age::Encryptor::new(out, &keys).map_err(|e| e.to_string())?;
        let (encrypted, summary) =
            collect(&mut volume, &plan, &options, encrypted).map_err(|e| e.to_string())?;
        close(encrypted.finish().map_err(|e| e.to_string())?)?;
        summary
    };
    report(args, &summary, started);
    Ok(())
}

/// The plan, the keys to encrypt to, and the job they came from: a signed
/// job's, checked and shown, or the command line's.
fn what_to_do(args: &Args) -> Result<(Plan, Vec<String>, Option<JobRecord>), String> {
    if let Some(path) = &args.job {
        let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let job = Job::verify(&text, i64::try_from(now).unwrap_or(i64::MAX))
            .map_err(|e| format!("job: {}", e.0))?;
        eprintln!(
            "job for case {}, signed by {} (key {}), valid until {}",
            job.case,
            job.issuer,
            job.fingerprint,
            job.expires.to_iso8601().unwrap_or_default()
        );
        let record = JobRecord {
            case: job.case,
            issuer: job.issuer,
            fingerprint: job.fingerprint,
        };
        return Ok((job.plan, job.recipients, Some(record)));
    }
    let text = match &args.plan {
        Some(path) => fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?,
        None => DEFAULT_PLAN.to_owned(),
    };
    let plan = Plan::parse(&text).map_err(|e| format!("plan: {}", e.0))?;
    Ok((plan, args.recipients.clone(), None))
}

/// Flush the archive and make it durable before saying it's done.
fn close(out: BufWriter<File>) -> Result<(), String> {
    let mut file = out.into_inner().map_err(|e| e.error().to_string())?;
    file.flush().map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

fn report(args: &Args, summary: &Summary, started: Instant) {
    println!(
        "{}: {} files collected, {} cut, {} unreadable, {} skipped at the deadline, {} rules found nothing ({} bytes, {:.0?})",
        args.output.display(),
        summary.collected,
        summary.partial,
        summary.errors,
        summary.skipped,
        summary.not_found,
        summary.bytes,
        started.elapsed()
    );
}
