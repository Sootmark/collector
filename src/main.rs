//! `sootmark-collector`: collect a Windows triage into one zip.

use std::fs::{self, OpenOptions};
use std::io::BufWriter;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use collector::{collect, Options, Plan, Volume, DEFAULT_PLAN};

const USAGE: &str = "sootmark-collector: collect a Windows triage into one zip

Usage:
  sootmark-collector collect --output <file.zip> [options]

Options:
  --output <file.zip>     Where the archive goes (never overwritten). Put it
                          on another volume than the one collected.
  --plan <file.json>      What to collect (default: the built-in Windows triage).
  --volume <device>       The volume to read raw (default: \\\\.\\C:). Needs
                          administrator rights.
  --image <file>          Collect from a raw disk image instead.
  --drive <letter>        The volume's drive letter, for paths (default: C).
  --deadline <minutes>    Stop collecting after this long; files not reached
                          are listed as skipped.
  --print-plan            Print the built-in plan and exit.";

struct Args {
    output: PathBuf,
    plan: Option<PathBuf>,
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
    let (mut output, mut plan, mut volume, mut image, mut drive, mut deadline) =
        (None, None, None, None, 'C', None);
    while let Some(arg) = args.next() {
        let mut value = || args.next().cloned().ok_or(format!("{arg} needs a value"));
        match arg.as_str() {
            "--output" => output = Some(PathBuf::from(value()?)),
            "--plan" => plan = Some(PathBuf::from(value()?)),
            "--volume" => volume = Some(value()?),
            "--image" => image = Some(PathBuf::from(value()?)),
            "--drive" => {
                let letter = value()?;
                drive = letter
                    .chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic() && letter.len() == 1)
                    .ok_or("--drive takes a letter")?
                    .to_ascii_uppercase();
            }
            "--deadline" => {
                let minutes: u64 = value()?.parse().map_err(|_| "--deadline takes minutes")?;
                deadline = Some(Duration::from_secs(minutes * 60));
            }
            other => return Err(format!("unknown option '{other}'")),
        }
    }
    if volume.is_some() && image.is_some() {
        return Err("--volume or --image, not both".to_owned());
    }
    Ok(Args {
        output: output.ok_or("collect needs --output <file.zip>")?,
        plan,
        volume,
        image,
        drive,
        deadline,
    })
}

fn run(args: &Args) -> Result<(), String> {
    let started = Instant::now();
    let text = match &args.plan {
        Some(path) => fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?,
        None => DEFAULT_PLAN.to_owned(),
    };
    let plan = Plan::parse(&text).map_err(|e| format!("plan: {}", e.0))?;
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
    };
    let (out, summary) =
        collect(&mut volume, &plan, &options, BufWriter::new(file)).map_err(|e| e.to_string())?;
    out.into_inner()
        .map_err(|e| e.error().to_string())?
        .sync_all()
        .map_err(|e| e.to_string())?;
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
    Ok(())
}
