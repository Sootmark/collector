//! Running a plan's commands: as given (no shell), with no input, their
//! output read as it comes (so a full pipe never stalls them) and kept up
//! to a bound, and stopped when they run past their time. Once a command
//! ends, its output gets a short grace period: a program it left behind
//! can keep the pipe open.

use std::io::{self, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use common::time::Ts;

/// Most of a command's output kept; the rest is read and dropped.
const MAX_OUTPUT: u64 = 256 << 20;
/// Most of what a command writes to its error stream kept.
const MAX_ERRORS: u64 = 64 << 10;
/// How often a running command is looked at.
const POLL: Duration = Duration::from_millis(50);
/// How long the output may go on once the command has ended.
const GRACE: Duration = Duration::from_secs(2);

/// What running a command gave.
#[derive(Debug)]
pub(crate) struct Ran {
    /// When it was started.
    pub started: Ts,
    /// How long it ran.
    pub duration: Duration,
    /// Its exit code, when it exited by itself.
    pub exit_code: Option<i32>,
    /// Why it didn't run to its end: it couldn't start, or was stopped.
    pub failure: Option<String>,
    /// What it printed (up to the bound).
    pub stdout: Vec<u8>,
    /// What it wrote to its error stream (up to the bound).
    pub stderr: Vec<u8>,
}

/// Run `argv`, stopping it after `timeout`.
pub(crate) fn run(argv: &[String], timeout: Duration) -> Ran {
    let started = crate::collect::now();
    let clock = Instant::now();
    let mut ran = Ran {
        started,
        duration: Duration::ZERO,
        exit_code: None,
        failure: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let (program, arguments) = argv.split_first().expect("a plan's command has a program");
    let spawned = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            ran.failure = Some(format!("could not start {program}: {error}"));
            return ran;
        }
    };
    let stdout = child
        .stdout
        .take()
        .map(|out| Drained::start(out, MAX_OUTPUT));
    let stderr = child
        .stderr
        .take()
        .map(|err| Drained::start(err, MAX_ERRORS));
    match wait(&mut child, timeout) {
        Ok(Ended::Exited(code)) => ran.exit_code = code,
        Ok(Ended::Stopped) => ran.failure = Some(format!("stopped after {} s", timeout.as_secs())),
        Err(error) => ran.failure = Some(format!("waiting for it failed: {error}")),
    }
    ran.stdout = stdout.map(Drained::finish).unwrap_or_default();
    ran.stderr = stderr.map(Drained::finish).unwrap_or_default();
    ran.duration = clock.elapsed();
    ran
}

/// How a command ended.
enum Ended {
    /// By itself, with its exit code (none when ended by a signal).
    Exited(Option<i32>),
    /// Stopped at its time.
    Stopped,
}

fn wait(child: &mut Child, timeout: Duration) -> io::Result<Ended> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Ended::Exited(status.code()));
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Ok(Ended::Stopped);
        }
        thread::sleep(POLL);
    }
}

/// A stream read to its end on a thread, the first bytes kept where the
/// caller can take them even if the end never comes: a program the command
/// started may hold the pipe open after the command itself is gone.
struct Drained {
    kept: Arc<Mutex<Vec<u8>>>,
    done: Receiver<()>,
}

impl Drained {
    fn start(mut stream: impl Read + Send + 'static, keep: u64) -> Self {
        let kept = Arc::new(Mutex::new(Vec::new()));
        let (finished, done) = mpsc::channel();
        let shared = Arc::clone(&kept);
        thread::spawn(move || {
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut kept = shared.lock().unwrap_or_else(PoisonError::into_inner);
                        let room = usize::try_from(keep)
                            .unwrap_or(usize::MAX)
                            .saturating_sub(kept.len());
                        kept.extend_from_slice(&buffer[..n.min(room)]);
                    }
                }
            }
            let _ = finished.send(());
        });
        Self { kept, done }
    }

    /// What was read, once the stream ended or a grace period passed.
    fn finish(self) -> Vec<u8> {
        let _ = self.done.recv_timeout(GRACE);
        std::mem::take(&mut *self.kept.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str, timeout: Duration) -> Ran {
        run(
            &["sh".to_owned(), "-c".to_owned(), script.to_owned()],
            timeout,
        )
    }

    #[test]
    fn output_exit_code_and_errors() {
        let ran = sh("echo out; echo err >&2; exit 3", Duration::from_secs(10));
        assert_eq!(ran.stdout, b"out\n");
        assert_eq!(ran.stderr, b"err\n");
        assert_eq!(ran.exit_code, Some(3));
        assert!(ran.failure.is_none());
    }

    #[test]
    fn stopped_at_its_time() {
        let ran = sh("echo started; sleep 30", Duration::from_millis(300));
        assert!(ran.failure.unwrap().starts_with("stopped after"));
        assert!(ran.duration < Duration::from_secs(10));
        assert_eq!(ran.stdout, b"started\n");
    }

    #[test]
    fn a_missing_program_is_reported() {
        let ran = run(&["no-such-program-here".to_owned()], Duration::from_secs(1));
        assert!(ran.failure.unwrap().contains("could not start"));
    }

    #[test]
    fn a_large_output_never_stalls_it() {
        let ran = sh("head -c 3000000 /dev/zero", Duration::from_secs(20));
        assert_eq!((ran.stdout.len(), ran.exit_code), (3_000_000, Some(0)));
    }
}
