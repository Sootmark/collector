//! Keeping the collector light on the host it runs on, as DFIR-ORC does:
//! background priority (low CPU, I/O and memory priority, so the host's
//! own work goes first), and a Job Object capping its CPU share and its
//! memory, and ending whatever it started if it dies. The commands it runs
//! inherit both.
//!
//! This is the only code that calls Windows directly, through Microsoft's
//! `windows-sys` declarations, so the only `unsafe` code in the crate.
//! Elsewhere, and on other systems, nothing changes.

/// The caps a run asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most of one processor's time the collector may use, in percent of
    /// the whole machine (1 to 100).
    pub cpu_percent: u32,
    /// Most memory the collector (and each command) may commit, in MiB.
    pub max_memory_mib: u64,
}

/// What applying the limits did, for the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applied {
    /// Background priority and the Job Object's caps are in force.
    Yes,
    /// They couldn't be applied, and why (the run goes on without them).
    No(String),
    /// Not a Windows host: nothing to apply.
    NotWindows,
}

/// Apply `limits` to this process.
#[must_use]
pub fn apply(limits: Limits) -> Applied {
    windows::apply(limits)
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod windows {
    use std::mem::size_of;
    use std::ptr::null;

    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectCpuRateControlInformation,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
        JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, SetPriorityClass, PROCESS_MODE_BACKGROUND_BEGIN,
    };

    use super::{Applied, Limits};

    pub(super) fn apply(limits: Limits) -> Applied {
        match background().and_then(|()| job(limits)) {
            Ok(()) => Applied::Yes,
            Err(why) => Applied::No(why),
        }
    }

    /// Background mode: lowest CPU, I/O and memory priority for this process.
    fn background() -> Result<(), String> {
        // SAFETY: GetCurrentProcess returns a pseudo-handle valid for the
        // process's life; SetPriorityClass takes it and a documented flag.
        let done = unsafe { SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN) };
        check(done, "background priority")
    }

    /// A Job Object holding this process: CPU hard-capped, memory capped,
    /// everything in it ended when the collector's handle closes (when it
    /// exits or dies). The handle is never closed before then.
    fn job(limits: Limits) -> Result<(), String> {
        // SAFETY: null security attributes and name are documented as
        // "default" and "unnamed".
        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            return Err(last_error("creating the Job Object"));
        }
        let mut memory = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        memory.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        memory.ProcessMemoryLimit =
            usize::try_from(limits.max_memory_mib << 20).unwrap_or(usize::MAX);
        // SAFETY: `memory` is the structure this information class takes,
        // with its size, and lives across the call.
        let done = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const memory).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        check(done, "the memory cap")?;
        let cpu = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
            ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
            // Hundredths of a percent of the whole machine.
            Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
                CpuRate: limits.cpu_percent.clamp(1, 100) * 100,
            },
        };
        // SAFETY: as above, for the CPU rate structure.
        let done = unsafe {
            SetInformationJobObject(
                job,
                JobObjectCpuRateControlInformation,
                (&raw const cpu).cast(),
                size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            )
        };
        check(done, "the CPU cap")?;
        // SAFETY: both handles are valid; the job handle is deliberately
        // leaked so the job lasts as long as the process.
        let done = unsafe { AssignProcessToJobObject(job, GetCurrentProcess()) };
        check(done, "joining the Job Object")
    }

    fn check(done: i32, what: &str) -> Result<(), String> {
        if done == 0 {
            Err(last_error(what))
        } else {
            Ok(())
        }
    }

    fn last_error(what: &str) -> String {
        // SAFETY: reads the calling thread's last error code.
        let code = unsafe { GetLastError() };
        format!("{what} failed (Windows error {code})")
    }
}

#[cfg(not(windows))]
mod windows {
    use super::{Applied, Limits};

    pub(super) fn apply(_limits: Limits) -> Applied {
        Applied::NotWindows
    }
}
