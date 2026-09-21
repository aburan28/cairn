//! How much of the host one verification may take while it runs.
//!
//! The deadline bounds *how long* objective-authored code runs. It does not
//! bound how much of the machine it takes meanwhile: a checker that forks one
//! busy process per core runs every fan on the host for its whole deadline,
//! and on macOS, which has no `RLIMIT_AS`, nothing stopped one that allocated
//! until the machine swapped. An operator lending a laptop to the network
//! needs both answered, and a Mac has neither Linux answer: no cgroups, no
//! address-space limit.
//!
//! So [`Watch`] measures the child's whole process tree while `run_bounded`
//! waits on it, and holds it to two limits:
//!
//! - **CPU** ([`CPUS_ENV`]): a token bucket in core-time. Once the tree has
//!   spent more than `cpus` cores' worth, it is stopped with `SIGSTOP` and
//!   continued when the budget catches up -- the duty cycle `cpulimit` uses,
//!   and the only whole-tree CPU cap a Mac gives an unprivileged process.
//!   Thread affinity is not an alternative: macOS treats it as a hint, and
//!   Apple silicon ignores it.
//! - **Memory**, on macOS only: the tree's summed physical footprint (what
//!   Activity Monitor shows as Memory) against the plan's `memory_mb`, the
//!   same `CAIRN_SANDBOX_MEMORY_MB` that is `RLIMIT_AS` on Linux. Past it the
//!   tree is killed. Linux keeps `RLIMIT_AS` alone, unchanged: adding a
//!   whole-tree cap there would start killing multi-process checkers that
//!   pass today.
//!
//! # Neither limit can produce a rejection
//!
//! A stopped child's deadline keeps running, so a heavily throttled checker
//! can time out, which is `Unavailable` like every timeout. A child killed for
//! its footprint is `Unavailable` too. Both are facts about this node, which
//! is what `Unavailable` is for. The CPU cap costs a *single-process* checker
//! nothing it was not already going to lose at one core or more: its
//! `RLIMIT_CPU` is its deadline in seconds, so it could never spend more than
//! one core's worth of the deadline anyway.
//!
//! # What "the tree" is
//!
//! The child's process group, which `run_bounded` makes it lead, plus every
//! descendant by parent pid. Both, because each misses something: a
//! descendant that calls `setsid` leaves the group (bubblewrap's
//! `--new-session` does exactly that), and one that double-forks is
//! reparented out of the tree but stays in the group. A process that does
//! both escapes this, as it escapes the timeout's kill.
//!
//! Each process counts its reaped children's CPU time as well as its own, so
//! a process that starts and ends between two samples -- one command of a
//! shell script, say -- is still paid for, through the parent that waited
//! for it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Cores one verification may keep busy, on average. Unset or `0` is no cap.
pub const CPUS_ENV: &str = "CAIRN_SANDBOX_CPUS";

/// How often the tree is measured. The 10 ms poll that watches for exit would
/// make this a noticeable cost on Linux, where finding the tree means reading
/// `/proc`; a tenth of a second is fine-grained enough for a duty cycle.
const SAMPLE_INTERVAL: Duration = Duration::from_millis(100);

/// Credit the bucket may bank, in wall time at the full rate. Starting full
/// is what leaves a check that finishes inside it untouched.
const BURST: Duration = Duration::from_millis(200);

/// What `run_bounded` holds a child to besides its deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Limits {
    /// Cores the tree may keep busy on average. `0` is no cap.
    pub cpus: u32,
    /// Physical-footprint cap in MiB, enforced by measurement on macOS. `0`
    /// is no cap.
    pub memory_mb: u64,
}

/// [`CPUS_ENV`], read the way the memory cap is: every verification, so a
/// long-lived node picks up nothing stale -- there is nothing to pick up, a
/// process's environment does not change -- and a test can pass its own.
pub fn configured_cpus() -> u32 {
    parse_cpus(std::env::var(CPUS_ENV).ok().as_deref())
}

/// A count of cores, or no cap. A value that is not a count is reported once
/// and ignored: it is a resource setting, not a security switch, so the
/// failure mode of a typo is the uncapped node every operator had before
/// this existed, said out loud.
fn parse_cpus(value: Option<&str>) -> u32 {
    let Some(text) = value.map(str::trim).filter(|text| !text.is_empty()) else {
        return 0;
    };
    match text.parse::<u32>() {
        Ok(cpus) => cpus,
        Err(_) => {
            static WARNED: OnceLock<()> = OnceLock::new();
            WARNED.get_or_init(|| {
                log::warn!(
                    "{CPUS_ENV}={text:?} is not a whole number of cores; no CPU cap applies"
                );
            });
            0
        }
    }
}

/// Why the watch stopped a child for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breach {
    /// The tree's physical footprint passed the cap.
    Memory { used_mb: u64, cap_mb: u64 },
}

impl std::fmt::Display for Breach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Breach::Memory { used_mb, cap_mb } => write!(
                f,
                "verifier used {used_mb} MiB, over this node's cap of {cap_mb} MiB \
                 (CAIRN_SANDBOX_MEMORY_MB), and was stopped; that is a fact about \
                 this node's limits, not about the artifact"
            ),
        }
    }
}

/// A child's tree, measured and held to its [`Limits`] while it runs.
///
/// Inert, and free, when no limit applies on this platform. Dropping it
/// continues anything it stopped, so no exit path can leave a tree frozen.
pub struct Watch {
    limits: Limits,
    leader: i32,
    live: bool,
    last: Option<Instant>,
    /// CPU time each pid had at the previous sample, its own and its reaped
    /// children's.
    spent: BTreeMap<i32, u64>,
    bucket: Bucket,
    stopped: Option<Instant>,
    stopped_pids: BTreeSet<i32>,
    paused: Duration,
}

impl Watch {
    pub fn new(limits: Limits, leader: u32) -> Watch {
        let memory = cfg!(target_os = "macos") && limits.memory_mb > 0;
        let live = (limits.cpus > 0 || memory) && platform::SUPPORTED;
        Watch {
            limits,
            leader: i32::try_from(leader).unwrap_or(0),
            live: live && leader > 0,
            last: None,
            spent: BTreeMap::new(),
            bucket: Bucket::new(limits.cpus),
            stopped: None,
            stopped_pids: BTreeSet::new(),
            paused: Duration::ZERO,
        }
    }

    /// Called on every turn of the wait loop; measures once a sample interval.
    pub fn poll(&mut self) -> Result<(), Breach> {
        if !self.live {
            return Ok(());
        }
        let now = Instant::now();
        let wall = match self.last {
            Some(last) if now.duration_since(last) < SAMPLE_INTERVAL => return Ok(()),
            Some(last) => now.duration_since(last),
            None => Duration::ZERO,
        };
        self.last = Some(now);

        let tree = platform::tree(self.leader);
        let mut spent: i128 = 0;
        let mut footprint = 0u64;
        let mut next = BTreeMap::new();
        for proc in &tree {
            // A pid first seen now counts everything it has spent: it started
            // since the last sample, or it is the leader at the first one.
            let before = self.spent.get(&proc.pid).copied().unwrap_or(0);
            spent += i128::from(proc.cpu_ns) - i128::from(before);
            footprint = footprint.saturating_add(proc.footprint);
            next.insert(proc.pid, proc.cpu_ns);
        }
        // A pid that has gone was reaped, and its whole total -- what was
        // already counted for it plus its last slice -- has landed in its
        // parent's reaped-children time above. Taking back what was counted
        // leaves exactly the slice. A process too short-lived to be sampled
        // at all is counted the same way, through its parent, which is the
        // point of reading reaped time: a checker that runs a thousand
        // ten-millisecond commands spends real CPU no sample ever sees live.
        for (pid, before) in &self.spent {
            if !next.contains_key(pid) {
                spent -= i128::from(*before);
            }
        }
        let spent = u64::try_from(spent.max(0)).unwrap_or(u64::MAX);
        self.spent = next;

        if cfg!(target_os = "macos") && self.limits.memory_mb > 0 {
            let used_mb = footprint >> 20;
            if used_mb > self.limits.memory_mb {
                return Err(Breach::Memory {
                    used_mb,
                    cap_mb: self.limits.memory_mb,
                });
            }
        }

        if self.limits.cpus > 0 {
            self.bucket.step(wall, spent);
            match (self.stopped.is_some(), self.bucket.in_debt()) {
                (false, true) => self.stop(&tree, now),
                // Anything that joined the tree after the stop -- forked in
                // the instant before it, or out of the group -- stops too.
                (true, true) => self.stop(&tree, now),
                (true, false) => self.release(),
                (false, false) => {}
            }
        }
        Ok(())
    }

    fn stop(&mut self, tree: &[Proc], now: Instant) {
        if self.stopped.is_none() {
            self.stopped = Some(now);
            platform::signal(-self.leader, platform::SIGSTOP);
        }
        for proc in tree {
            if self.stopped_pids.insert(proc.pid) {
                platform::signal(proc.pid, platform::SIGSTOP);
            }
        }
    }

    /// Continue everything this watch stopped. Idempotent.
    pub fn release(&mut self) {
        let Some(since) = self.stopped.take() else {
            return;
        };
        self.paused = self.paused.saturating_add(since.elapsed());
        platform::signal(-self.leader, platform::SIGCONT);
        for pid in std::mem::take(&mut self.stopped_pids) {
            platform::signal(pid, platform::SIGCONT);
        }
    }

    /// The CPU cap and how long it held the child, if it ever did. For the
    /// timeout message: an operator reading "exceeded 300s" should also read
    /// that their own cap spent part of those 300 seconds.
    pub fn throttled(&self) -> Option<(u32, Duration)> {
        let current = self
            .stopped
            .map(|since| since.elapsed())
            .unwrap_or_default();
        let total = self.paused.saturating_add(current);
        (total > Duration::ZERO).then_some((self.limits.cpus, total))
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.release();
    }
}

/// Core-time credit, in core-nanoseconds.
///
/// Integers, like everything else here: `cpus` cores for `wall` is
/// `cpus * wall` core-nanoseconds exactly, and `i128` holds a day of a
/// thousand cores without trying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Bucket {
    cpus: u32,
    credit: i128,
}

impl Bucket {
    fn new(cpus: u32) -> Bucket {
        Bucket {
            cpus,
            credit: Bucket::ceiling(cpus),
        }
    }

    fn ceiling(cpus: u32) -> i128 {
        i128::from(cpus) * i128::try_from(BURST.as_nanos()).unwrap_or(i128::MAX)
    }

    fn step(&mut self, wall: Duration, spent_ns: u64) {
        let wall = i128::try_from(wall.as_nanos()).unwrap_or(i128::MAX);
        let earned = i128::from(self.cpus).saturating_mul(wall);
        self.credit = self
            .credit
            .saturating_add(earned)
            .saturating_sub(i128::from(spent_ns))
            .min(Bucket::ceiling(self.cpus));
    }

    fn in_debt(&self) -> bool {
        self.credit < 0
    }
}

/// One process of the tree at one instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Proc {
    pid: i32,
    /// User plus system time, nanoseconds, its own and its reaped
    /// children's.
    cpu_ns: u64,
    /// Physical footprint, bytes. Measured on macOS only.
    footprint: u64,
}

/// The pids in `leader`'s process group or below it by parent pid, from a
/// table of `(pid, ppid, pgrp)`. What Linux has to compute from `/proc`, where
/// there is no call that answers "the children of".
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn select(leader: i32, table: &[(i32, i32, i32)]) -> BTreeSet<i32> {
    let mut children: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
    for &(pid, ppid, _) in table {
        children.entry(ppid).or_default().push(pid);
    }
    let mut tree: BTreeSet<i32> = table
        .iter()
        .filter(|&&(_, _, pgrp)| pgrp == leader)
        .map(|&(pid, _, _)| pid)
        .collect();
    let mut queue = vec![leader];
    let mut seen = BTreeSet::new();
    while let Some(pid) = queue.pop() {
        if !seen.insert(pid) {
            continue;
        }
        if table.iter().any(|&(p, _, _)| p == pid) {
            tree.insert(pid);
        }
        if let Some(kids) = children.get(&pid) {
            queue.extend(kids.iter().copied());
        }
    }
    tree
}

// This crate has no `libc` dependency (see `verifiers::libc_kill`), so the
// few calls below are declared where they are used. Every one is a stable
// entry point in the platform's C library, already linked into the binary.

#[cfg(unix)]
unsafe extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

#[cfg(target_os = "macos")]
mod platform {
    use super::Proc;
    use std::collections::BTreeSet;
    use std::sync::OnceLock;

    pub const SUPPORTED: bool = true;
    pub const SIGSTOP: i32 = 17;
    pub const SIGCONT: i32 = 19;

    const PROC_PGRP_ONLY: u32 = 2;
    const PROC_PPID_ONLY: u32 = 6;
    const RUSAGE_INFO_V1: i32 = 1;
    /// Pids read per listing. A verifier with more processes than this is
    /// measured in part, which is what best effort means here.
    const MAX_PIDS: usize = 4096;

    /// `struct rusage_info_v1` from `<sys/resource.h>`: v0, which has the
    /// process's own times and footprint, plus its reaped children's times.
    #[repr(C)]
    #[derive(Default)]
    struct RusageInfoV1 {
        uuid: [u8; 16],
        user_time: u64,
        system_time: u64,
        pkg_idle_wkups: u64,
        interrupt_wkups: u64,
        pageins: u64,
        wired_size: u64,
        resident_size: u64,
        phys_footprint: u64,
        proc_start_abstime: u64,
        proc_exit_abstime: u64,
        child_user_time: u64,
        child_system_time: u64,
        child_pkg_idle_wkups: u64,
        child_interrupt_wkups: u64,
        child_pageins: u64,
        child_elapsed_abstime: u64,
    }

    #[repr(C)]
    #[derive(Default)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }

    unsafe extern "C" {
        fn proc_listpids(kind: u32, info: u32, buffer: *mut i32, size: i32) -> i32;
        fn proc_pid_rusage(pid: i32, flavor: i32, buffer: *mut RusageInfoV1) -> i32;
        fn mach_timebase_info(info: *mut Timebase) -> i32;
    }

    pub fn signal(pid: i32, sig: i32) {
        // SAFETY: `kill` takes two integers and reports failure in its return
        // value; a pid that has already gone is ESRCH, which is fine here.
        unsafe {
            super::libc_kill(pid, sig);
        }
    }

    fn list(kind: u32, info: i32) -> Vec<i32> {
        let mut buffer = vec![0i32; MAX_PIDS];
        let size = i32::try_from(buffer.len() * std::mem::size_of::<i32>()).unwrap_or(i32::MAX);
        // SAFETY: the buffer is `size` bytes of writable, aligned `i32`s, and
        // the call writes at most `size` bytes, returning how many it wrote.
        let bytes = unsafe { proc_listpids(kind, info as u32, buffer.as_mut_ptr(), size) };
        let count = usize::try_from(bytes).unwrap_or(0) / std::mem::size_of::<i32>();
        buffer.truncate(count.min(MAX_PIDS));
        buffer.retain(|&pid| pid > 0);
        buffer
    }

    /// Nanoseconds per `ri_user_time` tick. Not 1 on Apple silicon, where
    /// these fields count `mach_absolute_time` units of 125/3 ns; reading them
    /// as nanoseconds would measure a busy core as 4% busy.
    fn timebase() -> (u128, u128) {
        static BASE: OnceLock<(u128, u128)> = OnceLock::new();
        *BASE.get_or_init(|| {
            let mut base = Timebase::default();
            // SAFETY: writes one small struct we own.
            let ok = unsafe { mach_timebase_info(&mut base) } == 0;
            if ok && base.numer > 0 && base.denom > 0 {
                (u128::from(base.numer), u128::from(base.denom))
            } else {
                (1, 1)
            }
        })
    }

    pub fn tree(leader: i32) -> Vec<Proc> {
        let mut pids: BTreeSet<i32> = list(PROC_PGRP_ONLY, leader).into_iter().collect();
        let mut queue = vec![leader];
        let mut seen = BTreeSet::new();
        while let Some(pid) = queue.pop() {
            if seen.insert(pid) {
                pids.insert(pid);
                queue.extend(list(PROC_PPID_ONLY, pid));
            }
        }
        let (numer, denom) = timebase();
        pids.into_iter()
            .filter_map(|pid| {
                let mut info = RusageInfoV1::default();
                // SAFETY: `info` is the v1 layout the flavor asks for.
                if unsafe { proc_pid_rusage(pid, RUSAGE_INFO_V1, &mut info) } != 0 {
                    return None;
                }
                // The children's fields count the same ticks as the
                // process's own.
                let ticks = u128::from(info.user_time)
                    + u128::from(info.system_time)
                    + u128::from(info.child_user_time)
                    + u128::from(info.child_system_time);
                Some(Proc {
                    pid,
                    cpu_ns: u64::try_from(ticks * numer / denom).unwrap_or(u64::MAX),
                    footprint: info.phys_footprint,
                })
            })
            .collect()
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::Proc;

    pub const SUPPORTED: bool = true;
    pub const SIGSTOP: i32 = 19;
    pub const SIGCONT: i32 = 18;

    /// `/proc` reports times in `USER_HZ`, which the kernel fixes at 100 for
    /// every architecture's userspace ABI.
    const NS_PER_TICK: u64 = 10_000_000;

    pub fn signal(pid: i32, sig: i32) {
        // SAFETY: as on macOS.
        unsafe {
            super::libc_kill(pid, sig);
        }
    }

    /// `(ppid, pgrp, utime + stime + cutime + cstime)` from
    /// `/proc/<pid>/stat`: its own time and its reaped children's. The command
    /// name is in parentheses and may itself contain spaces and parentheses,
    /// so fields are counted from the *last* `)`.
    pub(super) fn parse_stat(text: &str) -> Option<(i32, i32, u64)> {
        let rest = &text[text.rfind(')')? + 1..];
        let fields: Vec<&str> = rest.split_whitespace().collect();
        let ppid = fields.get(1)?.parse().ok()?;
        let pgrp = fields.get(2)?.parse().ok()?;
        let mut ticks = 0u64;
        for index in 11..=14 {
            ticks = ticks.saturating_add(fields.get(index)?.parse().ok()?);
        }
        Some((ppid, pgrp, ticks))
    }

    pub fn tree(leader: i32) -> Vec<Proc> {
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut table = Vec::new();
        let mut ticks = std::collections::BTreeMap::new();
        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<i32>().ok())
            else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
                continue;
            };
            if let Some((ppid, pgrp, cpu)) = parse_stat(&stat) {
                table.push((pid, ppid, pgrp));
                ticks.insert(pid, cpu);
            }
        }
        super::select(leader, &table)
            .into_iter()
            .map(|pid| Proc {
                pid,
                cpu_ns: ticks
                    .get(&pid)
                    .copied()
                    .unwrap_or(0)
                    .saturating_mul(NS_PER_TICK),
                footprint: 0,
            })
            .collect()
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    use super::Proc;

    pub const SUPPORTED: bool = false;
    pub const SIGSTOP: i32 = 0;
    pub const SIGCONT: i32 = 0;

    pub fn signal(_pid: i32, _sig: i32) {}

    pub fn tree(_leader: i32) -> Vec<Proc> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cpu_count_is_a_whole_number_and_anything_else_is_no_cap() {
        assert_eq!(parse_cpus(None), 0);
        assert_eq!(parse_cpus(Some("")), 0);
        assert_eq!(parse_cpus(Some(" 4 ")), 4);
        assert_eq!(parse_cpus(Some("0")), 0);
        assert_eq!(parse_cpus(Some("1.5")), 0);
        assert_eq!(parse_cpus(Some("-2")), 0);
        assert_eq!(parse_cpus(Some("all")), 0);
    }

    #[test]
    fn the_bucket_holds_a_busy_tree_to_its_cores_on_average() {
        // Eight busy cores capped at two, sampled every 100 ms: run a sample,
        // stop until the credit is back, repeat. Over a simulated minute the
        // tree may spend two cores' worth plus the one burst it started with.
        let step = SAMPLE_INTERVAL;
        let mut bucket = Bucket::new(2);
        let mut stopped = false;
        let mut spent: u128 = 0;
        let samples = 600u32;
        for _ in 0..samples {
            let used = if stopped {
                0
            } else {
                8 * step.as_nanos() as u64
            };
            spent += u128::from(used);
            bucket.step(step, used);
            stopped = bucket.in_debt();
        }
        let wall = step.as_nanos() * u128::from(samples);
        let allowed = 2 * wall + 2 * BURST.as_nanos();
        assert!(
            spent <= allowed + 8 * step.as_nanos(),
            "spent {spent} of {allowed}"
        );
        assert!(
            spent >= 2 * wall * 9 / 10,
            "throttled far below the cap: {spent}"
        );
    }

    #[test]
    fn a_tree_inside_its_cap_is_never_in_debt() {
        let mut bucket = Bucket::new(4);
        for _ in 0..1000 {
            bucket.step(SAMPLE_INTERVAL, 3 * SAMPLE_INTERVAL.as_nanos() as u64);
            assert!(!bucket.in_debt());
        }
    }

    #[test]
    fn the_tree_is_the_group_and_every_descendant() {
        // 10 leads group 10. 11 is its child; 12 is 11's child that left the
        // group with setsid; 13 double-forked away (parent 1) but kept the
        // group; 20 and its child 21 are strangers.
        let table = [
            (1, 0, 1),
            (10, 5, 10),
            (11, 10, 10),
            (12, 11, 12),
            (13, 1, 10),
            (20, 1, 20),
            (21, 20, 20),
        ];
        let tree: Vec<i32> = select(10, &table).into_iter().collect();
        assert_eq!(tree, vec![10, 11, 12, 13]);
    }

    #[test]
    fn a_leader_that_has_exited_leaves_only_what_it_left_behind() {
        let table = [(13, 1, 10), (20, 1, 20)];
        let tree: Vec<i32> = select(10, &table).into_iter().collect();
        assert_eq!(tree, vec![13]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_stat_is_read_from_the_last_parenthesis() {
        // utime 250, stime 50, and 7 + 3 of reaped children's.
        let line = "4242 (a (weird) name) S 7 4242 4242 0 -1 4194560 100 0 0 0 250 50 7 3 20 0 1 0";
        assert_eq!(platform::parse_stat(line), Some((7, 4242, 310)));
    }

    #[test]
    fn no_limits_is_an_inert_watch() {
        let mut watch = Watch::new(Limits::default(), std::process::id());
        assert!(!watch.live);
        assert_eq!(watch.poll(), Ok(()));
        assert_eq!(watch.throttled(), None);
    }

    /// The measurement is the part a unit test cannot fake: if the units were
    /// wrong -- Apple silicon's tick is not a nanosecond -- the cap would be
    /// off by twenty-four times and every test above would still pass.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_busy_child_is_measured_in_real_nanoseconds() {
        use std::process::Command;
        let mut child = Command::new("/bin/sh")
            .args(["-c", "i=0; while [ $i -lt 2000000 ]; do i=$((i+1)); done"])
            .spawn()
            .expect("spawn sh");
        let pid = i32::try_from(child.id()).expect("pid");
        let started = Instant::now();
        let mut last = 0u64;
        while started.elapsed() < Duration::from_millis(600) {
            if let Some(proc) = platform::tree(pid).into_iter().find(|p| p.pid == pid) {
                last = proc.cpu_ns;
            }
            if child.try_wait().expect("wait").is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let wall = started.elapsed();
        let _ = child.kill();
        let _ = child.wait();
        // One busy process: its CPU time cannot exceed the wall time it had,
        // and on any machine that is not badly oversubscribed it is most of
        // it. A 24x unit error lands far outside both bounds.
        let wall_ns = u64::try_from(wall.as_nanos()).unwrap_or(u64::MAX);
        assert!(
            last <= wall_ns + 50_000_000,
            "cpu {last} ns > wall {wall_ns} ns"
        );
        assert!(
            last >= wall_ns / 8,
            "cpu {last} ns is implausibly small for {wall_ns} ns"
        );
    }
}
