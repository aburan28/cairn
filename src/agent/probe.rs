//! What this machine is: CPUs, memory, NUMA, GPUs, and the cgroup the agent
//! itself is confined to.
//!
//! Everything is read from `/proc` and `/sys`; one optional process spawn
//! (`nvidia-smi`) fills in GPU memory where the driver's own files do not
//! say. The parsers take text and are tested on fixtures, because a probe
//! that can only be tested on the hardware it describes is a probe nobody
//! tests. A number the host does not state is reported as absent rather than
//! guessed: the node sums these, and a guess would be the kind of number a
//! reader multiplies.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::canonical::Value;

/// One accelerator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gpu {
    pub index: u64,
    /// `nvidia`, `amd`, `intel`, or the PCI vendor id in hex for anything else.
    pub vendor: String,
    pub model: Option<String>,
    pub memory_mb: Option<u64>,
    /// PCI bus location, `0000:17:00.0`.
    pub bus: Option<String>,
    pub driver: Option<String>,
}

impl Gpu {
    pub fn to_value(&self) -> Value {
        let opt = |value: &Option<String>| match value {
            Some(s) => Value::string(s.clone()),
            None => Value::Null,
        };
        Value::object([
            ("index", Value::Int(i128::from(self.index))),
            ("vendor", Value::string(self.vendor.clone())),
            ("model", opt(&self.model)),
            (
                "memory_mb",
                match self.memory_mb {
                    Some(mb) => Value::Int(i128::from(mb)),
                    None => Value::Null,
                },
            ),
            ("bus", opt(&self.bus)),
            ("driver", opt(&self.driver)),
        ])
    }
}

/// The machine, as the agent will describe it to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    pub hostname: String,
    pub os: &'static str,
    pub arch: &'static str,
    pub kernel: Option<String>,
    /// Logical CPUs this process may use.
    pub cpus: Option<u64>,
    pub cpu_model: Option<String>,
    pub sockets: Option<u64>,
    pub numa_nodes: Option<u64>,
    /// Instruction-set features a solver cares about: `avx2`, `avx512f`,
    /// `sve`, …, from `/proc/cpuinfo` flags.
    pub cpu_features: Vec<String>,
    pub memory_mb: Option<u64>,
    pub gpus: Vec<Gpu>,
    /// What the agent's own cgroup caps it to, when it is capped. A systemd
    /// unit with `CPUQuota=` or `MemoryMax=` shows here, and so does a VM
    /// handed less than its socket count.
    pub cgroup_cpus: Option<u64>,
    pub cgroup_memory_mb: Option<u64>,
    /// `/dev/kvm` is usable: the precondition for Kata with its default
    /// hypervisor.
    pub kvm: bool,
}

impl Inventory {
    /// Read the machine. Spawns `nvidia-smi` once if it is present.
    pub fn probe() -> Inventory {
        let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
        let (cpu_model, sockets, cpu_features) = parse_cpuinfo(&cpuinfo);
        let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let (cgroup_cpus, cgroup_memory_mb) = cgroup_limits(Path::new("/sys/fs/cgroup"));
        Inventory {
            hostname: hostname(),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            kernel: fs::read_to_string("/proc/sys/kernel/osrelease")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            cpus: std::thread::available_parallelism()
                .ok()
                .map(|n| n.get() as u64),
            cpu_model,
            sockets,
            numa_nodes: numa_nodes(Path::new("/sys/devices/system/node")),
            cpu_features,
            memory_mb: parse_meminfo_mb(&meminfo),
            gpus: gpus(),
            cgroup_cpus,
            cgroup_memory_mb,
            kvm: Path::new("/dev/kvm").exists(),
        }
    }

    /// The `hardware` block of a registration.
    pub fn to_value(&self) -> Value {
        let opt = |value: Option<u64>| match value {
            Some(n) => Value::Int(i128::from(n)),
            None => Value::Null,
        };
        let text = |value: &Option<String>| match value {
            Some(s) => Value::string(s.clone()),
            None => Value::Null,
        };
        Value::object([
            ("hostname", Value::string(self.hostname.clone())),
            ("os", Value::string(self.os)),
            ("arch", Value::string(self.arch)),
            ("kernel", text(&self.kernel)),
            ("cpus", opt(self.cpus)),
            ("cpu_model", text(&self.cpu_model)),
            ("sockets", opt(self.sockets)),
            ("numa_nodes", opt(self.numa_nodes)),
            (
                "cpu_features",
                Value::array(self.cpu_features.iter().map(|f| Value::string(f.clone()))),
            ),
            ("memory_mb", opt(self.memory_mb)),
            ("gpus", Value::array(self.gpus.iter().map(Gpu::to_value))),
            (
                "cgroup",
                Value::object([
                    ("cpus", opt(self.cgroup_cpus)),
                    ("memory_mb", opt(self.cgroup_memory_mb)),
                ]),
            ),
            ("kvm", Value::Bool(self.kvm)),
        ])
    }

    /// A one-line device name in the vocabulary `progress::device_class`
    /// understands, for workers the agent launches to heartbeat under.
    pub fn device_name(&self) -> String {
        match self.gpus.first() {
            Some(gpu) => {
                let model = gpu.model.clone().unwrap_or_else(|| gpu.vendor.clone());
                if self.gpus.len() > 1 {
                    format!("{}x {}", self.gpus.len(), model)
                } else {
                    model
                }
            }
            None => format!(
                "{} ({} cpus)",
                self.cpu_model.clone().unwrap_or_else(|| "cpu".to_string()),
                self.cpus.unwrap_or(0)
            ),
        }
    }
}

fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .or_else(|_| fs::read_to_string("/etc/hostname"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// The features worth telling a scheduler about. Everything else in the
/// flags line is noise to it.
const INTERESTING_FEATURES: [&str; 14] = [
    "avx",
    "avx2",
    "avx512f",
    "avx512bw",
    "avx512vl",
    "avx512ifma",
    "fma",
    "bmi2",
    "adx",
    "sha_ni",
    "aes",
    "pclmulqdq",
    "sve",
    "sve2",
];

/// `(model name, physical sockets, interesting flags)` from `/proc/cpuinfo`.
/// ARM's cpuinfo has no `model name`; `CPU part` is what it offers.
pub fn parse_cpuinfo(text: &str) -> (Option<String>, Option<u64>, Vec<String>) {
    let mut model = None;
    let mut part = None;
    let mut physical = BTreeSet::new();
    let mut features = BTreeSet::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "model name" if model.is_none() && !value.is_empty() => model = Some(value.to_string()),
            "CPU part" if part.is_none() && !value.is_empty() => part = Some(value.to_string()),
            "physical id" => {
                physical.insert(value.to_string());
            }
            "flags" | "Features" => {
                for flag in value.split_whitespace() {
                    if INTERESTING_FEATURES.contains(&flag) {
                        features.insert(flag.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    let sockets = if physical.is_empty() {
        None
    } else {
        Some(physical.len() as u64)
    };
    (
        model.or(part.map(|p| format!("arm part {p}"))),
        sockets,
        features.into_iter().collect(),
    )
}

/// `MemTotal:       16314372 kB` -> 15932.
pub fn parse_meminfo_mb(text: &str) -> Option<u64> {
    let line = text.lines().find(|line| line.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024)
}

fn numa_nodes(dir: &Path) -> Option<u64> {
    let entries = fs::read_dir(dir).ok()?;
    let count = entries
        .flatten()
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.starts_with("node") && name[4..].chars().all(|c| c.is_ascii_digit())
        })
        .count() as u64;
    (count > 0).then_some(count)
}

/// cgroup v2 `cpu.max` and `memory.max` of the agent's own cgroup, as whole
/// CPUs and MiB. `max` in either file is no limit, reported as absent.
pub fn cgroup_limits(root: &Path) -> (Option<u64>, Option<u64>) {
    let own = fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|text| parse_cgroup_path(&text));
    let dir = match own {
        Some(path) => root.join(path.trim_start_matches('/')),
        None => return (None, None),
    };
    let cpus = fs::read_to_string(dir.join("cpu.max"))
        .ok()
        .and_then(|text| parse_cpu_max(&text));
    let memory = fs::read_to_string(dir.join("memory.max"))
        .ok()
        .and_then(|text| text.trim().parse::<u64>().ok())
        .map(|bytes| bytes / (1024 * 1024));
    (cpus, memory)
}

/// The v2 line of `/proc/self/cgroup`: `0::/system.slice/cairn-agent.service`.
pub fn parse_cgroup_path(text: &str) -> Option<String> {
    text.lines()
        .find_map(|line| line.strip_prefix("0::").map(|path| path.trim().to_string()))
}

/// `cpu.max` is `$MAX $PERIOD` or `max $PERIOD`; whole CPUs, rounded down,
/// never zero -- a quota under one CPU is still one CPU to a scheduler.
pub fn parse_cpu_max(text: &str) -> Option<u64> {
    let mut parts = text.split_whitespace();
    let quota = parts.next()?;
    if quota == "max" {
        return None;
    }
    let quota: u64 = quota.parse().ok()?;
    let period: u64 = parts.next()?.parse().ok()?;
    if period == 0 {
        return None;
    }
    Some((quota / period).max(1))
}

// -- GPUs -------------------------------------------------------------------------

/// Every display or 3D controller on the PCI bus, with what the driver
/// files and `nvidia-smi` add.
fn gpus() -> Vec<Gpu> {
    let mut found = pci_gpus(Path::new("/sys/bus/pci/devices"));
    // NVIDIA's own files name the model per bus location.
    if let Ok(entries) = fs::read_dir("/proc/driver/nvidia/gpus") {
        for entry in entries.flatten() {
            let bus = entry.file_name().to_string_lossy().to_string();
            let info = fs::read_to_string(entry.path().join("information")).unwrap_or_default();
            if let Some(model) = parse_nvidia_information(&info) {
                if let Some(gpu) = found
                    .iter_mut()
                    .find(|gpu| gpu.bus.as_deref() == Some(bus.as_str()))
                {
                    gpu.model = Some(model);
                }
            }
        }
    }
    // Memory comes from the management tool where there is one. One spawn,
    // at startup, never per request.
    if found.iter().any(|gpu| gpu.vendor == "nvidia") {
        if let Ok(output) = Command::new("nvidia-smi")
            .args([
                "--query-gpu=pci.bus_id,name,memory.total,driver_version",
                "--format=csv,noheader,nounits",
            ])
            .output()
        {
            if output.status.success() {
                let rows = parse_nvidia_smi_csv(&String::from_utf8_lossy(&output.stdout));
                for (bus, name, memory_mb, driver) in rows {
                    if let Some(gpu) = found.iter_mut().find(|gpu| {
                        gpu.bus.as_deref().map(normalise_bus) == Some(normalise_bus(&bus))
                    }) {
                        gpu.model.get_or_insert(name);
                        gpu.memory_mb = memory_mb;
                        gpu.driver = Some(driver);
                    }
                }
            }
        }
    }
    for (index, gpu) in found.iter_mut().enumerate() {
        gpu.index = index as u64;
    }
    found
}

/// Walk `/sys/bus/pci/devices`, keeping class `0x03xxxx` (display).
fn pci_gpus(dir: &Path) -> Vec<Gpu> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<_> = entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .collect();
    names.sort();
    let mut gpus = Vec::new();
    for name in names {
        let device = dir.join(&name);
        let class = fs::read_to_string(device.join("class")).unwrap_or_default();
        let vendor = fs::read_to_string(device.join("vendor")).unwrap_or_default();
        if let Some(vendor) = classify_pci(vendor.trim(), class.trim()) {
            let model = fs::read_to_string(device.join("product_name"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let driver = fs::read_link(device.join("driver"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));
            // AMD exposes VRAM size here on amdgpu.
            let memory_mb = fs::read_to_string(device.join("mem_info_vram_total"))
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|bytes| bytes / (1024 * 1024));
            gpus.push(Gpu {
                index: 0,
                vendor,
                model,
                memory_mb,
                bus: Some(name),
                driver,
            });
        }
    }
    gpus
}

/// A PCI device is a GPU when its class is display (`0x03`). Returns the
/// vendor name for the three everyone has heard of and the raw id otherwise.
pub fn classify_pci(vendor: &str, class: &str) -> Option<String> {
    let class = class.trim_start_matches("0x");
    if !class.starts_with("03") || class.len() < 4 {
        return None;
    }
    Some(
        match vendor
            .trim_start_matches("0x")
            .to_ascii_lowercase()
            .as_str()
        {
            "10de" => "nvidia".to_string(),
            "1002" => "amd".to_string(),
            "8086" => "intel".to_string(),
            other => format!("pci:{other}"),
        },
    )
}

/// `Model: NVIDIA A100-SXM4-80GB` from `/proc/driver/nvidia/gpus/*/information`.
pub fn parse_nvidia_information(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        line.strip_prefix("Model:")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    })
}

/// Rows of `nvidia-smi --query-gpu=pci.bus_id,name,memory.total,driver_version
/// --format=csv,noheader,nounits`: `(bus, name, memory_mb, driver)`.
pub fn parse_nvidia_smi_csv(text: &str) -> Vec<(String, String, Option<u64>, String)> {
    text.lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            if fields.len() < 4 {
                return None;
            }
            Some((
                fields[0].to_string(),
                fields[1].to_string(),
                fields[2].parse::<u64>().ok(),
                fields[3].to_string(),
            ))
        })
        .collect()
}

/// `nvidia-smi` prints `00000000:17:00.0`; sysfs names the device
/// `0000:17:00.0`. Compare on the last three segments, lower-cased.
fn normalise_bus(bus: &str) -> String {
    let lower = bus.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split(':').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(":")
    } else {
        lower
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpuinfo_yields_model_sockets_and_the_flags_a_solver_cares_about() {
        let text = "processor\t: 0\nmodel name\t: AMD EPYC 7763 64-Core Processor\nphysical id\t: 0\nflags\t\t: fpu vme avx avx2 fma bmi2 adx sha_ni\n\nprocessor\t: 1\nmodel name\t: AMD EPYC 7763 64-Core Processor\nphysical id\t: 1\nflags\t\t: fpu avx avx2 avx512f\n";
        let (model, sockets, features) = parse_cpuinfo(text);
        assert_eq!(model.as_deref(), Some("AMD EPYC 7763 64-Core Processor"));
        assert_eq!(sockets, Some(2));
        assert_eq!(
            features,
            ["adx", "avx", "avx2", "avx512f", "bmi2", "fma", "sha_ni"]
        );
        let arm = "processor\t: 0\nFeatures\t: fp asimd sve sve2\nCPU part\t: 0xd0c\n";
        let (model, sockets, features) = parse_cpuinfo(arm);
        assert_eq!(model.as_deref(), Some("arm part 0xd0c"));
        assert_eq!(sockets, None);
        assert_eq!(features, ["sve", "sve2"]);
    }

    #[test]
    fn meminfo_and_cgroup_files_parse_as_the_kernel_writes_them() {
        assert_eq!(
            parse_meminfo_mb("MemTotal:       16314372 kB\n"),
            Some(15932)
        );
        assert_eq!(parse_meminfo_mb(""), None);
        assert_eq!(
            parse_cgroup_path("0::/system.slice/cairn-agent.service\n").as_deref(),
            Some("/system.slice/cairn-agent.service")
        );
        assert_eq!(parse_cpu_max("max 100000\n"), None);
        assert_eq!(parse_cpu_max("400000 100000\n"), Some(4));
        assert_eq!(parse_cpu_max("50000 100000\n"), Some(1));
        assert_eq!(parse_cpu_max("garbage"), None);
    }

    #[test]
    fn pci_display_controllers_are_gpus_and_named_by_vendor() {
        assert_eq!(
            classify_pci("0x10de", "0x030000").as_deref(),
            Some("nvidia")
        );
        assert_eq!(
            classify_pci("0x10de", "0x030200").as_deref(),
            Some("nvidia")
        );
        assert_eq!(classify_pci("0x1002", "0x038000").as_deref(), Some("amd"));
        assert_eq!(classify_pci("0x8086", "0x030000").as_deref(), Some("intel"));
        assert_eq!(
            classify_pci("0x1234", "0x030000").as_deref(),
            Some("pci:1234")
        );
        assert_eq!(
            classify_pci("0x10de", "0x020000"),
            None,
            "a NIC is not a GPU"
        );
        assert_eq!(classify_pci("0x10de", "0x0c0330"), None);
    }

    #[test]
    fn nvidia_files_and_smi_rows_parse() {
        let info = "Model: \t NVIDIA A100-SXM4-80GB\nIRQ:   \t 0\nBus Location: \t 0000:17:00.0\n";
        assert_eq!(
            parse_nvidia_information(info).as_deref(),
            Some("NVIDIA A100-SXM4-80GB")
        );
        let rows = parse_nvidia_smi_csv(
            "00000000:17:00.0, NVIDIA A100-SXM4-80GB, 81920, 550.54.15\n00000000:65:00.0, NVIDIA A100-SXM4-80GB, 81920, 550.54.15\nshort\n",
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].2, Some(81920));
        assert_eq!(normalise_bus(&rows[0].0), normalise_bus("0000:17:00.0"));
    }

    #[test]
    fn the_probe_runs_and_describes_at_least_the_platform() {
        let inventory = Inventory::probe();
        assert!(!inventory.hostname.is_empty());
        let value = inventory.to_value();
        assert!(value.get("cpus").is_some());
        assert!(value.get("gpus").unwrap().as_array().is_some());
        assert!(!inventory.device_name().is_empty());
    }
}
