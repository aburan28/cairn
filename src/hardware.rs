//! CPU observations for routing and experiment provenance, never proof of work.
//!
//! Clock readings are integer kHz. A boost ceiling is not a sustained rate;
//! neither a clock nor an ISA flag measures a workload's throughput.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::canonical::Value;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuProfile {
    pub arch: String,
    pub vendor: Option<String>,
    pub model: Option<String>,
    /// Features usable by this process, including the OS's vector-state support.
    pub features: Vec<String>,
    /// Common flags reported by the OS, before runtime gating.
    pub reported_features: Vec<String>,
    pub base_khz: Option<u64>,
    pub max_khz: Option<u64>,
    pub observed_min_khz: Option<u64>,
    pub observed_max_khz: Option<u64>,
    pub source: String,
    pub observed_at: String,
}

impl CpuProfile {
    /// Sample again before a registration or experiment: frequency and VM
    /// configuration can change during an agent's lifetime.
    pub fn probe() -> Self {
        let mut cpu = Self::from_cpuinfo(
            &fs::read_to_string("/proc/cpuinfo").unwrap_or_default(),
            std::env::consts::ARCH,
        );
        let runtime = runtime_features();
        if cfg!(target_os = "linux") {
            // Taking the common set across *all* listed CPUs is conservative
            // when affinity selects only some of them. A union can SIGILL as
            // soon as the scheduler moves the worker to another core.
            cpu.features = cpu
                .reported_features
                .iter()
                .filter(|feature| runtime.contains(feature.as_str()))
                .cloned()
                .collect();
            cpu.base_khz = policy_min(
                Path::new("/sys/devices/system/cpu/cpufreq"),
                "base_frequency",
            );
            cpu.max_khz = policy_min(
                Path::new("/sys/devices/system/cpu/cpufreq"),
                "cpuinfo_max_freq",
            );
            cpu.source = "linux_cpuinfo_intersection+runtime".into();
        } else {
            cpu.features = runtime.into_iter().collect();
            cpu.source = "runtime".into();
        }
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            let (vendor, model) = x86_identity();
            cpu.vendor = cpu.vendor.or(vendor);
            cpu.model = cpu.model.or(model);
        }
        #[cfg(target_os = "macos")]
        {
            cpu.model = cpu
                .model
                .or_else(|| sysctl("machdep.cpu.brand_string"))
                .or_else(|| sysctl("hw.model"));
            cpu.base_khz = sysctl("hw.cpufrequency")
                .and_then(|s| s.parse::<u64>().ok())
                .map(|hz| hz / 1000);
            cpu.max_khz = sysctl("hw.cpufrequency_max")
                .and_then(|s| s.parse::<u64>().ok())
                .map(|hz| hz / 1000);
        }
        cpu.observed_at = crate::time::timestamp();
        cpu
    }

    /// Parse without depending on the machine running the test. Missing flags
    /// on one processor mean the common feature set is unknown (empty).
    pub fn from_cpuinfo(text: &str, arch: &str) -> Self {
        let mut cpu = Self {
            arch: arch.into(),
            ..Self::default()
        };
        let mut common: Option<BTreeSet<String>> = None;
        let mut clocks = Vec::new();
        let mut models = BTreeSet::new();
        let mut vendors = BTreeSet::new();
        let mut parts = BTreeSet::new();
        for block in text.split("\n\n").filter(|block| !block.trim().is_empty()) {
            let mut flags = BTreeSet::new();
            let mut processor = false;
            for line in block.lines() {
                let Some((key, value)) = line.split_once(':') else {
                    continue;
                };
                let value = value.trim();
                match key.trim() {
                    "processor" => processor = true,
                    "vendor_id" | "CPU implementer" if !value.is_empty() => {
                        vendors.insert(value.to_string());
                    }
                    "model name" if !value.is_empty() => {
                        models.insert(value.to_string());
                    }
                    "CPU part" if !value.is_empty() => {
                        parts.insert(value.to_string());
                    }
                    "flags" | "Features" => {
                        flags.extend(value.split_whitespace().map(normalize_feature))
                    }
                    "cpu MHz" => {
                        if let Some(khz) = mhz_to_khz(value) {
                            clocks.push(khz);
                        }
                    }
                    _ => {}
                }
            }
            if processor {
                common = Some(match common {
                    None => flags,
                    Some(old) => old.intersection(&flags).cloned().collect(),
                });
            }
        }
        cpu.reported_features = common.unwrap_or_default().into_iter().collect();
        cpu.vendor = match vendors.len() {
            0 => None,
            1 => vendors.into_iter().next(),
            _ => Some("mixed CPU vendors".into()),
        };
        cpu.model = match models.len() {
            0 => None,
            1 => models.into_iter().next(),
            _ => Some("mixed CPU models".into()),
        };
        if cpu.model.is_none() && !parts.is_empty() {
            cpu.model = Some(format!(
                "arm part{} {}",
                if parts.len() > 1 { "s" } else { "" },
                parts.into_iter().collect::<Vec<_>>().join(",")
            ));
        }
        cpu.observed_min_khz = clocks.iter().min().copied();
        cpu.observed_max_khz = clocks.iter().max().copied();
        cpu
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("arch", Value::string(&self.arch)),
            ("vendor", optional_text(&self.vendor)),
            ("model", optional_text(&self.model)),
            ("features", strings(&self.features)),
            ("reported_features", strings(&self.reported_features)),
            ("base_khz", optional_int(self.base_khz)),
            ("max_khz", optional_int(self.max_khz)),
            ("observed_min_khz", optional_int(self.observed_min_khz)),
            ("observed_max_khz", optional_int(self.observed_max_khz)),
            ("source", Value::string(&self.source)),
            ("observed_at", Value::string(&self.observed_at)),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Self, String> {
        object(value, "CPU profile")?;
        Ok(Self {
            arch: text(value, "arch")?.ok_or("CPU profile needs arch")?,
            vendor: text(value, "vendor")?,
            model: text(value, "model")?,
            features: features(value, "features")?,
            reported_features: features(value, "reported_features")?,
            base_khz: number(value, "base_khz")?,
            max_khz: number(value, "max_khz")?,
            observed_min_khz: number(value, "observed_min_khz")?,
            observed_max_khz: number(value, "observed_max_khz")?,
            source: text(value, "source")?.unwrap_or_else(|| "host_report".into()),
            observed_at: text(value, "observed_at")?.unwrap_or_default(),
        })
    }
}

/// Exact feature names: `avx512f` does not imply `avx512bw`, IFMA, or VNNI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CpuRequirements {
    pub arch: Option<String>,
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub features: Vec<String>,
    /// A reported base clock floor, never a sustained-throughput guarantee.
    pub min_base_khz: Option<u64>,
}

impl CpuRequirements {
    pub fn from_value(value: &Value) -> Result<Self, String> {
        let fields = object(value, "CPU requirements")?;
        if fields.keys().any(|key| {
            !["arch", "vendor", "model", "features", "min_base_khz"].contains(&key.as_str())
        }) {
            return Err(
                "unknown CPU requirement; expected arch, vendor, model, features, min_base_khz"
                    .into(),
            );
        }
        Ok(Self {
            arch: text(value, "arch")?,
            vendor: text(value, "vendor")?,
            model: text(value, "model")?,
            features: features(value, "features")?,
            min_base_khz: number(value, "min_base_khz")?,
        })
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("arch", optional_text(&self.arch)),
            ("vendor", optional_text(&self.vendor)),
            ("model", optional_text(&self.model)),
            ("features", strings(&self.features)),
            ("min_base_khz", optional_int(self.min_base_khz)),
        ])
    }

    pub fn matches(&self, cpu: Option<&CpuProfile>) -> bool {
        if *self == Self::default() {
            return true;
        }
        let Some(cpu) = cpu else { return false };
        self.arch.as_ref().is_none_or(|arch| arch == &cpu.arch)
            && self
                .vendor
                .as_ref()
                .is_none_or(|vendor| Some(vendor) == cpu.vendor.as_ref())
            && self
                .model
                .as_ref()
                .is_none_or(|model| Some(model) == cpu.model.as_ref())
            && self
                .features
                .iter()
                .all(|feature| cpu.features.contains(feature))
            && self
                .min_base_khz
                .is_none_or(|minimum| cpu.base_khz.is_some_and(|base| base >= minimum))
    }
}

pub(crate) fn object<'a>(
    value: &'a Value,
    label: &str,
) -> Result<&'a std::collections::BTreeMap<String, Value>, String> {
    value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))
}
pub(crate) fn number(value: &Value, name: &str) -> Result<Option<u64>, String> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{name} must be a non-negative integer")),
    }
}
pub(crate) fn text(value: &Value, name: &str) -> Result<Option<String>, String> {
    match value.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s))
            if !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control) =>
        {
            Ok(Some(s.clone()))
        }
        _ => Err(format!("{name} must be 1-256 printable bytes")),
    }
}
pub(crate) fn optional_int(value: Option<u64>) -> Value {
    value.map_or(Value::Null, |n| Value::Int(i128::from(n)))
}
fn optional_text(value: &Option<String>) -> Value {
    value.as_ref().map_or(Value::Null, Value::string)
}
fn strings(values: &[String]) -> Value {
    Value::array(values.iter().map(Value::string))
}
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn nonempty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.into())
}
fn normalize_feature(s: &str) -> String {
    if let Some(suffix) = s.strip_prefix("avx512_") {
        return format!("avx512{suffix}");
    }
    match s {
        "pni" => "sse3",
        "sha_ni" => "sha",
        "asimd" => "neon",
        "asimddp" => "dotprod",
        "crc32" => "crc",
        "sse4_1" => "sse4.1",
        "sse4_2" => "sse4.2",
        _ => s,
    }
    .into()
}
fn features(value: &Value, name: &str) -> Result<Vec<String>, String> {
    let items = match value.get(name) {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(items)) if items.len() <= 256 => items,
        _ => {
            return Err(format!(
                "{name} must be an array of at most 256 feature names"
            ))
        }
    };
    let mut names = BTreeSet::new();
    for item in items {
        let Some(s) = item.as_str() else {
            return Err(format!("{name} must contain feature names"));
        };
        if s.is_empty()
            || s.len() > 48
            || s == "avx512"
            || !s
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
        {
            return Err(format!(
                "invalid feature {s:?}; use exact lowercase names such as avx512f, avx512bw"
            ));
        }
        names.insert(normalize_feature(s));
    }
    Ok(names.into_iter().collect())
}
fn mhz_to_khz(text: &str) -> Option<u64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let fractional: String = fraction
        .chars()
        .take(3)
        .chain(std::iter::repeat('0'))
        .take(3)
        .collect();
    whole
        .parse::<u64>()
        .ok()?
        .checked_mul(1000)?
        .checked_add(fractional.parse().ok()?)
        .filter(|n| *n > 0)
}
fn policy_min(root: &Path, name: &str) -> Option<u64> {
    let mut minimum = None;
    for entry in fs::read_dir(root).ok()?.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("policy") {
            continue;
        }
        // A missing policy must not let the faster cores stand in for it.
        let khz = fs::read_to_string(entry.path().join(name))
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()?;
        if khz == 0 {
            return None;
        }
        minimum = Some(minimum.map_or(khz, |old: u64| old.min(khz)));
    }
    minimum
}

#[cfg(target_os = "macos")]
fn sysctl(name: &str) -> Option<String> {
    let output = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", name])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_arch = "x86")]
use std::arch::x86;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64 as x86;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[allow(unused_unsafe)] // CPUID was unsafe on the minimum supported Rust.
fn x86_identity() -> (Option<String>, Option<String>) {
    // CPUID is baseline on x86_64 and on the x86 targets Rust supports here.
    unsafe {
        let leaf = x86::__cpuid(0);
        let vendor = [
            leaf.ebx.to_le_bytes(),
            leaf.edx.to_le_bytes(),
            leaf.ecx.to_le_bytes(),
        ]
        .concat();
        let vendor = String::from_utf8(vendor)
            .ok()
            .filter(|s| !s.trim_matches('\0').is_empty());
        let max = x86::__cpuid(0x8000_0000).eax;
        let model = if max >= 0x8000_0004 {
            let mut bytes = Vec::new();
            for leaf in 0x8000_0002..=0x8000_0004 {
                let r = x86::__cpuid(leaf);
                for n in [r.eax, r.ebx, r.ecx, r.edx] {
                    bytes.extend(n.to_le_bytes());
                }
            }
            String::from_utf8(bytes)
                .ok()
                .and_then(|s| nonempty(s.trim_matches('\0').trim()))
        } else {
            None
        };
        (vendor, model)
    }
}

// Keep the vector-state gate separate from CPUID so fixtures cover a VM that
// exposes AVX-512 hardware bits without the OS preserving ZMM registers.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
fn x86_features(
    ecx: u32,
    edx: u32,
    ebx7: u32,
    ecx7: u32,
    edx7: u32,
    eax71: u32,
    xcr0: u64,
) -> BTreeSet<String> {
    let mut features = BTreeSet::new();
    let avx =
        ecx & (1 << 28) != 0 && ecx & (1 << 27) != 0 && ecx & (1 << 26) != 0 && xcr0 & 0x6 == 0x6;
    let zmm = avx && xcr0 & 0xe6 == 0xe6 && ebx7 & (1 << 16) != 0;
    for (name, present) in [
        ("sse2", edx & (1 << 26) != 0),
        ("sse3", ecx & 1 != 0),
        ("ssse3", ecx & (1 << 9) != 0),
        ("sse4.1", ecx & (1 << 19) != 0),
        ("sse4.2", ecx & (1 << 20) != 0),
        ("aes", ecx & (1 << 25) != 0),
        ("pclmulqdq", ecx & (1 << 1) != 0),
        ("avx", avx && ecx & (1 << 28) != 0),
        ("avx2", avx && ecx & (1 << 28) != 0 && ebx7 & (1 << 5) != 0),
        ("fma", avx && ecx & (1 << 28) != 0 && ecx & (1 << 12) != 0),
        ("f16c", avx && ecx & (1 << 28) != 0 && ecx & (1 << 29) != 0),
        ("bmi1", ebx7 & (1 << 3) != 0),
        ("bmi2", ebx7 & (1 << 8) != 0),
        ("adx", ebx7 & (1 << 19) != 0),
        ("sha", ebx7 & (1 << 29) != 0),
        ("avx512f", zmm),
        ("avx512dq", zmm && ebx7 & (1 << 17) != 0),
        ("avx512ifma", zmm && ebx7 & (1 << 21) != 0),
        ("avx512cd", zmm && ebx7 & (1 << 28) != 0),
        ("avx512bw", zmm && ebx7 & (1 << 30) != 0),
        ("avx512vl", zmm && ebx7 & (1 << 31) != 0),
        ("avx512vbmi", zmm && ecx7 & (1 << 1) != 0),
        ("avx512vbmi2", zmm && ecx7 & (1 << 6) != 0),
        ("avx512vnni", zmm && ecx7 & (1 << 11) != 0),
        ("avx512bitalg", zmm && ecx7 & (1 << 12) != 0),
        ("avx512vpopcntdq", zmm && ecx7 & (1 << 14) != 0),
        ("avx512bf16", zmm && eax71 & (1 << 5) != 0),
        ("avx512fp16", zmm && edx7 & (1 << 23) != 0),
    ] {
        if present {
            features.insert(name.into());
        }
    }
    features
}

fn runtime_features() -> BTreeSet<String> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    unsafe {
        let max = x86::__cpuid(0).eax;
        if max < 1 {
            return BTreeSet::new();
        }
        let r = x86::__cpuid(1);
        // XGETBV itself faults without OSXSAVE; never issue it speculatively.
        let xcr0 = if r.ecx & ((1 << 26) | (1 << 27)) == ((1 << 26) | (1 << 27)) {
            x86::_xgetbv(0)
        } else {
            0
        };
        let mut r7 = [0; 3];
        let mut r71 = 0;
        if max >= 7 {
            let leaf = x86::__cpuid_count(7, 0);
            r7 = [leaf.ebx, leaf.ecx, leaf.edx];
            if leaf.eax >= 1 {
                r71 = x86::__cpuid_count(7, 1).eax;
            }
        }
        x86_features(r.ecx, r.edx, r7[0], r7[1], r7[2], r71, xcr0)
    }
    #[cfg(target_arch = "aarch64")]
    {
        let mut features = BTreeSet::new();
        macro_rules! detect { ($($name:tt),*) => { $(if std::arch::is_aarch64_feature_detected!($name) { features.insert($name.into()); })* }; }
        detect!("neon", "aes", "sha2", "sha3", "crc", "dotprod", "sve", "sve2", "i8mm", "bf16");
        features
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
    {
        BTreeSet::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn heterogeneous_cores_and_missing_flags_never_form_a_union() {
        let text = "processor: 0\nmodel name: Test CPU\nflags: avx avx2 avx512f sha_ni\ncpu MHz: 2400.1259\n\nprocessor: 1\nflags: avx avx2 sha_ni\ncpu MHz: 1800\n";
        let cpu = CpuProfile::from_cpuinfo(text, "x86_64");
        assert_eq!(cpu.reported_features, ["avx", "avx2", "sha"]);
        assert_eq!(
            (cpu.observed_min_khz, cpu.observed_max_khz),
            (Some(1_800_000), Some(2_400_125))
        );
        assert!(
            CpuProfile::from_cpuinfo(&format!("{text}\nprocessor: 2\n"), "x86_64")
                .reported_features
                .is_empty()
        );
        for bad in ["nan", "1e3", "-1", "18446744073709551615"] {
            assert_eq!(mhz_to_khz(bad), None);
        }
        assert_eq!(
            CpuProfile::from_cpuinfo(
                "processor: 0\nmodel name: Fast\n\nprocessor: 1\nmodel name: Slow\n",
                "x86_64"
            )
            .model
            .as_deref(),
            Some("mixed CPU models")
        );
        assert_eq!(CpuProfile::from_cpuinfo("processor: 0\nCPU implementer: 0x41\nCPU part: 0xd0c\nFeatures: asimd asimddp crc32\n", "aarch64").model.as_deref(), Some("arm part 0xd0c"));
    }
    #[test]
    fn avx512_needs_os_vector_state_and_each_specific_extension() {
        let ecx = (1 << 26) | (1 << 27) | (1 << 28);
        let ebx = (1 << 5) | (1 << 16) | (1 << 30);
        assert!(!x86_features(ecx & !(1 << 27), 0, ebx, 0, 0, 0, 0xe6).contains("avx2"));
        let ymm = x86_features(ecx, 0, ebx, 0, 0, 0, 6);
        assert!(ymm.contains("avx2"));
        assert!(!ymm.contains("avx512f"));
        let zmm = x86_features(ecx, 0, ebx, 0, 0, 0, 0xe6);
        assert!(zmm.contains("avx512f") && zmm.contains("avx512bw"));
        assert!(!zmm.contains("avx512ifma"));
        assert!(!x86_features(ecx & !(1 << 28), 0, ebx, 0, 0, 0, 0xe6).contains("avx512f"));
        let reported =
            CpuProfile::from_cpuinfo("processor: 0\nflags: avx512_vnni avx512_bf16\n", "x86_64");
        assert_eq!(reported.reported_features, ["avx512bf16", "avx512vnni"]);
    }
    #[test]
    fn requirements_fail_closed_on_missing_profiles_and_peak_only_clocks() {
        let requirements = CpuRequirements::from_value(
            &Value::from_json(r#"{"features":["avx512f","avx512bw"],"min_base_khz":2000000}"#)
                .unwrap(),
        )
        .unwrap();
        let mut cpu = CpuProfile {
            features: vec!["avx512f".into(), "avx512bw".into()],
            max_khz: Some(4_000_000),
            ..CpuProfile::default()
        };
        assert!(!requirements.matches(None));
        assert!(!requirements.matches(Some(&cpu)));
        cpu.base_khz = Some(2_000_000);
        assert!(requirements.matches(Some(&cpu)));
        cpu.features.pop();
        assert!(!requirements.matches(Some(&cpu)));
        for bad in [
            r#"{"features":["avx512"]}"#,
            r#"{"feautres":["avx2"]}"#,
            r#"{"min_base_khz":-1}"#,
        ] {
            assert!(CpuRequirements::from_value(&Value::from_json(bad).unwrap()).is_err());
        }
    }
}
