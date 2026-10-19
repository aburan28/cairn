//! `solver.json`: what a solver package is, read strictly.
//!
//! Strict because two nodes that read one manifest differently disagree about
//! which program a contributor's machine is about to run. An unknown top-level
//! key is refused rather than ignored, so a field added in a later ABI cannot
//! mean something on one node and nothing on another; the way to add one is a
//! new `abi` string. The single exception is a *target* name this build does
//! not know, which is kept and skipped: a package that adds a `wasm32-wasip1`
//! build next year should still run on today's nodes through the targets they
//! do know.

use std::collections::BTreeMap;
use std::fmt;

use crate::blobs;
use crate::canonical::{Value, DIGEST_PREFIX};

/// The one ABI this build speaks. See [`super`] for what it promises.
pub const ABI: &str = "cairn-solver/v1";

/// Most files in one package. A solver is a program and its data, not a tree.
pub const MAX_FILES: usize = 256;
/// Largest single file. Room for a statically linked native solver.
pub const MAX_FILE_BYTES: u64 = 32 << 20;
/// Largest package, all files together.
pub const MAX_PACKAGE_BYTES: u64 = 64 << 20;
/// Largest manifest, canonically encoded. It has to fit in one request body.
pub const MAX_MANIFEST_BYTES: usize = 512 << 10;
/// Most known-answer tests. Every node that offers the package runs them all.
pub const MAX_TESTS: usize = 16;
/// Largest test assignment, canonically encoded.
pub const MAX_ASSIGNMENT_BYTES: usize = 64 << 10;
/// Most candidates a test may expect, and a round may print.
pub const MAX_CANDIDATES: usize = 256;
/// Longest round a package may ask for. Past an hour a round outlives the
/// epoch its assignment was cut for.
pub const MAX_ROUND_SECONDS: u64 = 3600;
pub const DEFAULT_ROUND_SECONDS: u64 = 600;
/// Memory a round may ask for. The node's own `CAIRN_SANDBOX_MEMORY_MB` is
/// not consulted: that is a cap on *verifiers*, and a solver is meant to use
/// the machine it was given.
pub const MAX_MEMORY_MB: u64 = 16 << 10;
pub const DEFAULT_MEMORY_MB: u64 = 1024;
const MIN_MEMORY_MB: u64 = 64;

/// The platforms this build can run, by the name a manifest uses.
///
/// Not Rust target triples: `x86_64-unknown-linux-gnu` and `-musl` are one
/// platform to somebody choosing which binary to run, and a manifest that had
/// to say which libc its binary was linked against would be wrong about it
/// half the time. A Linux build should be static; the jail shows `/usr` and
/// `/lib`, so a dynamic one that links only against glibc also runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Platform {
    DarwinArm64,
    DarwinX86_64,
    LinuxX86_64,
    LinuxArm64,
    /// A Python 3 script run by the same interpreter, in the same jail, as
    /// the objective's own pinned checker. Standard library only: nothing in
    /// the jail can install a package.
    Python3,
}

impl Platform {
    pub const ALL: [Platform; 5] = [
        Platform::DarwinArm64,
        Platform::DarwinX86_64,
        Platform::LinuxX86_64,
        Platform::LinuxArm64,
        Platform::Python3,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Platform::DarwinArm64 => "darwin-arm64",
            Platform::DarwinX86_64 => "darwin-x86_64",
            Platform::LinuxX86_64 => "linux-x86_64",
            Platform::LinuxArm64 => "linux-arm64",
            Platform::Python3 => "python3",
        }
    }

    pub fn parse(name: &str) -> Option<Platform> {
        Platform::ALL.into_iter().find(|p| p.as_str() == name)
    }

    pub fn is_native(self) -> bool {
        self != Platform::Python3
    }

    /// The native platform this process is running on, if a manifest can
    /// name it.
    pub fn host() -> Option<Platform> {
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            Some(Platform::DarwinArm64)
        } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            Some(Platform::DarwinX86_64)
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Some(Platform::LinuxX86_64)
        } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
            Some(Platform::LinuxArm64)
        } else {
            None
        }
    }

    /// Which of the bytes' formats this platform accepts as its entry
    /// point, or why not. Checked at publish and again before every first
    /// run, so a Linux binary filed under `darwin-arm64` is refused with that
    /// sentence rather than failing to exec inside a jail with `Exec format
    /// error`, which reads like a broken sandbox.
    pub fn check_entry(self, bytes: &[u8]) -> Result<(), String> {
        match self {
            Platform::Python3 => {
                if bytes.contains(&0) {
                    return Err(
                        "a python3 entry must be a text file; this one has NUL bytes".into(),
                    );
                }
                std::str::from_utf8(bytes)
                    .map(|_| ())
                    .map_err(|_| "a python3 entry must be UTF-8 source".into())
            }
            Platform::DarwinArm64 => mach_o(bytes, MACH_ARM64, "arm64"),
            Platform::DarwinX86_64 => mach_o(bytes, MACH_X86_64, "x86_64"),
            Platform::LinuxX86_64 => elf(bytes, ELF_X86_64, "x86_64"),
            Platform::LinuxArm64 => elf(bytes, ELF_AARCH64, "aarch64"),
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

const MACH_ARM64: u32 = 0x0100_000c;
const MACH_X86_64: u32 = 0x0100_0007;
const ELF_X86_64: u16 = 0x3e;
const ELF_AARCH64: u16 = 0xb7;

fn mach_o(bytes: &[u8], cpu: u32, name: &str) -> Result<(), String> {
    let word = |at: usize, little: bool| -> Option<u32> {
        let b: [u8; 4] = bytes.get(at..at + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    match bytes.get(..4) {
        // MH_MAGIC_64, little-endian on disk.
        Some([0xcf, 0xfa, 0xed, 0xfe]) => {
            if word(4, true) == Some(cpu) {
                Ok(())
            } else {
                Err(format!("a 64-bit Mach-O executable, but not for {name}"))
            }
        }
        // FAT_MAGIC: a universal binary, big-endian header, one 20-byte
        // record per slice after the 8-byte header.
        Some([0xca, 0xfe, 0xba, 0xbe]) => {
            let slices = word(4, false).unwrap_or(0).min(32) as usize;
            if (0..slices).any(|i| word(8 + i * 20, false) == Some(cpu)) {
                Ok(())
            } else {
                Err(format!("a universal binary with no {name} slice"))
            }
        }
        _ => Err(format!("not a Mach-O executable for {name}")),
    }
}

fn elf(bytes: &[u8], machine: u16, name: &str) -> Result<(), String> {
    if bytes.get(..4) != Some(b"\x7fELF".as_slice()) {
        return Err(format!("not an ELF executable for {name}"));
    }
    // EI_CLASS 2 is 64-bit, EI_DATA 1 is little-endian; e_machine at 18.
    let class = bytes.get(4).copied();
    let data = bytes.get(5).copied();
    let found = bytes.get(18..20).map(|b| u16::from_le_bytes([b[0], b[1]]));
    if class == Some(2) && data == Some(1) && found == Some(machine) {
        Ok(())
    } else {
        Err(format!(
            "an ELF file, but not a 64-bit little-endian {name} executable"
        ))
    }
}

/// What a target runs: a file in the package and fixed arguments.
///
/// The arguments are the package's, pinned with it. A contributor pressing
/// "Start" chooses no program and types no flags, which is the point: the
/// command that runs is the command the publisher tested and the node
/// checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub entry: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileEntry {
    /// Bare lowercase hex, the spelling [`blobs::address`] produces.
    pub sha256: [u8; 32],
    pub size: u64,
}

impl FileEntry {
    pub fn hex(&self) -> String {
        crate::hex::encode(&self.sha256)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources {
    pub memory_mb: u64,
    pub round_seconds: u64,
}

/// One known-answer test: an assignment, and what the solver must do with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestVector {
    pub name: String,
    pub assignment: Value,
    /// `CAIRN_ROUND` for this run.
    pub round: u64,
    /// Exactly these candidates, in any order. The test that makes a
    /// package's behaviour a fact anyone can re-derive rather than a claim.
    pub expect: Option<Vec<Value>>,
    /// Every candidate printed must be accepted by the objective's pinned
    /// verifier, and there must be at least one.
    pub verify_accept: bool,
}

/// A parsed, statically valid manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub summary: String,
    /// The objective this package was written for, when it says. Optional,
    /// because a package an objective pins is written before that
    /// objective's id exists.
    pub objective: Option<String>,
    pub targets: BTreeMap<Platform, Target>,
    /// Target names this build does not know. Kept so they can be reported;
    /// never run.
    pub other_targets: Vec<String>,
    pub files: BTreeMap<String, FileEntry>,
    pub resources: Resources,
    pub tests: Vec<TestVector>,
    raw: Value,
}

/// Why a manifest is not a v1 solver package. Always the publisher's to fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub String);

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Invalid {}

fn invalid<T>(message: impl Into<String>) -> Result<T, Invalid> {
    Err(Invalid(message.into()))
}

const TOP_LEVEL: [&str; 9] = [
    "abi",
    "name",
    "version",
    "summary",
    "objective",
    "targets",
    "files",
    "resources",
    "tests",
];

impl Manifest {
    pub fn from_value(value: &Value) -> Result<Manifest, Invalid> {
        let Some(object) = value.as_object() else {
            return invalid("solver.json must be a JSON object");
        };
        if let Some(key) = object.keys().find(|k| !TOP_LEVEL.contains(&k.as_str())) {
            return invalid(format!(
                "unknown field {key:?}; {ABI} has exactly {}",
                TOP_LEVEL.join(", ")
            ));
        }
        if value.canonical_bytes().len() > MAX_MANIFEST_BYTES {
            return invalid(format!("solver.json is over {MAX_MANIFEST_BYTES} bytes"));
        }
        match object.get("abi").and_then(Value::as_str) {
            Some(ABI) => {}
            Some(other) => {
                return invalid(format!("abi {other:?} is not one this node speaks ({ABI})"))
            }
            None => return invalid(format!("abi is required and must be {ABI:?}")),
        }
        let name = required_str(object, "name")?;
        if !(1..=64).contains(&name.len())
            || !name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
        {
            return invalid(
                "name is 1-64 of a-z, 0-9, '.', '_', '-', starting with a letter or digit",
            );
        }
        let version = required_str(object, "version")?;
        if !(1..=32).contains(&version.len())
            || !version.starts_with(|c: char| c.is_ascii_alphanumeric())
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+_-".contains(&b))
        {
            return invalid("version is 1-32 of letters, digits, '.', '+', '_', '-'");
        }
        let summary = match object.get("summary") {
            None => String::new(),
            Some(Value::String(text)) if text.chars().count() <= 500 => text.clone(),
            Some(_) => return invalid("summary is a string of at most 500 characters"),
        };
        let objective = match object.get("objective") {
            None => None,
            Some(Value::String(id)) if is_record_id(id) => Some(id.clone()),
            Some(_) => return invalid("objective is an objective id, sha256:<64 hex>"),
        };

        let files = parse_files(object.get("files"))?;
        let (targets, other_targets) = parse_targets(object.get("targets"), &files)?;
        let resources = parse_resources(object.get("resources"))?;
        let tests = parse_tests(object.get("tests"))?;

        Ok(Manifest {
            name: name.to_string(),
            version: version.to_string(),
            summary,
            objective,
            targets,
            other_targets,
            files,
            resources,
            tests,
            raw: value.clone(),
        })
    }

    pub fn from_json(text: &str) -> Result<Manifest, Invalid> {
        let value = Value::from_json(text).map_err(|e| Invalid(format!("solver.json: {e}")))?;
        Manifest::from_value(&value)
    }

    /// The package's identity: the digest of its canonical manifest, which
    /// names every file by hash. One pin covers the program, its data, its
    /// arguments and its tests.
    pub fn id(&self) -> String {
        self.raw.digest()
    }

    pub fn to_value(&self) -> &Value {
        &self.raw
    }

    pub fn total_bytes(&self) -> u64 {
        self.files.values().map(|f| f.size).sum()
    }

    /// The target this host would run: its own native build first, then the
    /// portable script.
    pub fn target_for_host(&self) -> Option<(Platform, &Target)> {
        Platform::host()
            .and_then(|p| self.targets.get(&p).map(|t| (p, t)))
            .or_else(|| {
                self.targets
                    .get(&Platform::Python3)
                    .map(|t| (Platform::Python3, t))
            })
    }
}

fn required_str<'a>(object: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a str, Invalid> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Invalid(format!("{key} is required and must be a string")))
}

/// `sha256:` and 64 lowercase hex digits.
pub fn is_record_id(text: &str) -> bool {
    text.strip_prefix(DIGEST_PREFIX)
        .is_some_and(blobs::is_address)
}

/// Whether `path` may name a file in a package.
///
/// Relative, `/`-separated, from a small alphabet, no empty, `.` or `..`
/// component and nothing hidden. Every one of those rules is about the same
/// thing: the path is joined onto a directory on somebody else's disk, and it
/// arrived from a stranger.
pub fn valid_path(path: &str) -> bool {
    path.len() <= 200
        && path != "solver.json"
        && path.split('/').count() <= 8
        && path.split('/').all(|part| {
            !part.is_empty()
                && !part.starts_with('.')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

fn parse_files(value: Option<&Value>) -> Result<BTreeMap<String, FileEntry>, Invalid> {
    let Some(object) = value.and_then(Value::as_object) else {
        return invalid("files is required: an object of path -> {sha256, size}");
    };
    if object.is_empty() || object.len() > MAX_FILES {
        return invalid(format!("files lists 1 to {MAX_FILES} files"));
    }
    let mut files = BTreeMap::new();
    let mut total: u64 = 0;
    for (path, entry) in object {
        if !valid_path(path) {
            return invalid(format!(
                "file path {path:?} must be relative, '/'-separated, use only letters, digits, \
                 '.', '_', '-', and have no hidden, empty, '.' or '..' part"
            ));
        }
        let hash = entry.get("sha256").and_then(Value::as_str).unwrap_or("");
        if !blobs::is_address(hash) {
            return invalid(format!(
                "{path}: sha256 must be 64 lowercase hex characters"
            ));
        }
        let Some(size) = entry.get("size").and_then(Value::as_u64) else {
            return invalid(format!("{path}: size must be a non-negative integer"));
        };
        if size > MAX_FILE_BYTES {
            return invalid(format!(
                "{path} is {size} bytes; the limit is {MAX_FILE_BYTES}"
            ));
        }
        if entry.as_object().is_some_and(|o| o.len() != 2) {
            return invalid(format!("{path}: a file entry has exactly sha256 and size"));
        }
        total = total.saturating_add(size);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&crate::hex::decode(hash).unwrap_or_default());
        files.insert(path.clone(), FileEntry { sha256, size });
    }
    if total > MAX_PACKAGE_BYTES {
        return invalid(format!(
            "the package is {total} bytes; the limit is {MAX_PACKAGE_BYTES}"
        ));
    }
    // A file and a directory of the same name cannot both be on disk.
    for path in files.keys() {
        let prefix = format!("{path}/");
        if files.keys().any(|other| other.starts_with(&prefix)) {
            return invalid(format!("{path} is listed as a file and as a directory"));
        }
    }
    Ok(files)
}

fn parse_targets(
    value: Option<&Value>,
    files: &BTreeMap<String, FileEntry>,
) -> Result<(BTreeMap<Platform, Target>, Vec<String>), Invalid> {
    let Some(object) = value.and_then(Value::as_object) else {
        return invalid("targets is required: an object of platform -> {entry, args}");
    };
    if object.is_empty() || object.len() > 16 {
        return invalid("targets names 1 to 16 platforms");
    }
    let mut targets = BTreeMap::new();
    let mut other = Vec::new();
    for (name, spec) in object {
        let Some(fields) = spec.as_object() else {
            return invalid(format!("targets.{name} must be an object"));
        };
        if let Some(key) = fields.keys().find(|k| *k != "entry" && *k != "args") {
            return invalid(format!(
                "targets.{name}: unknown field {key:?} (entry, args)"
            ));
        }
        let entry = fields.get("entry").and_then(Value::as_str).unwrap_or("");
        if !files.contains_key(entry) {
            return invalid(format!(
                "targets.{name}.entry {entry:?} must be one of the listed files"
            ));
        }
        let args = match fields.get("args") {
            None => Vec::new(),
            Some(Value::Array(items)) if items.len() <= 32 => {
                let mut args = Vec::with_capacity(items.len());
                for item in items {
                    match item.as_str() {
                        Some(arg) if arg.len() <= 512 && !arg.contains('\0') => {
                            args.push(arg.to_string())
                        }
                        _ => {
                            return invalid(format!(
                                "targets.{name}.args: each argument is a string of at most 512 \
                                 bytes"
                            ))
                        }
                    }
                }
                args
            }
            Some(_) => {
                return invalid(format!("targets.{name}.args is a list of up to 32 strings"))
            }
        };
        match Platform::parse(name) {
            Some(platform) => {
                targets.insert(
                    platform,
                    Target {
                        entry: entry.to_string(),
                        args,
                    },
                );
            }
            None if valid_target_name(name) => other.push(name.clone()),
            None => return invalid(format!("target name {name:?} is not a platform name")),
        }
    }
    if targets.is_empty() {
        return invalid(format!(
            "no target this node can run; known targets are {}",
            Platform::ALL.map(Platform::as_str).join(", ")
        ));
    }
    Ok((targets, other))
}

fn valid_target_name(name: &str) -> bool {
    (1..=32).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
}

fn parse_resources(value: Option<&Value>) -> Result<Resources, Invalid> {
    let mut resources = Resources {
        memory_mb: DEFAULT_MEMORY_MB,
        round_seconds: DEFAULT_ROUND_SECONDS,
    };
    let Some(value) = value else {
        return Ok(resources);
    };
    let Some(object) = value.as_object() else {
        return invalid("resources must be an object");
    };
    for (key, field) in object {
        let number = field.as_u64();
        match (key.as_str(), number) {
            ("memory_mb", Some(mb)) if (MIN_MEMORY_MB..=MAX_MEMORY_MB).contains(&mb) => {
                resources.memory_mb = mb
            }
            ("round_seconds", Some(s)) if (1..=MAX_ROUND_SECONDS).contains(&s) => {
                resources.round_seconds = s
            }
            ("memory_mb", _) => {
                return invalid(format!(
                    "resources.memory_mb is {MIN_MEMORY_MB} to {MAX_MEMORY_MB}"
                ))
            }
            ("round_seconds", _) => {
                return invalid(format!(
                    "resources.round_seconds is 1 to {MAX_ROUND_SECONDS}"
                ))
            }
            (other, _) => {
                return invalid(format!(
                    "resources: unknown field {other:?} (memory_mb, round_seconds)"
                ))
            }
        }
    }
    Ok(resources)
}

fn parse_tests(value: Option<&Value>) -> Result<Vec<TestVector>, Invalid> {
    let Some(items) = value.and_then(Value::as_array) else {
        return invalid(
            "tests is required: a package proves it implements the interface by passing them",
        );
    };
    if items.is_empty() || items.len() > MAX_TESTS {
        return invalid(format!("tests lists 1 to {MAX_TESTS} known-answer tests"));
    }
    let mut tests = Vec::with_capacity(items.len());
    let mut names = std::collections::BTreeSet::new();
    for (n, item) in items.iter().enumerate() {
        let Some(fields) = item.as_object() else {
            return invalid(format!("tests[{n}] must be an object"));
        };
        const KEYS: [&str; 5] = ["name", "assignment", "round", "expect", "verify"];
        if let Some(key) = fields.keys().find(|k| !KEYS.contains(&k.as_str())) {
            return invalid(format!(
                "tests[{n}]: unknown field {key:?} ({})",
                KEYS.join(", ")
            ));
        }
        let name = fields.get("name").and_then(Value::as_str).unwrap_or("");
        if !(1..=64).contains(&name.len())
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._- ".contains(&b))
        {
            return invalid(format!(
                "tests[{n}].name is 1-64 letters, digits, spaces, '.', '_', '-'"
            ));
        }
        if !names.insert(name.to_string()) {
            return invalid(format!("two tests are named {name:?}"));
        }
        let assignment = match fields.get("assignment") {
            Some(a @ Value::Object(_)) if a.canonical_bytes().len() <= MAX_ASSIGNMENT_BYTES => {
                a.clone()
            }
            _ => {
                return invalid(format!(
                    "tests[{n}].assignment is an object of at most {MAX_ASSIGNMENT_BYTES} bytes, \
                     shaped like GET /work_assignment"
                ))
            }
        };
        let round = match fields.get("round") {
            None => 0,
            Some(v) => match v.as_u64() {
                Some(r) if r <= u64::from(u32::MAX) => r,
                _ => return invalid(format!("tests[{n}].round is a non-negative integer")),
            },
        };
        let expect = match fields.get("expect") {
            None => None,
            Some(Value::Array(items))
                if items.len() <= MAX_CANDIDATES
                    && items.iter().all(|i| i.as_object().is_some()) =>
            {
                Some(items.clone())
            }
            Some(_) => {
                return invalid(format!(
                    "tests[{n}].expect is a list of up to {MAX_CANDIDATES} candidate objects"
                ))
            }
        };
        let verify_accept = match fields.get("verify") {
            None => false,
            Some(Value::String(v)) if v == "accept" => true,
            Some(_) => return invalid(format!("tests[{n}].verify, when present, is \"accept\"")),
        };
        if expect.is_none() && !verify_accept {
            return invalid(format!(
                "tests[{n}] checks nothing: give expect (the exact candidates) or \
                 verify: \"accept\" (the objective's checker accepts what it prints), or both"
            ));
        }
        tests.push(TestVector {
            name: name.to_string(),
            assignment,
            round,
            expect,
            verify_accept,
        });
    }
    Ok(tests)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn minimal() -> Value {
        Value::from_json(&format!(
            r#"{{"abi":"{ABI}","name":"walk","version":"1.0.0",
                "targets":{{"python3":{{"entry":"solve.py","args":["--fast"]}}}},
                "files":{{"solve.py":{{"sha256":"{}","size":3}}}},
                "tests":[{{"name":"zero","assignment":{{"units":{{"first":0,"end":1}}}},
                           "expect":[{{"x":"1"}}]}}]}}"#,
            blobs::address(b"x=1")
        ))
        .unwrap()
    }

    fn with(mut value: Value, key: &str, field: Value) -> Value {
        if let Value::Object(map) = &mut value {
            map.insert(key.into(), field);
        }
        value
    }

    #[test]
    fn a_minimal_manifest_parses_and_its_id_is_its_digest() {
        let value = minimal();
        let manifest = Manifest::from_value(&value).unwrap();
        assert_eq!(manifest.id(), value.digest());
        assert_eq!(manifest.resources.round_seconds, DEFAULT_ROUND_SECONDS);
        assert_eq!(manifest.targets[&Platform::Python3].args, ["--fast"]);
        assert!(manifest.target_for_host().is_some());
    }

    #[test]
    fn unknown_fields_are_refused_but_unknown_targets_are_kept() {
        let refused = with(minimal(), "network", Value::Bool(true));
        assert!(Manifest::from_value(&refused)
            .unwrap_err()
            .0
            .contains("unknown field"));

        let value = with(
            minimal(),
            "targets",
            Value::from_json(
                r#"{"python3":{"entry":"solve.py"},"wasm32-wasip1":{"entry":"solve.py"}}"#,
            )
            .unwrap(),
        );
        let manifest = Manifest::from_value(&value).unwrap();
        assert_eq!(manifest.other_targets, ["wasm32-wasip1"]);
    }

    #[test]
    fn a_path_cannot_leave_the_package() {
        for bad in [
            "../x",
            "/etc/passwd",
            "a//b",
            "a/./b",
            ".hidden",
            "a/..",
            "solver.json",
            "a b",
        ] {
            assert!(!valid_path(bad), "{bad:?} was accepted");
        }
        for good in ["solve.py", "bin/solve-darwin-arm64", "data/job_23.json"] {
            assert!(valid_path(good), "{good:?} was refused");
        }
    }

    #[test]
    fn a_test_must_check_something() {
        let value = with(
            minimal(),
            "tests",
            Value::from_json(r#"[{"name":"idle","assignment":{}}]"#).unwrap(),
        );
        assert!(Manifest::from_value(&value)
            .unwrap_err()
            .0
            .contains("checks nothing"));
        let value = with(minimal(), "tests", Value::array([]));
        assert!(Manifest::from_value(&value).is_err());
    }

    #[test]
    fn the_entry_must_be_a_listed_file() {
        let value = with(
            minimal(),
            "targets",
            Value::from_json(r#"{"python3":{"entry":"other.py"}}"#).unwrap(),
        );
        assert!(Manifest::from_value(&value)
            .unwrap_err()
            .0
            .contains("listed files"));
    }

    #[test]
    fn entry_formats_are_checked_against_their_platform() {
        let mut macho = vec![0xcf, 0xfa, 0xed, 0xfe];
        macho.extend_from_slice(&MACH_ARM64.to_le_bytes());
        assert!(Platform::DarwinArm64.check_entry(&macho).is_ok());
        assert!(Platform::DarwinX86_64.check_entry(&macho).is_err());

        let mut fat = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2];
        fat.extend_from_slice(&MACH_X86_64.to_be_bytes());
        fat.extend_from_slice(&[0; 16]);
        fat.extend_from_slice(&MACH_ARM64.to_be_bytes());
        fat.extend_from_slice(&[0; 16]);
        assert!(Platform::DarwinArm64.check_entry(&fat).is_ok());
        assert!(Platform::DarwinX86_64.check_entry(&fat).is_ok());

        let mut elf = b"\x7fELF\x02\x01".to_vec();
        elf.resize(18, 0);
        elf.extend_from_slice(&ELF_X86_64.to_le_bytes());
        assert!(Platform::LinuxX86_64.check_entry(&elf).is_ok());
        assert!(Platform::LinuxArm64.check_entry(&elf).is_err());
        assert!(Platform::DarwinArm64.check_entry(&elf).is_err());

        assert!(Platform::Python3.check_entry(b"print(1)\n").is_ok());
        assert!(Platform::Python3.check_entry(&elf).is_err());
    }
}
