//! The seed list a node dials when nobody has told it about a peer.
//!
//! # Why it is compiled in
//!
//! `launch/seeds.json` used to reach a node by one route: `make seeds`
//! downloads it with `curl`, `cairn seeds resolve` checks the key files beside
//! it, and the operator passes whatever verified with `--bootstrap`. Cairn.app
//! runs `cairn run` and nothing else, so a node started from the app never saw
//! the list. It heard LAN beacons and read the peer records of a log that
//! starts empty, which made every desktop node LAN-only without saying so.
//!
//! # Why that adds no trust
//!
//! An entry is an address and a transport id. The key a dial needs is asked for
//! at the address ([`transport::request_key`]) and kept only if it hashes to
//! the id -- the check `cairn seeds resolve` makes against a downloaded key
//! file, made against the seed itself. So a wrong list can send a node to the
//! wrong machine and cannot make it trust one, which is the bound
//! `docs/discovery.md` sets for every hint source and the reason the list needs
//! no signature.
//!
//! Nor is it privileged. [`SEEDS_ENV`] names another list in the same shape, or
//! turns this one off, with no code change: the second of the three properties
//! `docs/discovery.md` asks of an anchor, and what keeps a fork, a private
//! network or a test harness from being stuck with this project's seeds.
//!
//! # Why no key is compiled in beside it
//!
//! A seed answers a key request from anyone, because that is how a beacon
//! contact becomes dialable. Carrying 261,120 bytes per seed in every binary
//! would buy nothing the first dial does not.
//!
//! [`transport::request_key`]: super::transport::request_key

use std::path::{Path, PathBuf};

use super::handshake::PeerId;
use crate::canonical::Value;

/// Names another seed list, or `off`. See the module docs.
pub const SEEDS_ENV: &str = "CAIRN_SEEDS";

/// `launch/seeds.json`, as this binary was built with it.
pub const BUILT_IN: &str = include_str!("../../launch/seeds.json");

/// Largest seed list read from disk, in bytes.
///
/// The published list is under 3 KiB. A file far past that is not a seed list,
/// and there is no reason to hold it in memory to find out.
const MAX_LIST_BYTES: u64 = 1 << 20;

/// One dialable entry: where to knock, and the id whose key must answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed {
    /// Letters, digits, `-` and `_` only; see [`entry`].
    pub name: String,
    /// A dial hint, `IP:port` or `host:port`, resolved when it is dialled.
    pub addr: String,
    /// The seed's peer id: `sha256` of its transport key.
    pub transport: PeerId,
}

/// An entry a list carried that this build will not dial, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub why: String,
}

/// A list, split into what will be dialled and what will not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct List {
    pub seeds: Vec<Seed>,
    pub skipped: Vec<Skipped>,
}

/// Check one entry of a published list.
///
/// Shared with `cairn seeds resolve`, which applies these rules and then checks
/// a key file. Two copies of "what makes an entry dialable" would drift, and
/// the daemon and the resolver disagreeing about one entry is a seed that works
/// from `make seeds` and not from the app, or the other way round.
pub fn entry(value: &Value) -> Result<Seed, Skipped> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>")
        .to_string();
    // The name becomes a filename in `cairn seeds resolve` and a line in the
    // daemon's log, which the macOS app parses. The list is fetched from a URL
    // and edited by pull request, so `../../.ssh` would be a write chosen by
    // whoever served it, and a newline would be a log line they wrote.
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Skipped {
            name,
            why: "name must be non-empty and only letters, digits, - and _".into(),
        });
    }
    let Some(addr) = value.get("addr").and_then(Value::as_str) else {
        return Err(Skipped {
            name,
            why: "no addr: an HTTP-only entry is for the site to read, not to dial".into(),
        });
    };
    let Some(transport) = value.get("transport").and_then(Value::as_str) else {
        return Err(Skipped {
            name,
            why: "no transport key published, so nothing here can authenticate it".into(),
        });
    };
    let Some(id) = decode_transport(transport) else {
        return Err(Skipped {
            name,
            why: format!("transport {transport:?} is not a 64-character peer id"),
        });
    };
    Ok(Seed {
        name,
        addr: addr.to_string(),
        transport: id,
    })
}

fn decode_transport(text: &str) -> Option<PeerId> {
    if text.len() != 64 {
        return None;
    }
    crate::hex::decode(text)?.try_into().ok()
}

/// Parse a list in the published shape: an object with a `seeds` array.
///
/// An entry that fails [`entry`] is skipped and named rather than failing the
/// list. A list is edited by strangers, and one malformed entry costing every
/// other seed is a way to take a network's newcomers offline with a typo.
pub fn parse(text: &str) -> Result<List, String> {
    let value = Value::from_json(text).map_err(|e| e.to_string())?;
    let entries = value
        .get("seeds")
        .and_then(Value::as_array)
        .ok_or("no \"seeds\" array")?;
    let mut list = List::default();
    for item in entries {
        match entry(item) {
            Ok(seed) => list.seeds.push(seed),
            Err(skipped) => list.skipped.push(skipped),
        }
    }
    Ok(list)
}

/// Where a node's seed list comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// [`BUILT_IN`], when [`SEEDS_ENV`] is unset or empty.
    BuiltIn,
    /// A file in the published shape, named by [`SEEDS_ENV`].
    File(PathBuf),
    /// `off` or `0`: no seeds, for a node meant to be alone -- a test, a demo,
    /// a private network -- for the reason `CAIRN_BEACON_PORT=off` exists.
    Off,
}

impl Source {
    /// Read a setting's value. `None` is an unset variable.
    ///
    /// Empty counts as unset, as it does for `CAIRN_BINARY` in the macOS app:
    /// a launcher that always passes the variable, sometimes blank, must not
    /// turn discovery off by accident.
    pub fn from_setting(setting: Option<&str>) -> Source {
        match setting.map(str::trim) {
            None | Some("") => Source::BuiltIn,
            Some(off) if off.eq_ignore_ascii_case("off") || off == "0" => Source::Off,
            Some(path) => Source::File(PathBuf::from(path)),
        }
    }

    /// [`SEEDS_ENV`], read now.
    pub fn from_env() -> Source {
        Source::from_setting(std::env::var(SEEDS_ENV).ok().as_deref())
    }

    /// The list this source names.
    ///
    /// A file that cannot be read or parsed is an error rather than an empty
    /// list: the operator named it, and a node that quietly ran without the
    /// seeds it was told to use would look exactly like a network that is down.
    pub fn load(&self) -> Result<List, String> {
        match self {
            Source::BuiltIn => parse(BUILT_IN),
            Source::File(path) => parse(&read_bounded(path)?),
            Source::Off => Ok(List::default()),
        }
    }

    /// Where the list came from, for a log line.
    pub fn describe(&self) -> String {
        match self {
            Source::BuiltIn => "the list built into this binary".into(),
            Source::File(path) => path.display().to_string(),
            Source::Off => format!("{SEEDS_ENV}=off"),
        }
    }
}

fn read_bounded(path: &Path) -> Result<String, String> {
    let size = std::fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
    if size > MAX_LIST_BYTES {
        return Err(format!(
            "{}: {size} bytes is not a seed list",
            path.display()
        ));
    }
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(json: &str) -> Value {
        Value::from_json(json).expect("json")
    }

    /// The compiled list names a seed the daemon will dial, and the daemon
    /// skips nothing in it that carries both an address and an id.
    ///
    /// `tests/seeds_list.rs` pins the list's shape for the site and for
    /// `make seeds`, and allows entries no node can dial: HTTP-only mirrors,
    /// and addresses whose operator has not published an id yet. What it
    /// cannot see is the daemon disagreeing with it about an entry that *is*
    /// complete, which would be a seed that works from `make seeds` and not
    /// from the app. And a list with no dialable seed at all is the bug this
    /// module exists to fix, arriving by edit instead of by omission.
    #[test]
    fn the_built_in_list_names_a_seed_and_skips_only_incomplete_entries() {
        let list = parse(BUILT_IN).expect("launch/seeds.json parses");
        assert!(
            !list.seeds.is_empty(),
            "the built-in list names no dialable seed, so a node started from the app finds nobody"
        );
        let raw = Value::from_json(BUILT_IN).expect("json");
        for item in raw.get("seeds").and_then(Value::as_array).expect("seeds") {
            let complete = item.get("addr").and_then(Value::as_str).is_some()
                && item.get("transport").and_then(Value::as_str).is_some();
            if complete {
                assert!(
                    entry(item).is_ok(),
                    "a complete entry the daemon will not dial: {:?}",
                    entry(item).err()
                );
            }
        }
    }

    #[test]
    fn an_entry_is_dialable_only_with_a_name_an_address_and_a_transport_id() {
        let id = "ab".repeat(32);
        let good = entry(&value(&format!(
            r#"{{"name":"us-west","addr":"203.0.113.10:9000","transport":"{id}"}}"#
        )))
        .expect("a complete entry is dialable");
        assert_eq!(good.name, "us-west");
        assert_eq!(good.addr, "203.0.113.10:9000");
        assert_eq!(good.transport, [0xab; 32]);

        for json in [
            format!(r#"{{"addr":"203.0.113.10:9000","transport":"{id}"}}"#),
            format!(r#"{{"name":"../up","addr":"203.0.113.10:9000","transport":"{id}"}}"#),
            format!(r#"{{"name":"two\nlines","addr":"203.0.113.10:9000","transport":"{id}"}}"#),
            format!(r#"{{"name":"httponly","transport":"{id}"}}"#),
            r#"{"name":"nokey","addr":"203.0.113.10:9000"}"#.to_string(),
            r#"{"name":"nokey","addr":"203.0.113.10:9000","transport":null}"#.to_string(),
            r#"{"name":"short","addr":"203.0.113.10:9000","transport":"abcd"}"#.to_string(),
            format!(
                r#"{{"name":"nothex","addr":"203.0.113.10:9000","transport":"{}"}}"#,
                "zz".repeat(32)
            ),
        ] {
            assert!(entry(&value(&json)).is_err(), "accepted {json}");
        }
    }

    /// One bad entry costs itself, never the list.
    #[test]
    fn a_list_skips_what_it_cannot_dial_and_keeps_the_rest() {
        let id = "cd".repeat(32);
        let list = parse(&format!(
            r#"{{"version":1,"seeds":[
                {{"name":"good","addr":"seed.example:9000","transport":"{id}"}},
                {{"name":"nokey","addr":"203.0.113.10:9000"}}
            ]}}"#
        ))
        .expect("parses");
        assert_eq!(list.seeds.len(), 1);
        assert_eq!(list.seeds[0].addr, "seed.example:9000");
        assert_eq!(list.skipped.len(), 1);
        assert_eq!(list.skipped[0].name, "nokey");

        assert!(parse(r#"{"version":1}"#).is_err(), "no seeds array");
        assert!(parse("not json").is_err());
    }

    #[test]
    fn the_setting_chooses_built_in_a_file_or_nothing() {
        assert_eq!(Source::from_setting(None), Source::BuiltIn);
        assert_eq!(Source::from_setting(Some("")), Source::BuiltIn);
        assert_eq!(Source::from_setting(Some("  ")), Source::BuiltIn);
        assert_eq!(Source::from_setting(Some("off")), Source::Off);
        assert_eq!(Source::from_setting(Some("OFF")), Source::Off);
        assert_eq!(Source::from_setting(Some("0")), Source::Off);
        assert_eq!(
            Source::from_setting(Some("/etc/cairn/seeds.json")),
            Source::File(PathBuf::from("/etc/cairn/seeds.json"))
        );
        assert_eq!(Source::Off.load(), Ok(List::default()));
    }

    /// A list the operator named and the node cannot read is a refusal, not a
    /// node that runs without seeds and looks like a network that is down.
    #[test]
    fn a_named_file_is_read_and_an_unreadable_one_is_an_error() {
        let dir = std::env::temp_dir().join(format!("cairn-seeds-list-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("seeds.json");
        let id = "ef".repeat(32);
        std::fs::write(
            &path,
            format!(r#"{{"seeds":[{{"name":"lab","addr":"10.0.0.2:9000","transport":"{id}"}}]}}"#),
        )
        .expect("write");
        let list = Source::File(path.clone()).load().expect("reads");
        assert_eq!(list.seeds.len(), 1);
        assert_eq!(list.seeds[0].name, "lab");

        assert!(Source::File(dir.join("absent.json")).load().is_err());
        std::fs::write(&path, "{").expect("write");
        assert!(Source::File(path).load().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
