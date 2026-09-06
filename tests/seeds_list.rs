//! The seed list this repository publishes is well-formed, and every key file
//! in it is named for the key it contains.
//!
//! # Why this is a test and not a review checklist
//!
//! `launch/seeds.json` is deployed to GitHub Pages by
//! `.github/workflows/pages.yml` on every push to `main`, and it is the file
//! strangers point `scripts/seeds-fetch.sh` at to find the network. It is also
//! the one file here that gets edited by people who are not maintainers: adding
//! a seed is a pull request carrying half a megabyte of hex, which no human
//! reviews byte by byte.
//!
//! A wrong entry is not dangerous -- `cairn seeds resolve` re-derives every peer
//! id before it writes a bootstrap file, so a mismatched key is refused on the
//! machine that downloaded it. It is *silently useless*, which is worse to
//! debug: an operator runs `make seeds`, gets "refused us-west", and has no way
//! to tell a bad commit from a hostile mirror. Catching it here means the
//! published list is only ever one that verifies.
//!
//! The one thing this cannot check is whether an address is reachable, or
//! whether the key belongs to the person the `operator` field names. Neither is
//! checkable from a checkout, and neither has to be: an address is a hint and a
//! handshake decides.

use std::collections::BTreeSet;
use std::path::PathBuf;

use cairn::canonical::Value;
use cairn::p2p::discovery::peer_id_string;
use cairn::p2p::handshake::PeerPublic;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn launch() -> PathBuf {
    repo().join("launch")
}

fn list() -> Value {
    let path = launch().join("seeds.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Value::from_json(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Every entry carries the fields both readers expect: `cairn seeds resolve`
/// dials `addr` and checks `transport`, and `ui/lib/seeds.ts` reads `http`.
/// A field renamed on one side and not the other is the failure `ui/lib/shape.ts`
/// exists to make loud, and this is the same check one layer earlier.
#[test]
fn every_published_seed_has_the_shape_both_readers_expect() {
    let list = list();
    let seeds = list
        .get("seeds")
        .and_then(Value::as_array)
        .expect("launch/seeds.json has a \"seeds\" array");

    let mut names = BTreeSet::new();
    for seed in seeds {
        let name = seed
            .get("name")
            .and_then(Value::as_str)
            .expect("every seed has a name");
        // The name becomes `<name>.json` in the operator's bootstrap directory,
        // so two entries sharing one would have the second overwrite the first
        // and nothing would say so.
        assert!(
            names.insert(name.to_string()),
            "duplicate seed name {name:?}"
        );
        assert!(
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "seed name {name:?} is not filename-safe; `cairn seeds resolve` will refuse it",
        );

        // Every entry has to be *something*: a peer to dial, a node to read, or
        // both. One that is neither is a row nobody consumes.
        let addr = seed.get("addr").and_then(Value::as_str);
        let http = seed.get("http").and_then(Value::as_str);
        assert!(
            addr.is_some() || http.is_some(),
            "seed {name:?} has neither addr nor http, so nothing reads it",
        );

        if let Some(addr) = addr {
            assert!(
                addr.rsplit_once(':').is_some_and(|(host, port)| {
                    !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0)
                }),
                "seed {name:?} addr {addr:?} is not host:port",
            );
        }
        if let Some(http) = http {
            // The published site is HTTPS, so a browser blocks a plain-http
            // subresource before the request leaves. An `http://` endpoint here
            // is a seed the site can never read -- see `ui/lib/seeds.ts`.
            assert!(
                http.starts_with("https://"),
                "seed {name:?} http {http:?} is not https, so the published site cannot read it",
            );
        }
        if let Some(transport) = seed.get("transport").and_then(Value::as_str) {
            assert!(
                transport.len() == 64 && transport.chars().all(|c| c.is_ascii_hexdigit()),
                "seed {name:?} transport {transport:?} is not a 64-character peer id",
            );
        }
    }
}

/// A key file is named for the peer id of the key inside it, and that naming is
/// the entire reason the list is safe to serve from a host nobody controls: a
/// mirror can withhold a key, and cannot put a different one under the same
/// name. If the *published* tree ever broke that, the property would be a
/// sentence in a doc rather than a fact.
#[test]
fn every_published_key_file_is_named_for_the_key_it_contains() {
    let dir = launch().join("seeds");
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        // No published keys yet is the state this repository is in, and it is a
        // legitimate one: the list then resolves to nothing and `make p2p`
        // falls back to the placeholder, loudly. Not a failure.
        Err(_) => return,
    };
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("key") {
            continue;
        }
        let named = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("file stem")
            .to_string();
        let hex =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let bytes = cairn::hex::decode(hex.trim())
            .unwrap_or_else(|| panic!("{}: not hexadecimal", path.display()));
        // `from_bytes` derives the id rather than accepting one, so this is the
        // same check `cairn seeds resolve` makes on a downloaded copy.
        let public =
            PeerPublic::from_bytes(&bytes).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(
            peer_id_string(&public.id()),
            named,
            "{} contains a key for a different peer than its name claims",
            path.display(),
        );
    }
}

/// A `transport` in the list with no key file beside it resolves to nothing, so
/// the entry is inert -- which is correct while an operator has not published
/// yet, and a mistake if they think they have. Checked in the direction that
/// can be wrong: a key file nobody references is dead weight served forever.
#[test]
fn no_key_file_is_published_without_an_entry_naming_it() {
    let list = list();
    let referenced: BTreeSet<String> = list
        .get("seeds")
        .and_then(Value::as_array)
        .expect("seeds")
        .iter()
        .filter_map(|seed| seed.get("transport").and_then(Value::as_str))
        .map(str::to_string)
        .collect();

    let dir = launch().join("seeds");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("key") {
            continue;
        }
        let named = path.file_stem().and_then(|s| s.to_str()).expect("stem");
        assert!(
            referenced.contains(named),
            "{} is published but no entry in launch/seeds.json names it",
            path.display(),
        );
    }
}

/// The three places that name the published URL still name the same one.
///
/// There is no way to avoid hardcoding an anchor -- `docs/discovery.md` opens
/// by saying every system hides one somewhere -- but there is a way to avoid
/// hardcoding it *three times and letting two rot*. `make seeds` reads the
/// Makefile's copy, somebody running the script directly gets the script's
/// default, and a stray copy of `seeds.json` carries `published_at` so a reader
/// who has only the file can tell where it came from.
///
/// This is not hypothetical and it is not a style point. This repository was
/// renamed from `distributed-researcher` to `cairn`, GitHub Pages does not
/// redirect the old project path, and the first version of this feature shipped
/// all three copies pointing at a URL that 404s -- caught by hitting it, not by
/// reading it. A rename will happen again. This test is what makes the next one
/// cost one edit rather than three, with the two nobody remembered failing only
/// for people who are not the maintainer.
///
/// It deliberately does *not* check the URL is reachable. A test that needed
/// the network would fail on a plane, in a sandbox, and in any fork that has
/// not deployed yet, and would be deleted within a month.
#[test]
fn the_published_url_is_the_same_in_every_place_that_names_it() {
    fn url_in(path: &str, needle: &str) -> String {
        let text =
            std::fs::read_to_string(repo().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"));
        let line = text
            .lines()
            .find(|line| line.contains(needle))
            .unwrap_or_else(|| panic!("{path}: no line containing {needle:?}"));
        let start = line
            .find("https://")
            .unwrap_or_else(|| panic!("{path}: {line:?} names no URL"));
        line[start..]
            .split(|c: char| c.is_whitespace() || c == '"' || c == '}' || c == ',')
            .next()
            .expect("a URL")
            .to_string()
    }

    let makefile = url_in("Makefile", "SEEDS_URL ?=");
    let script = url_in("scripts/seeds-fetch.sh", "CAIRN_SEEDS_URL:-");
    let published = url_in("launch/seeds.json", "published_at");

    assert_eq!(
        makefile, script,
        "the Makefile and scripts/seeds-fetch.sh disagree about where the seed list is",
    );
    assert_eq!(
        makefile, published,
        "launch/seeds.json's published_at disagrees with where the tooling fetches it",
    );
    // The path segment after the origin is the repository name, and getting
    // *that* wrong is the specific failure this test was written for.
    assert!(
        makefile.ends_with("/seeds.json"),
        "{makefile} does not name a seeds.json",
    );
}
