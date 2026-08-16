//! Embed the built `ui/` reader into the binary, when the `ui` feature is on.
//!
//! # Why a build script rather than a directory on disk
//!
//! The daemon ships as a single file an operator downloads with `install.sh`
//! and drops on an EC2 box. A UI served from a directory beside it would be a
//! second thing to copy, a second thing to keep at the same version, and a path
//! to get wrong — and the failure mode is a node that serves a page from a
//! build that does not match the binary rendering it.
//!
//! # Nothing here compiles C
//!
//! It reads files and writes Rust. That matters because `release.yml` builds
//! musl targets with nothing but a linker, on the checked claim that no build
//! script in the graph needs a C toolchain. This does not change that.
//!
//! # A missing export warns; it does not fail the build
//!
//! It used to panic, on the reasoning that a binary whose `/ui/` answers 404 for
//! invisible reasons is worse than a build error. That reasoning was right about
//! releases and wrong about everything else: `--all-features` is how this
//! repository runs clippy, the test suite, rustdoc and the MSRV check, and a
//! panic here broke all four for anyone without a Node toolchain -- which is the
//! configuration the feature exists to keep working.
//!
//! So the absence is a `cargo:warning`, and the table comes out empty; `/ui/`
//! then answers a 404 that names the feature, which is the visibility the panic
//! was for. The hard requirement lives where it belongs: `release.yml` asserts
//! the export is present before it builds, so a *release* cannot ship without
//! the reader.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    // Rerun rules first, so they apply even on the early return. Without the
    // `ui/out` line, turning the feature on after a build that skipped it
    // leaves a cached empty table.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=ui/out");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is always set by cargo"));
    let generated = out_dir.join("ui_assets.rs");

    // Both branches emit the same two items. `serve.rs` refers to them
    // unconditionally -- it answers `/ui/` with a 404 that names the feature
    // rather than being compiled out -- so the *type* has to exist even when
    // the table is empty.
    let header = "/// One embedded file: request path under `/ui/`, MIME type, bytes.\n\
                  pub type Asset = (&'static str, &'static str, &'static [u8]);\n\n";

    if env::var("CARGO_FEATURE_UI").is_err() {
        fs::write(
            &generated,
            format!("{header}pub static ASSETS: &[Asset] = &[];\n"),
        )
        .expect("cannot write the empty asset table");
        return;
    }

    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let dist = root.join("ui").join("out");
    if !dist.is_dir() {
        println!(
            "cargo:warning=the `ui` feature is on but {} does not exist, so no \
             reader is embedded and /ui/ will 404. Build it with `make ui-build` \
             (or `cd ui && npm ci && npm run build`) if you wanted one.",
            dist.display()
        );
        fs::write(
            &generated,
            format!("{header}pub static ASSETS: &[Asset] = &[];\n"),
        )
        .expect("cannot write the empty asset table");
        return;
    }

    let mut files = Vec::new();
    collect(&dist, &dist, &mut files);
    files.sort();
    if files.is_empty() {
        // Still a hard error: a directory that exists and is empty is a partial
        // `next build`, which is a broken state rather than an absent one.
        panic!(
            "{} exists but holds no files; a partial `next build` leaves this. \
             Remove it and build again.",
            dist.display()
        );
    }

    let mut source = format!("{header}pub static ASSETS: &[Asset] = &[\n");
    for relative in &files {
        let absolute = dist.join(relative);
        source.push_str(&format!(
            "    ({:?}, {:?}, include_bytes!({:?})),\n",
            relative.replace('\\', "/"),
            mime_of(relative),
            absolute
        ));
    }
    source.push_str("];\n");
    fs::write(&generated, source).expect("cannot write the asset table");
}

/// Every file under `dir`, as a path relative to `base` with `/` separators.
fn collect(base: &Path, dir: &Path, out: &mut Vec<String>) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) => panic!("cannot read {}: {error}", dir.display()),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(base, &path, out);
        } else if let Ok(relative) = path.strip_prefix(base) {
            out.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// The `Content-Type` for an exported asset.
///
/// A short list, because the export only ever contains these. An unknown
/// extension gets `application/octet-stream` rather than a guess: a stylesheet
/// served as the wrong type is silently ignored by the browser, which looks
/// exactly like the CSS bug `ui/README.md` warns about.
fn mime_of(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    }
}
