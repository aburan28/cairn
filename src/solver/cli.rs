//! `cairn solver`: write, check, add and list solver packages.

use std::io::Write;
use std::path::{Path, PathBuf};

use super::check::{self, Checker, Outcome, Report, Verify};
use super::manifest::Platform;
use super::package::{self, Package};
use super::store::{Offers, Store};
use crate::canonical::Value;
use crate::records::Objective;
use crate::verifiers::{Status, VerifierRegistry};

pub const USAGE: &str = "\
cairn solver — publish the program that solves an objective, so anyone can run it

USAGE
    cairn solver pack DIR
    cairn solver check DIR [--objective FILE|ID] [--allow-unjailed]
    cairn [--root DIR --log FILE] solver add DIR [--objective FILE|ID] [--allow-unjailed]
    cairn [--root DIR --log FILE] solver list [--objective ID]

    pack    list every file under DIR in DIR/solver.json, with its SHA-256 and
            size, and print the package id. Run it after every change.
    check   run the package's known-answer tests here, in the sandbox, and say
            whether it implements cairn-solver/v1. Tests with verify: \"accept\"
            need the objective: a draft objective FILE or an id in this node's log.
    add     check, then file the package in this node's store (ROOT/.cairn/solvers)
            so `cairn work --package auto` finds it. Refused unless its tests pass.
            Pin it in an objective with
              \"verifier\": {…, \"capabilities\": {\"worker\": {\"mode\": \"package\",
                                                         \"package\": \"<id>\"}}}
            or name the objective in solver.json (\"objective\": \"sha256:…\") to offer it
            as an approach to an objective that pinned none.
    list    the packages this node offers, and for --objective, which one runs.

    --allow-unjailed   run tests on a host with no sandbox (development only)

    The interface, the manifest and the sandbox are in docs/solvers.md.
";

/// What the command needs from the node it runs beside, supplied lazily so
/// `pack` and `check` work with no log at all.
pub struct Context<'a> {
    pub root: &'a Path,
    /// An objective in this node's log, by id.
    pub objective: &'a dyn Fn(&str) -> Result<Option<Objective>, String>,
}

pub fn main(args: &[String], context: &Context<'_>, out: &mut dyn Write) -> i32 {
    match run(args, context, out) {
        Ok(code) => code,
        Err(message) => {
            let _ = writeln!(out, "cairn solver: {message}");
            2
        }
    }
}

struct Flags {
    dir: Option<PathBuf>,
    objective: Option<String>,
    allow_unjailed: bool,
}

fn flags(args: &[String]) -> Result<Flags, String> {
    let mut flags = Flags {
        dir: None,
        objective: None,
        allow_unjailed: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--objective" => {
                flags.objective = Some(args.get(i + 1).ok_or("--objective needs a value")?.clone());
                i += 2;
            }
            "--allow-unjailed" => {
                flags.allow_unjailed = true;
                i += 1;
            }
            flag if flag.starts_with('-') => return Err(format!("unknown flag {flag}\n\n{USAGE}")),
            dir if flags.dir.is_none() => {
                flags.dir = Some(PathBuf::from(dir));
                i += 1;
            }
            extra => return Err(format!("unexpected {extra:?}")),
        }
    }
    Ok(flags)
}

fn run(args: &[String], context: &Context<'_>, out: &mut dyn Write) -> Result<i32, String> {
    let Some((verb, rest)) = args.split_first() else {
        let _ = write!(out, "{USAGE}");
        return Ok(0);
    };
    let say = |out: &mut dyn Write, line: String| {
        let _ = writeln!(out, "{line}");
    };
    match verb.as_str() {
        "help" | "--help" | "-h" => {
            let _ = write!(out, "{USAGE}");
            Ok(0)
        }
        "pack" => {
            let dir = flags(rest)?.dir.ok_or("pack needs a package directory")?;
            let manifest = package::pack(&dir).map_err(|e| e.0)?;
            say(out, format!("package {}", manifest.id()));
            say(
                out,
                format!(
                    "  {} {}: {} file(s), {} bytes, targets {}",
                    manifest.name,
                    manifest.version,
                    manifest.files.len(),
                    manifest.total_bytes(),
                    manifest
                        .targets
                        .keys()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
            say(out, format!("  next: cairn solver check {}", dir.display()));
            Ok(0)
        }
        "check" | "add" => {
            let flags = flags(rest)?;
            let dir = flags
                .dir
                .ok_or_else(|| format!("{verb} needs a package directory"))?;
            let package = Package::open(&dir).map_err(|e| e.0)?;
            let objective = match flags.objective.as_deref() {
                Some(wanted) => Some(load_objective(wanted, context)?),
                None => match &package.manifest.objective {
                    Some(id) => (context.objective)(id)?.map(|o| (id.clone(), o)),
                    None => None,
                },
            };
            if let (Some(named), Some((id, _))) = (&package.manifest.objective, &objective) {
                if named != id {
                    return Err(format!(
                        "solver.json names objective {named}, but you are checking it against {id}"
                    ));
                }
            }
            if let Some((id, objective)) = &objective {
                if let Some(pin) = super::store::pinned(objective) {
                    if pin != package.id() {
                        return Err(format!(
                            "objective {id} pins package {pin}; this package is {}",
                            package.id()
                        ));
                    }
                }
            }
            say(out, format!("package {}", package.id()));
            say(
                out,
                format!(
                    "  {} {}, {} test(s), sandbox {}",
                    package.manifest.name,
                    package.manifest.version,
                    package.manifest.tests.len(),
                    crate::verifiers::sandbox::mechanism().as_str()
                ),
            );
            let report = check_package(
                &package,
                objective.as_ref().map(|(id, o)| (id.as_str(), o)),
                context.root,
                flags.allow_unjailed,
                true,
            );
            for line in report.lines() {
                say(out, line);
            }
            let verdict = report.verdict();
            say(out, format!("  verdict: {}", verdict.as_str()));
            if verb == "check" {
                return Ok(match verdict {
                    Outcome::Pass => 0,
                    Outcome::Fail => 1,
                    Outcome::Unavailable => 3,
                });
            }
            let store = Store::under(context.root);
            let slot = store
                .add(&package, &report)
                .map_err(|why| format!("not added: {why}"))?;
            say(out, format!("  added to {}", slot.display()));
            let pinned_by = objective
                .as_ref()
                .filter(|(_, o)| super::store::pinned(o).as_deref() == Some(package.id().as_str()))
                .map(|(id, _)| id.clone());
            match (&pinned_by, &package.manifest.objective) {
                (Some(id), _) => say(
                    out,
                    format!("  pinned by objective {id}; `cairn post` it, and contributors can press Start"),
                ),
                (None, Some(id)) => say(
                    out,
                    format!("  offered for objective {id}; `cairn work --package auto` runs it"),
                ),
                (None, None) => say(
                    out,
                    format!(
                        "  pin it in an objective: \"capabilities\": {{\"worker\": {{\"mode\": \
                         \"package\", \"package\": \"{}\"}}}}",
                        package.id()
                    ),
                ),
            }
            Ok(0)
        }
        "list" => {
            let flags = flags(rest)?;
            let store = Store::under(context.root);
            if let Some(wanted) = flags.objective {
                let objective = (context.objective)(&wanted)?
                    .ok_or_else(|| format!("no objective {wanted} in this node's log"))?;
                let offers = Offers::for_objective(&store, &objective);
                say(out, offers.to_value(&wanted).canonical_string());
                return Ok(0);
            }
            for stored in store.list() {
                say(
                    out,
                    format!(
                        "{}  {} {}  {}  {}",
                        stored.id(),
                        stored.manifest.name,
                        stored.manifest.version,
                        stored.report.verdict().as_str(),
                        stored
                            .manifest
                            .objective
                            .as_deref()
                            .unwrap_or("(for whichever objective pins it)")
                    ),
                );
            }
            Ok(0)
        }
        other => Err(format!("unknown subcommand {other:?}\n\n{USAGE}")),
    }
}

/// An objective named on the command line: an id in this node's log, or a
/// draft on disk that has not been posted yet. The draft case is the one an
/// author meets first: the package id goes into the objective before the
/// objective exists.
fn load_objective(wanted: &str, context: &Context<'_>) -> Result<(String, Objective), String> {
    if wanted.starts_with(crate::canonical::DIGEST_PREFIX) {
        let objective = (context.objective)(wanted)?
            .ok_or_else(|| format!("no objective {wanted} in this node's log"))?;
        return Ok((wanted.to_string(), objective));
    }
    let text = std::fs::read_to_string(wanted).map_err(|e| format!("{wanted}: {e}"))?;
    let value = Value::from_json(&text).map_err(|e| format!("{wanted}: {e}"))?;
    let objective = Objective::from_value(&value).map_err(|e| format!("{wanted}: {e}"))?;
    Ok((objective.id(), objective))
}

/// Run a package's tests on this host, scoring `verify: "accept"` candidates
/// with `objective`'s pinned verifier resolved under `root`, exactly as the
/// node would score a submission.
pub fn check_package(
    package: &Package,
    objective: Option<(&str, &Objective)>,
    root: &Path,
    allow_unjailed: bool,
    all_targets: bool,
) -> Report {
    let registry = VerifierRegistry::new(root).interactive();
    let verify = |candidate: &Value| -> Verify {
        let Some((_, objective)) = objective else {
            return Verify::Unavailable("no objective".into());
        };
        let verdict = registry.run(&objective.verifier, candidate);
        match verdict.status {
            Status::Accept => Verify::Accept,
            Status::Reject => Verify::Reject(verdict.detail),
            Status::Unavailable | Status::InvalidSpec => Verify::Unavailable(verdict.detail),
        }
    };
    let checker = Checker {
        objective: objective.map(|(id, _)| id),
        verify: objective
            .is_some()
            .then_some(&verify as &dyn Fn(&Value) -> Verify),
        allow_unjailed,
        all_targets,
        node_vouched: false,
    };
    check::check(package, &checker)
}

/// What `cairn post` says about an objective's pinned package, or why it
/// refuses to post it: a pin this node does not hold, or holds without a
/// passing check, is an objective nobody can press "Start" on.
pub fn pin_problem(root: &Path, objective: &Objective) -> Option<String> {
    let pin = super::store::pinned(objective)?;
    match Store::under(root).get(&pin) {
        Some(stored) if stored.report.verdict() == Outcome::Pass => None,
        Some(stored) if package::runnable_here(&stored.manifest).is_empty() => None,
        Some(_) => Some(format!(
            "this objective pins solver package {pin}, whose tests did not pass on this node; \
             fix it and `cairn solver add` it again"
        )),
        None => Some(format!(
            "this objective pins solver package {pin}, which this node does not have. A \
             published objective must ship a solver that passes its tests: run `cairn solver \
             add DIR --objective {}` first",
            "<this file>"
        )),
    }
}

/// Set to `1` on a process that posts objectives (`cairn post`, `cairn mcp`,
/// `cairn serve`) to admit objectives that ship no solver package. For test
/// harnesses, demos, and objectives meant only for agents; Cairn.app never
/// sets it. `cairn post --without-solver` is the same thing for one post.
pub const ALLOW_NO_SOLVER_ENV: &str = "CAIRN_ALLOW_NO_SOLVER";

/// Whether this process was told to admit objectives with no solver.
pub fn no_solver_allowed() -> bool {
    std::env::var(ALLOW_NO_SOLVER_ENV).is_ok_and(|v| v == "1")
}

/// Why an author may not post `objective` from this node, or `None`.
///
/// Every objective must ship a solver anyone can press Start on: either a
/// pinned package ([`pin_problem`]) or, for an objective that pins none, an
/// approach package this node holds that names it and passed its tests. Only
/// author-side entry points apply this -- record sync and peers never do --
/// so it changes no rule about which records a node admits.
pub fn solver_problem(root: &Path, objective: &Objective) -> Option<String> {
    if super::store::pinned(objective).is_some() {
        return pin_problem(root, objective);
    }
    if Offers::for_objective(&Store::under(root), objective)
        .recommended
        .is_some()
    {
        return None;
    }
    Some(String::from(
        "this objective ships no solver package. Every objective must publish a solver \
         contributors can press Start on (docs/solvers.md): post it with `cairn post <this file> \
         --solver DIR`, which checks the package, adds it to this node and pins it",
    ))
}

/// Check the package in `dir` against `objective` and file it in this
/// node's store, as `cairn solver add DIR --objective FILE` does. Used by
/// `cairn post --solver DIR`, after the pin is written into the objective.
pub fn add_for(
    dir: &Path,
    objective: &Objective,
    root: &Path,
    out: &mut dyn Write,
) -> Result<String, String> {
    let package = Package::open(dir).map_err(|e| e.0)?;
    let id = objective.id();
    if let Some(named) = &package.manifest.objective {
        if named != &id {
            return Err(format!(
                "{} names objective {named} in solver.json, but this objective is {id}",
                dir.display()
            ));
        }
    }
    let report = check_package(&package, Some((id.as_str(), objective)), root, false, true);
    for line in report.lines() {
        let _ = writeln!(out, "  solver: {line}");
    }
    if report.verdict() != Outcome::Pass {
        return Err(format!(
            "solver package {} did not pass its tests here (verdict {}); nothing was posted",
            package.id(),
            report.verdict().as_str()
        ));
    }
    Store::under(root)
        .add(&package, &report)
        .map_err(|why| format!("solver package not added: {why}"))?;
    Ok(package.id())
}

/// The id a package directory would be pinned by, and the objective its
/// `solver.json` names if it is an approach package, without running anything.
pub fn package_id(dir: &Path) -> Result<(String, Option<String>), String> {
    Package::open(dir)
        .map(|p| (p.id(), p.manifest.objective.clone()))
        .map_err(|e| e.0)
}

/// The platform a worker here would run, for a message.
pub fn host_platform() -> String {
    Platform::host()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "this platform".into())
}
