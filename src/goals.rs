//! Goals and angles: what the network is trying to beat, and from which
//! directions -- read off the objectives already in the log, with no new
//! record, field or rule.
//!
//! # The problem this solves
//!
//! Somebody says "let's solve ECC2K-130". Somebody else already posted an
//! objective paying for distinguished points of a distributed Pollard rho on
//! it; a third person is funding a faster GPU kernel for the same walk; a
//! fourth wants index calculus tried instead. Four objectives, one problem,
//! and until now four rows in a list with nothing to say they were the same
//! thing -- so the fifth person types `GOAL-ecc2k-130` where the first typed
//! `GOAL-certicom-ecc2k130`, and the network has two spellings of one goal.
//!
//! # The encoding, which already exists
//!
//! Every objective carries a `goal`, a free string the rules never read
//! (`records.rs`); the design note `docs/design/workspace-benchmarks.md`
//! turned down a `category` field for exactly this reason -- "a prefix
//! convention buys the same grouping for no consensus surface". So:
//!
//! ```text
//! GOAL-<key>[/<angle>[/<angle>...]]
//!
//! GOAL-certicom-ecc2k130                   the problem, no particular approach
//! GOAL-certicom-ecc2k130/rho/distributed   distributed Pollard rho on it
//! GOAL-certicom-ecc2k130/rho/gpu-kernel    making that walk faster on a GPU
//! GOAL-certicom-ecc2k130/index-calculus    a different method altogether
//! ```
//!
//! The **key** names the problem; the **angle path** names the approach, and
//! its segments nest, so `rho/gpu-kernel` is a refinement of `rho` without a
//! relation record saying so. `docs/goals.md` carries the vocabulary of angle
//! names worth agreeing on. None of this changes an objective's digest -- the
//! handle was always part of it -- and an objective written before the
//! convention has an empty angle, which the reader shows as such.
//!
//! # Deduplication, honestly
//!
//! A goal's **key** is normalised (`GOAL-`, case, punctuation and spacing
//! dropped), and a catalog (`launch/goals.json`, compiled in; `CAIRN_GOALS`
//! names another) supplies the aliases a person actually types -- `ECC2K-130`,
//! `ecc2k130` -- so `find("solve ecc2k 130")` lands on the goal the examples
//! use. What it does not do is rewrite anything: an objective's goal is what
//! its funder wrote, and two goals that are really one and that no alias
//! joins are shown as two, each with its objectives, for a person to notice.
//! The catalog is a convenience for readers and drafting tools and decides
//! nothing; nothing here is a record, a rule or a payment.

use std::collections::BTreeMap;

use crate::canonical::Value;
use crate::progress::{FleetWorker, Liveness};
use crate::records::Objective;

/// The catalog compiled into the binary.
pub const BUILT_IN: &str = include_str!("../launch/goals.json");
/// Names another catalog file in the same shape.
pub const ENV: &str = "CAIRN_GOALS";
/// Every goal handle begins with this.
pub const PREFIX: &str = "GOAL-";
/// How much of a statement a goal listing carries.
pub const EXCERPT_CHARS: usize = 160;

// -- handles --------------------------------------------------------------------

/// A goal handle taken apart: `GOAL-<key>/<angle>/<angle>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Handle {
    /// The handle as written, less the angle: `GOAL-certicom-ecc2k130`.
    pub goal: String,
    /// The problem, normalised: `certicomecc2k130`.
    pub key: String,
    /// The approach, as written: `["rho", "gpu-kernel"]`. Empty when none.
    pub angle: Vec<String>,
}

impl Handle {
    /// Take a `goal` field apart. Never fails: a goal that follows no
    /// convention is a key with no angle.
    pub fn parse(goal: &str) -> Handle {
        let trimmed = goal.trim();
        let mut parts = trimmed.split('/');
        let head = parts.next().unwrap_or_default().trim();
        let angle: Vec<String> = parts
            .map(|segment| segment.trim().to_string())
            .filter(|segment| !segment.is_empty())
            .collect();
        Handle {
            goal: head.to_string(),
            key: normalize(head),
            angle,
        }
    }

    /// The angle as one path, `rho/gpu-kernel`; empty when there is none.
    pub fn angle_path(&self) -> String {
        self.angle.join("/")
    }

    /// Build a handle: `GOAL-<key>/<angle>`. The key is written as given,
    /// since a key is a name people read; the angle segments are lowercased.
    pub fn compose(key: &str, angle: &[&str]) -> String {
        let key = key.trim().trim_start_matches(PREFIX);
        let mut out = format!("{PREFIX}{key}");
        for segment in angle {
            let segment = segment.trim().to_ascii_lowercase();
            if !segment.is_empty() {
                out.push('/');
                out.push_str(&segment);
            }
        }
        out
    }
}

/// Lowercase, no `GOAL-` prefix, nothing but letters and digits. The key two
/// spellings of one goal share, and the shape every alias is compared in.
pub fn normalize(text: &str) -> String {
    let text = text.trim();
    let text = text
        .get(..PREFIX.len())
        .filter(|head| head.eq_ignore_ascii_case(PREFIX))
        .map(|_| &text[PREFIX.len()..])
        .unwrap_or(text);
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

// -- the catalog -----------------------------------------------------------------

/// A goal the catalog knows: the name people use and the spellings they type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Known {
    pub key: String,
    pub name: String,
    pub aliases: Vec<String>,
    pub family: String,
    pub summary: String,
}

/// The catalog: known goals by normalised key, and every alias pointing at one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalog {
    known: Vec<Known>,
    /// Normalised alias or key -> index into `known`.
    by_alias: BTreeMap<String, usize>,
    /// Where it came from, for the report.
    pub source: String,
}

impl Catalog {
    /// The compiled-in catalog, which parses by construction (a test says so).
    pub fn built_in() -> Catalog {
        Catalog::parse(BUILT_IN, "launch/goals.json (built in)").expect("launch/goals.json parses")
    }

    /// `CAIRN_GOALS=<file>` or the built-in list. A named file that does not
    /// read is an error for the caller to refuse to start on.
    pub fn from_env() -> Result<Catalog, String> {
        match std::env::var(ENV) {
            Ok(path) if !path.trim().is_empty() => {
                let path = path.trim();
                let text = std::fs::read_to_string(path)
                    .map_err(|e| format!("{ENV}={path:?}: cannot read: {e}"))?;
                Catalog::parse(&text, path).map_err(|e| format!("{ENV}={path:?}: {e}"))
            }
            _ => Ok(Catalog::built_in()),
        }
    }

    pub fn parse(text: &str, source: &str) -> Result<Catalog, String> {
        let value = Value::from_json(text).map_err(|e| format!("not usable JSON: {e}"))?;
        let goals = value
            .get("goals")
            .and_then(Value::as_array)
            .ok_or_else(|| "no `goals` array".to_string())?;
        let mut catalog = Catalog {
            known: Vec::new(),
            by_alias: BTreeMap::new(),
            source: source.to_string(),
        };
        for (n, entry) in goals.iter().enumerate() {
            let field = |name: &str| -> Result<String, String> {
                entry
                    .get(name)
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| format!("goals[{n}]: `{name}` is missing or not a string"))
            };
            let key_text = field("key")?;
            let key = normalize(&key_text);
            if key.is_empty() {
                return Err(format!(
                    "goals[{n}]: `key` {key_text:?} normalises to nothing"
                ));
            }
            let aliases: Vec<String> = entry
                .get("aliases")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            let index = catalog.known.len();
            let mut names = vec![key.clone(), normalize(&field("name")?)];
            names.extend(aliases.iter().map(|alias| normalize(alias)));
            for alias in names.into_iter().filter(|a| !a.is_empty()) {
                if let Some(other) = catalog.by_alias.get(&alias) {
                    if *other != index {
                        return Err(format!(
                            "goals[{n}]: alias {alias:?} already names {}",
                            catalog.known[*other].key
                        ));
                    }
                }
                catalog.by_alias.insert(alias, index);
            }
            catalog.known.push(Known {
                key,
                name: field("name")?,
                aliases,
                family: entry
                    .get("family")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                summary: entry
                    .get("summary")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        Ok(catalog)
    }

    pub fn len(&self) -> usize {
        self.known.len()
    }

    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }

    /// The known goal a normalised key or alias names, if any.
    pub fn lookup(&self, normalized: &str) -> Option<&Known> {
        self.by_alias.get(normalized).map(|&i| &self.known[i])
    }

    /// The canonical key for a goal handle's key: the catalog's when an alias
    /// matches, else the key itself. This is what two spellings collapse to.
    pub fn canonical(&self, key: &str) -> String {
        self.lookup(key)
            .map(|known| known.key.clone())
            .unwrap_or_else(|| key.to_string())
    }

    pub fn known(&self) -> &[Known] {
        &self.known
    }
}

// -- the view ---------------------------------------------------------------------

/// One objective under an angle: what a reader needs to tell it apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub goal: String,
    pub statement_excerpt: String,
    pub verifier_kind: String,
    pub reward: u64,
    pub funder: String,
    pub settled: bool,
    pub live_workers: u64,
}

/// An approach to a goal, with the objectives funded under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Angle {
    /// `rho/gpu-kernel`; empty for objectives whose goal names no approach.
    pub path: String,
    pub segments: Vec<String>,
    pub objectives: Vec<Entry>,
}

impl Angle {
    /// The angle this one refines: `rho` for `rho/gpu-kernel`, none for `rho`.
    pub fn parent(&self) -> Option<String> {
        if self.segments.len() < 2 {
            None
        } else {
            Some(self.segments[..self.segments.len() - 1].join("/"))
        }
    }
}

/// A goal: one problem, the handles that named it, the angles taken on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Goal {
    /// The canonical normalised key.
    pub key: String,
    /// The name people use: the catalog's, else the first handle seen.
    pub name: String,
    /// Every distinct `GOAL-...` head that mapped here, in log order.
    pub handles: Vec<String>,
    pub known: Option<Known>,
    pub angles: Vec<Angle>,
}

impl Goal {
    pub fn objectives(&self) -> usize {
        self.angles.iter().map(|a| a.objectives.len()).sum()
    }
    pub fn settled(&self) -> usize {
        self.angles
            .iter()
            .flat_map(|a| &a.objectives)
            .filter(|e| e.settled)
            .count()
    }
    pub fn live_workers(&self) -> u64 {
        self.angles
            .iter()
            .flat_map(|a| &a.objectives)
            .map(|e| e.live_workers)
            .sum()
    }
    pub fn reward_total(&self) -> u128 {
        self.angles
            .iter()
            .flat_map(|a| &a.objectives)
            .map(|e| u128::from(e.reward))
            .sum()
    }
}

/// Group objectives by goal and angle. `closed` says whether an objective is
/// settled (no longer payable); `fleet` is the heartbeat roster, counted per
/// objective for live workers only.
///
/// Objectives come in log order (a `BTreeMap` by id gives id order, so the
/// caller passes the order it wants); goals are returned in order of first
/// appearance, angles likewise, so a listing is stable across reads.
pub fn group<'a>(
    catalog: &Catalog,
    objectives: impl IntoIterator<Item = (&'a str, &'a Objective)>,
    closed: impl Fn(&Objective) -> bool,
    fleet: &[FleetWorker],
) -> Vec<Goal> {
    let mut live: BTreeMap<&str, u64> = BTreeMap::new();
    for worker in fleet.iter().filter(|w| w.status == Liveness::Live) {
        *live.entry(worker.objective_id.as_str()).or_insert(0) += 1;
    }
    let mut goals: Vec<Goal> = Vec::new();
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    for (id, objective) in objectives {
        let handle = Handle::parse(&objective.goal);
        let key = catalog.canonical(&handle.key);
        let slot = match index.get(&key) {
            Some(&i) => i,
            None => {
                let known = catalog.lookup(&key).cloned();
                let name = known
                    .as_ref()
                    .map(|k| k.name.clone())
                    .unwrap_or_else(|| display_name(&handle.goal));
                goals.push(Goal {
                    key: key.clone(),
                    name,
                    handles: Vec::new(),
                    known,
                    angles: Vec::new(),
                });
                index.insert(key.clone(), goals.len() - 1);
                goals.len() - 1
            }
        };
        let goal = &mut goals[slot];
        if !handle.goal.is_empty() && !goal.handles.contains(&handle.goal) {
            goal.handles.push(handle.goal.clone());
        }
        let path = handle.angle_path();
        let angle = match goal.angles.iter().position(|a| a.path == path) {
            Some(i) => &mut goal.angles[i],
            None => {
                goal.angles.push(Angle {
                    path: path.clone(),
                    segments: handle.angle.clone(),
                    objectives: Vec::new(),
                });
                goal.angles.last_mut().expect("just pushed")
            }
        };
        angle.objectives.push(Entry {
            id: id.to_string(),
            goal: objective.goal.clone(),
            statement_excerpt: excerpt(&objective.statement),
            verifier_kind: objective.verifier_kind().unwrap_or("?").to_string(),
            reward: objective.reward,
            funder: objective.funder.clone(),
            settled: closed(objective),
            live_workers: live.get(id).copied().unwrap_or(0),
        });
    }
    goals
}

/// `GOAL-certicom-ecc2k130` -> `certicom-ecc2k130`, for a goal the catalog
/// does not know.
fn display_name(goal: &str) -> String {
    let name = goal.trim();
    let name = name
        .get(..PREFIX.len())
        .filter(|head| head.eq_ignore_ascii_case(PREFIX))
        .map(|_| &name[PREFIX.len()..])
        .unwrap_or(name);
    if name.is_empty() {
        "(no goal)".to_string()
    } else {
        name.to_string()
    }
}

fn excerpt(statement: &str) -> String {
    let line = statement.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() <= EXCERPT_CHARS {
        line
    } else {
        let cut: String = line.chars().take(EXCERPT_CHARS - 1).collect();
        format!("{}…", cut.trim_end())
    }
}

// -- finding ----------------------------------------------------------------------

/// How well a goal matched a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Match {
    /// A word of the query is a known alias or the key itself.
    Alias,
    /// The query, normalised, contains the key or an alias of at least
    /// four characters -- "solve ecc2k130 with index calculus".
    Contains,
}

/// Goals that a query names, best match first. The query is anything a
/// person typed: a handle, an alias, a sentence. A goal the catalog knows is
/// found whether or not any objective funds it yet, so a drafting tool can
/// say "this is ECC2K-130, and nobody has posted on it" as well as "and
/// three people have".
pub fn find<'a>(
    catalog: &'a Catalog,
    goals: &'a [Goal],
    query: &str,
) -> Vec<(Match, FoundGoal<'a>)> {
    let whole = normalize(query);
    if whole.is_empty() {
        return Vec::new();
    }
    let words: Vec<String> = query
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        .map(normalize)
        .filter(|w| !w.is_empty())
        .collect();

    let mut found: BTreeMap<String, (Match, FoundGoal<'a>)> = BTreeMap::new();
    let mut consider = |key: &str, names: Vec<String>, goal: FoundGoal<'a>| {
        let mut best: Option<Match> = None;
        for name in names.into_iter().filter(|n| !n.is_empty()) {
            if whole == name || words.contains(&name) {
                best = Some(Match::Alias);
                break;
            }
            if name.len() >= 4 && whole.contains(&name) {
                best = Some(best.map_or(Match::Contains, |b| b.min(Match::Contains)));
            }
        }
        if let Some(rank) = best {
            match found.get(key) {
                Some((existing, _)) if *existing <= rank => {}
                _ => {
                    found.insert(key.to_string(), (rank, goal));
                }
            }
        }
    };
    for goal in goals {
        let mut names = vec![goal.key.clone()];
        names.extend(goal.handles.iter().map(|h| normalize(h)));
        if let Some(known) = &goal.known {
            names.push(normalize(&known.name));
            names.extend(known.aliases.iter().map(|a| normalize(a)));
        }
        consider(&goal.key, names, FoundGoal::Funded(goal));
    }
    for known in catalog.known() {
        if goals.iter().any(|g| g.key == known.key) {
            continue;
        }
        let mut names = vec![known.key.clone(), normalize(&known.name)];
        names.extend(known.aliases.iter().map(|a| normalize(a)));
        consider(&known.key, names, FoundGoal::Known(known));
    }
    let mut out: Vec<(Match, FoundGoal<'a>)> = found.into_values().collect();
    out.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.key().cmp(b.1.key())));
    out
}

/// What a search returns: a goal with objectives, or one only the catalog knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoundGoal<'a> {
    Funded(&'a Goal),
    Known(&'a Known),
}

impl FoundGoal<'_> {
    pub fn key(&self) -> &str {
        match self {
            FoundGoal::Funded(goal) => &goal.key,
            FoundGoal::Known(known) => &known.key,
        }
    }
}

// -- JSON ----------------------------------------------------------------------------

fn entry_value(entry: &Entry) -> Value {
    Value::object([
        ("id", Value::string(entry.id.clone())),
        ("goal", Value::string(entry.goal.clone())),
        (
            "statement_excerpt",
            Value::string(entry.statement_excerpt.clone()),
        ),
        ("verifier_kind", Value::string(entry.verifier_kind.clone())),
        ("reward", Value::Int(i128::from(entry.reward))),
        ("funder", Value::string(entry.funder.clone())),
        ("settled", Value::Bool(entry.settled)),
        ("open", Value::Bool(!entry.settled)),
        ("live_workers", Value::Int(i128::from(entry.live_workers))),
    ])
}

fn angle_value(angle: &Angle) -> Value {
    Value::object([
        ("path", Value::string(angle.path.clone())),
        (
            "segments",
            Value::Array(
                angle
                    .segments
                    .iter()
                    .map(|s| Value::string(s.clone()))
                    .collect(),
            ),
        ),
        (
            "parent",
            match angle.parent() {
                Some(parent) => Value::string(parent),
                None => Value::Null,
            },
        ),
        (
            "objectives",
            Value::Array(angle.objectives.iter().map(entry_value).collect()),
        ),
        (
            "open",
            Value::Int(angle.objectives.iter().filter(|e| !e.settled).count() as i128),
        ),
        (
            "settled",
            Value::Int(angle.objectives.iter().filter(|e| e.settled).count() as i128),
        ),
        (
            "live_workers",
            Value::Int(
                angle
                    .objectives
                    .iter()
                    .map(|e| i128::from(e.live_workers))
                    .sum(),
            ),
        ),
    ])
}

fn known_fields(known: &Known) -> Vec<(&'static str, Value)> {
    vec![
        ("name", Value::string(known.name.clone())),
        (
            "aliases",
            Value::Array(
                known
                    .aliases
                    .iter()
                    .map(|a| Value::string(a.clone()))
                    .collect(),
            ),
        ),
        ("family", Value::string(known.family.clone())),
        ("summary", Value::string(known.summary.clone())),
    ]
}

/// A goal with its angles and objectives, as `GET /goals` lists it.
pub fn goal_value(goal: &Goal) -> Value {
    let mut fields: Vec<(&'static str, Value)> = vec![
        ("key", Value::string(goal.key.clone())),
        ("name", Value::string(goal.name.clone())),
        (
            "handle",
            Value::string(
                goal.handles
                    .first()
                    .cloned()
                    .unwrap_or_else(|| Handle::compose(&goal.key, &[])),
            ),
        ),
        (
            "handles",
            Value::Array(
                goal.handles
                    .iter()
                    .map(|h| Value::string(h.clone()))
                    .collect(),
            ),
        ),
        ("known", Value::Bool(goal.known.is_some())),
    ];
    match &goal.known {
        Some(known) => fields.extend(known_fields(known)),
        None => fields.extend([
            ("aliases", Value::Array(Vec::new())),
            ("family", Value::Null),
            ("summary", Value::Null),
        ]),
    }
    fields.extend([
        ("objectives", Value::Int(goal.objectives() as i128)),
        (
            "open",
            Value::Int((goal.objectives() - goal.settled()) as i128),
        ),
        ("settled", Value::Int(goal.settled() as i128)),
        ("reward_total", Value::Int(goal.reward_total() as i128)),
        ("live_workers", Value::Int(i128::from(goal.live_workers()))),
        (
            "angles",
            Value::Array(goal.angles.iter().map(angle_value).collect()),
        ),
    ]);
    Value::object(fields)
}

/// A goal only the catalog knows, in the same shape with nothing funded.
pub fn known_value(known: &Known) -> Value {
    let mut fields: Vec<(&'static str, Value)> = vec![
        ("key", Value::string(known.key.clone())),
        ("name", Value::string(known.name.clone())),
        ("handle", Value::string(Handle::compose(&known.key, &[]))),
        ("handles", Value::Array(Vec::new())),
        ("known", Value::Bool(true)),
    ];
    fields.extend(known_fields(known));
    fields.extend([
        ("objectives", Value::Int(0)),
        ("open", Value::Int(0)),
        ("settled", Value::Int(0)),
        ("reward_total", Value::Int(0)),
        ("live_workers", Value::Int(0)),
        ("angles", Value::Array(Vec::new())),
    ]);
    Value::object(fields)
}

/// A search result row: the goal, and how it matched.
pub fn found_value(rank: Match, found: &FoundGoal<'_>) -> Value {
    let mut value = match found {
        FoundGoal::Funded(goal) => goal_value(goal),
        FoundGoal::Known(known) => known_value(known),
    };
    if let Value::Object(fields) = &mut value {
        fields.insert(
            "match".to_string(),
            Value::string(match rank {
                Match::Alias => "alias",
                Match::Contains => "contains",
            }),
        );
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn objective(goal: &str, statement: &str, reward: u64) -> Objective {
        let mut value = Value::object([
            ("goal", Value::string(goal)),
            ("statement", Value::string(statement)),
            (
                "verifier",
                Value::object([("kind", Value::string("evaluator"))]),
            ),
            ("reward", Value::Int(i128::from(reward))),
            ("funder", Value::string("treasury")),
            ("created_at", Value::string("2026-10-04T00:00:00+00:00")),
        ]);
        if let Value::Object(fields) = &mut value {
            fields.insert("type".to_string(), Value::string("objective"));
        }
        Objective::from_value(&value).expect("a well-formed objective")
    }

    #[test]
    fn handles_come_apart_into_key_and_angle_and_go_back_together() {
        let h = Handle::parse("GOAL-certicom-ecc2k130/rho/gpu-kernel");
        assert_eq!(h.goal, "GOAL-certicom-ecc2k130");
        assert_eq!(h.key, "certicomecc2k130");
        assert_eq!(h.angle, vec!["rho", "gpu-kernel"]);
        assert_eq!(h.angle_path(), "rho/gpu-kernel");

        let plain = Handle::parse("GOAL-capset-lower-bounds");
        assert!(plain.angle.is_empty());
        assert_eq!(plain.angle_path(), "");

        // Stray slashes and spaces cost nothing; a bare word is a key.
        assert_eq!(Handle::parse(" ECC2K-130 / rho / ").angle, vec!["rho"]);
        assert_eq!(Handle::parse("ECC2K-130").key, "ecc2k130");
        assert_eq!(
            Handle::compose("certicom-ecc2k130", &["Rho", "GPU-Kernel"]),
            "GOAL-certicom-ecc2k130/rho/gpu-kernel"
        );
        assert_eq!(Handle::compose("GOAL-x", &[]), "GOAL-x");
    }

    #[test]
    fn normalising_drops_the_prefix_case_and_punctuation() {
        for spelling in [
            "GOAL-certicom-ecc2k130",
            "goal-Certicom_ECC2K-130",
            "Certicom ECC2K-130",
            "certicomecc2k130",
        ] {
            assert_eq!(normalize(spelling), "certicomecc2k130", "{spelling}");
        }
        assert_eq!(normalize("GOAL-"), "");
        assert_eq!(
            normalize("goals"),
            "goals",
            "a word that merely starts like the prefix"
        );
    }

    #[test]
    fn the_built_in_catalog_parses_and_aliases_point_one_way() {
        let catalog = Catalog::built_in();
        assert!(catalog.len() >= 5);
        let ecc = catalog.lookup("ecc2k130").expect("ECC2K-130 is known");
        assert_eq!(ecc.key, "certicomecc2k130");
        assert_eq!(
            catalog
                .lookup(&normalize("Certicom ECC2K-130"))
                .map(|k| k.key.as_str()),
            Some("certicomecc2k130")
        );
        assert_eq!(catalog.canonical("ecc2k130"), "certicomecc2k130");
        assert_eq!(catalog.canonical("somethingelse"), "somethingelse");
        assert!(catalog.lookup("eccp131").is_some());

        assert!(Catalog::parse("{", "x").is_err());
        assert!(Catalog::parse(r#"{"goals": [{"key": "a", "name": "A"}, {"key": "b", "name": "B", "aliases": ["A"]}]}"#, "x")
            .unwrap_err()
            .contains("already names"));
        assert!(Catalog::parse(r#"{"goals": [{"key": "---", "name": "x"}]}"#, "x").is_err());
        assert!(Catalog::parse(r#"{"goals": []}"#, "x").unwrap().is_empty());
    }

    #[test]
    fn objectives_group_by_goal_then_angle_and_two_spellings_are_one_goal() {
        let catalog = Catalog::built_in();
        let objectives = [
            (
                "sha256:1".to_string(),
                objective("GOAL-certicom-ecc2k130", "the dlog itself", 2_000_000),
            ),
            (
                "sha256:2".to_string(),
                objective(
                    "GOAL-certicom-ecc2k130/rho/distributed",
                    "distinguished points of a distributed rho",
                    500_000,
                ),
            ),
            (
                "sha256:3".to_string(),
                objective(
                    "GOAL-ecc2k-130/rho/gpu-kernel",
                    "a faster GPU kernel for the same walk",
                    100_000,
                ),
            ),
            (
                "sha256:4".to_string(),
                objective(
                    "GOAL-ecc2k130/index-calculus",
                    "relations over a factor base",
                    100_000,
                ),
            ),
            (
                "sha256:5".to_string(),
                objective("GOAL-capset-lower-bounds", "a bigger cap set", 10),
            ),
        ];
        let fleet = vec![
            FleetWorker {
                objective_id: "sha256:2".into(),
                worker: "gpu-1".into(),
                status: Liveness::Live,
                age_seconds: 1,
                device: None,
                lanes: None,
                client: None,
                steps_per_second: None,
                epoch: None,
                units: None,
            },
            FleetWorker {
                objective_id: "sha256:2".into(),
                worker: "gpu-2".into(),
                status: Liveness::Stale,
                age_seconds: 900,
                device: None,
                lanes: None,
                client: None,
                steps_per_second: None,
                epoch: None,
                units: None,
            },
        ];
        let goals = group(
            &catalog,
            objectives.iter().map(|(id, o)| (id.as_str(), o)),
            |o| o.reward == 10,
            &fleet,
        );
        assert_eq!(
            goals.len(),
            2,
            "{:?}",
            goals.iter().map(|g| &g.key).collect::<Vec<_>>()
        );
        let ecc = &goals[0];
        assert_eq!(ecc.key, "certicomecc2k130");
        assert_eq!(ecc.name, "ECC2K-130", "the catalog names it");
        assert_eq!(
            ecc.handles,
            vec!["GOAL-certicom-ecc2k130", "GOAL-ecc2k-130", "GOAL-ecc2k130"]
        );
        assert_eq!(ecc.objectives(), 4);
        assert_eq!(ecc.settled(), 0);
        assert_eq!(ecc.live_workers(), 1, "stale workers do not count");
        let paths: Vec<&str> = ecc.angles.iter().map(|a| a.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["", "rho/distributed", "rho/gpu-kernel", "index-calculus"]
        );
        assert_eq!(ecc.angles[2].parent(), Some("rho".to_string()));
        assert_eq!(ecc.angles[3].parent(), None);
        assert_eq!(ecc.reward_total(), 2_700_000);

        let capset = &goals[1];
        assert_eq!(
            capset.name, "capset-lower-bounds",
            "unknown to the catalog: named from the handle"
        );
        assert!(capset.known.is_none());
        assert_eq!(capset.settled(), 1);

        let value = goal_value(ecc);
        assert_eq!(value.get("known").unwrap(), &Value::Bool(true));
        assert_eq!(value.get("objectives").unwrap(), &Value::Int(4));
        assert_eq!(
            value.get("handle").unwrap().as_str(),
            Some("GOAL-certicom-ecc2k130")
        );
        let angles = value.get("angles").unwrap().as_array().unwrap();
        assert_eq!(angles.len(), 4);
        assert_eq!(angles[1].get("live_workers").unwrap(), &Value::Int(1));
        assert_eq!(angles[2].get("parent").unwrap().as_str(), Some("rho"));
    }

    #[test]
    fn finding_a_goal_works_from_a_sentence_an_alias_or_a_handle_and_knows_unfunded_goals() {
        let catalog = Catalog::built_in();
        let objectives = [(
            "sha256:1".to_string(),
            objective("GOAL-certicom-ecc2k130/rho/distributed", "dps", 1),
        )];
        let goals = group(
            &catalog,
            objectives.iter().map(|(id, o)| (id.as_str(), o)),
            |_| false,
            &[],
        );

        let hits = find(
            &catalog,
            &goals,
            "I want to solve ECC2K-130 with index calculus",
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, Match::Alias);
        assert!(matches!(hits[0].1, FoundGoal::Funded(g) if g.key == "certicomecc2k130"));

        let hits = find(&catalog, &goals, "GOAL-ecc2k130/rho/gpu-kernel");
        assert_eq!(hits.len(), 1, "a handle with an angle still names the goal");

        let hits = find(&catalog, &goals, "ecc2k130");
        assert_eq!(hits.len(), 1);

        // Run together: the whole query contains the alias.
        let hits = find(&catalog, &goals, "letsbeatecc2k130please");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0, Match::Contains);

        // Known to the catalog, funded by nobody: still found, said as such.
        let hits = find(&catalog, &goals, "ECCp-131");
        assert_eq!(hits.len(), 1);
        assert!(matches!(hits[0].1, FoundGoal::Known(k) if k.key == "certicomeccp131"));
        let value = found_value(hits[0].0, &hits[0].1);
        assert_eq!(value.get("objectives").unwrap(), &Value::Int(0));
        assert_eq!(value.get("match").unwrap().as_str(), Some("alias"));

        assert!(find(&catalog, &goals, "").is_empty());
        assert!(find(&catalog, &goals, "nothing like it").is_empty());
        // A three-letter alias never matches by containment; "ecc" is not a goal.
        assert!(find(&catalog, &goals, "ecc").is_empty());
    }

    #[test]
    fn excerpts_are_one_line_and_bounded() {
        assert_eq!(excerpt("a   b\n c"), "a b c");
        let long = "x".repeat(400);
        let cut = excerpt(&long);
        assert!(cut.chars().count() <= EXCERPT_CHARS);
        assert!(cut.ends_with('…'));
    }
}
