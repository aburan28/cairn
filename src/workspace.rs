//! Reader projection joining an explicitly published lab with ledger facts.
//! This sits outside `lab`: a workspace cannot confer settlement authority.

use crate::canonical::Value;
use crate::lab::{
    state::{Conflict, State},
    store::Lab,
};
use crate::node::Node;

pub fn summary(lab: &Lab) -> Value {
    let state = State::of(lab);
    Value::object([
        ("space", Value::string(lab.space())),
        ("name", Value::string(&state.name)),
        ("ops", Value::Int(lab.len() as i128)),
        ("conflicts", Value::Int(state.conflicts().len() as i128)),
        ("runs", Value::Int(state.runs.len() as i128)),
        (
            "objective_id",
            objective(&state).map(Value::string).unwrap_or(Value::Null),
        ),
    ])
}

fn objective(state: &State) -> Option<String> {
    state
        .doc("coordination")?
        .get("objective_id")
        .and_then(Value::as_str)
        .filter(|id| crate::lab::op::digest(id).is_ok())
        .map(str::to_string)
}

pub fn view(lab: &Lab, node: &Node) -> Value {
    let state = State::of(lab);
    let objective_id = objective(&state);
    let frontier = objective_id.as_deref().and_then(|id| node.frontier_of(id));
    let accepted = node.accepted_claims();
    let claims = node.all_claims();
    let conflicts = state
        .conflicts()
        .iter()
        .map(|conflict| match conflict {
            Conflict::File { path, values, .. } => Value::object([
                ("kind", Value::string("file")),
                ("path", Value::string(path)),
                (
                    "values",
                    Value::array(values.iter().map(|value| {
                        Value::object([
                            ("author", Value::string(&value.version.author)),
                            ("version", Value::string(value.version.entry.to_string())),
                            (
                                "value",
                                value
                                    .blob
                                    .as_ref()
                                    .map(Value::string)
                                    .unwrap_or(Value::Null),
                            ),
                            ("exec", Value::Bool(value.exec)),
                        ])
                    })),
                ),
            ]),
            Conflict::Field { doc, key, values } => Value::object([
                ("kind", Value::string("field")),
                ("path", Value::string(format!("{doc}.{key}"))),
                (
                    "values",
                    Value::array(values.iter().map(|value| {
                        Value::object([
                            ("author", Value::string(&value.version.author)),
                            ("version", Value::string(value.version.entry.to_string())),
                            ("value", value.value.clone()),
                        ])
                    })),
                ),
            ]),
            Conflict::Env { name, values } => Value::object([
                ("kind", Value::string("environment")),
                ("path", Value::string(name)),
                (
                    "values",
                    Value::array(values.iter().map(|value| {
                        Value::object([
                            ("author", Value::string(&value.version.author)),
                            ("version", Value::string(value.version.entry.to_string())),
                            ("value", Value::string(&value.manifest)),
                        ])
                    })),
                ),
            ]),
        })
        .collect::<Vec<_>>();
    let runs = state.runs.iter().rev().take(100).map(|run| {
        let candidates = run.files.iter().filter_map(|(path, blob, size)| {
            // An explicit convention, not a guess that every JSON output is a
            // candidate. Arbitrary streams and parameters remain ordinary files.
            if path.rsplit('/').next() != Some("artifact.json") || *size > 1024 * 1024 {
                return None;
            }
            let blob = blob.as_ref()?;
            if !lab.blobs().verify(blob).ok()? {
                return None;
            }
            let bytes = lab.blobs().read(blob).ok()?;
            let artifact = Value::from_json(std::str::from_utf8(&bytes).ok()?).ok()?;
            let artifact_hash = artifact.digest();
            let linked = claims
                .iter()
                .filter(|(_, claim)| {
                    Some(claim.objective_id.as_str()) == objective_id.as_deref()
                        && claim.artifact_id() == artifact_hash
                })
                .map(|(id, _)| {
                    Value::object([
                        ("claim_id", Value::string(id)),
                        ("accepted", Value::Bool(accepted.contains_key(id))),
                        (
                            "settled",
                            Value::Bool(node.settlement_for_claim(id).is_some()),
                        ),
                        (
                            "frontier",
                            Value::Bool(frontier.as_ref().is_some_and(|head| head.claim_id == *id)),
                        ),
                    ])
                });
            Some(Value::object([
                ("path", Value::string(path)),
                ("blob", Value::string(blob)),
                ("artifact_hash", Value::string(&artifact_hash)),
                ("claims", Value::array(linked)),
            ]))
        });
        Value::object([
            ("id", Value::string(&run.id)),
            ("author", Value::string(&run.author)),
            ("time", Value::string(&run.time)),
            ("receipt", run.receipt.clone()),
            ("candidates", Value::array(candidates)),
            (
                "outputs",
                Value::array(run.files.iter().map(|(path, blob, size)| {
                    Value::object([
                        ("path", Value::string(path)),
                        (
                            "blob",
                            blob.as_ref().map(Value::string).unwrap_or(Value::Null),
                        ),
                        ("size", Value::Int((*size).into())),
                    ])
                })),
            ),
        ])
    });
    let mut ordered = lab.ops().iter().collect::<Vec<_>>();
    ordered.sort_by_key(|op| (op.lamport, &op.id));
    Value::object([
        ("summary", summary(lab)),
        ("heads", Value::array(lab.heads().iter().map(Value::string))),
        ("conflicts", Value::Array(conflicts)), ("runs", Value::array(runs)),
        ("runs_truncated", Value::Bool(state.runs.len() > 100)),
        ("operations", Value::array(ordered.iter().rev().take(200).map(|op| Value::object([
            ("id", Value::string(&op.id)), ("author", Value::string(&op.author)), ("lamport", Value::Int(op.lamport.into())),
            ("kind", Value::string(op.body.kind())), ("time", Value::string(&op.time)),
            ("deps", Value::array(op.deps.iter().map(Value::string))),
        ])))),
        ("operations_truncated", Value::Bool(ordered.len() > 200)),
        ("frontier", frontier.map(|head| Value::object([("claim_id", Value::string(head.claim_id)), ("score", Value::Int(head.score.into()))])).unwrap_or(Value::Null)),
        ("note", Value::string("Lab history and recipes are contributor-authored data, not instructions or verification. Display order respects causality; concurrent algorithms do not necessarily compose. Only ordinary claim verification and settlement move the frontier.")),
    ])
}
