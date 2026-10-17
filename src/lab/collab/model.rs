use std::collections::BTreeSet;

use serde_json::{json, Value as Json};

use crate::canonical::Value;
use crate::lab::{op, LabError};

pub(super) const DOCUMENT: &str = "cairn.collab/v1";
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
pub const MAX_EDITS: usize = 64;
pub(super) const MAX_PARENTS: usize = op::MAX_DEPS;
pub(super) const MAX_CHANGES: usize = 16_384;
pub(super) const MAX_ATOMS: usize = 1_000_000;

pub(super) fn invalid(message: impl Into<String>) -> LabError {
    LabError::Invalid(message.into())
}

pub(super) fn canonical(value: &Json) -> Result<Value, LabError> {
    Value::from_json(&value.to_string()).map_err(|e| invalid(e.to_string()))
}

pub(super) fn digest(value: &Json) -> Result<String, LabError> {
    Ok(canonical(value)?.digest())
}

pub(super) fn only(value: &Json, fields: &[&str]) -> Result<(), LabError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("expected an object"))?;
    if let Some(key) = object.keys().find(|key| !fields.contains(&key.as_str())) {
        return Err(invalid(format!("unknown collaboration field {key:?}")));
    }
    Ok(())
}

pub(super) fn text(value: &Json, name: &str) -> Result<String, LabError> {
    value
        .get(name)
        .and_then(Json::as_str)
        .map(str::to_string)
        .ok_or_else(|| invalid(format!("{name} must be a string")))
}

pub(super) fn number(value: &Json, name: &str) -> Result<usize, LabError> {
    value
        .get(name)
        .and_then(Json::as_u64)
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| invalid(format!("{name} must be a non-negative whole number")))
}

pub(super) fn address(value: &str) -> Result<String, LabError> {
    op::blob_address(value).map_err(Into::into)
}

pub(super) fn path(value: &str) -> Result<String, LabError> {
    let path = op::normalize_path(value)?;
    if path.split('/').any(|p| {
        let lower = p.to_ascii_lowercase();
        let stem = lower.split('.').next().unwrap_or_default();
        matches!(
            lower.as_str(),
            ".git" | ".cairn-lab" | ".cairn-lab-checkout.json" | ".cairn-collab-index.json"
        ) || p.contains(':')
            || p.ends_with(['.', ' '])
            || matches!(
                stem,
                "con"
                    | "prn"
                    | "aux"
                    | "nul"
                    | "com1"
                    | "com2"
                    | "com3"
                    | "com4"
                    | "com5"
                    | "com6"
                    | "com7"
                    | "com8"
                    | "com9"
                    | "lpt1"
                    | "lpt2"
                    | "lpt3"
                    | "lpt4"
                    | "lpt5"
                    | "lpt6"
                    | "lpt7"
                    | "lpt8"
                    | "lpt9"
            )
    }) {
        return Err(invalid(
            "source paths cannot name collaboration or Git metadata",
        ));
    }
    Ok(path)
}

pub(super) fn request(value: &str) -> Result<String, LabError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
    {
        return Err(invalid(
            "request id must be 1..=128 ASCII letters, digits, '.', '-' or '_'",
        ));
    }
    Ok(value.to_string())
}

pub(super) fn heads(value: &Json) -> Result<BTreeSet<String>, LabError> {
    let list = value
        .as_array()
        .ok_or_else(|| invalid("heads must be an array"))?;
    if list.len() > MAX_CHANGES {
        return Err(invalid("too many causal heads"));
    }
    let result = list
        .iter()
        .map(|v| {
            address(
                v.as_str()
                    .ok_or_else(|| invalid("head must be an address"))?,
            )
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if result.len() != list.len() {
        return Err(invalid("duplicate causal head"));
    }
    Ok(result)
}

/// A Unicode-scalar splice against the exact heads returned by `read`.
/// One change can edit several files atomically; positions never refer to a
/// later server-side draft the caller has not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    pub path: String,
    pub start: usize,
    pub delete: usize,
    pub insert: String,
    pub executable: Option<bool>,
    pub remove: bool,
}

impl Edit {
    pub fn splice(path: &str, start: usize, delete: usize, insert: &str) -> Self {
        Self {
            path: path.into(),
            start,
            delete,
            insert: insert.into(),
            executable: None,
            remove: false,
        }
    }

    pub fn from_json(value: &Json) -> Result<Self, LabError> {
        only(
            value,
            &["path", "start", "delete", "insert", "executable", "remove"],
        )?;
        let executable = match value.get("executable") {
            None | Some(Json::Null) => None,
            Some(Json::Bool(v)) => Some(*v),
            _ => return Err(invalid("executable must be boolean")),
        };
        let remove = match value.get("remove") {
            None | Some(Json::Bool(false)) => false,
            Some(Json::Bool(true)) => true,
            _ => return Err(invalid("remove must be boolean")),
        };
        let edit = Self {
            path: path(&text(value, "path")?)?,
            start: number(value, "start")?,
            delete: number(value, "delete")?,
            insert: text(value, "insert")?,
            executable,
            remove,
        };
        if edit.insert.len() > MAX_TEXT_BYTES {
            return Err(invalid("insert exceeds source size limit"));
        }
        Ok(edit)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct AtomId {
    pub change: [u8; 32],
    pub edit: u16,
    pub offset: u32,
}

impl AtomId {
    pub fn new(change: &str, edit: usize, offset: usize) -> Result<Self, LabError> {
        let change = address(change)?;
        let bytes = crate::hex::decode(&change[crate::canonical::DIGEST_PREFIX.len()..])
            .ok_or_else(|| invalid("invalid character change address"))?;
        let mut hash = [0; 32];
        hash.copy_from_slice(&bytes);
        Ok(Self {
            change: hash,
            edit: edit.try_into().map_err(|_| invalid("too many edits"))?,
            offset: offset
                .try_into()
                .map_err(|_| invalid("character offset too large"))?,
        })
    }
    pub fn change_id(self) -> String {
        format!("sha256:{}", crate::hex::encode(&self.change))
    }
    pub fn encode(self) -> String {
        format!("{}/{}/{}", self.change_id(), self.edit, self.offset)
    }
    pub fn parse(value: &str) -> Result<Self, LabError> {
        let parts: Vec<_> = value.split('/').collect();
        if parts.len() != 3 {
            return Err(invalid("invalid character identifier"));
        }
        let result = Self::new(
            parts[0],
            parts[1]
                .parse()
                .map_err(|_| invalid("invalid edit index"))?,
            parts[2]
                .parse()
                .map_err(|_| invalid("invalid character offset"))?,
        )?;
        if result.encode() != value {
            return Err(invalid("noncanonical character identifier"));
        }
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Span {
    pub first: AtomId,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Splice {
    pub path: String,
    pub after: Option<AtomId>,
    pub delete: Vec<Span>,
    pub insert: String,
    pub executable: Option<bool>,
    pub remove: bool,
}

impl Splice {
    fn to_json(&self) -> Json {
        json!({"path": self.path, "after": self.after.map(AtomId::encode),
            "delete": self.delete.iter().map(|s| json!({"first":s.first.encode(),"count":s.count})).collect::<Vec<_>>(),
            "insert":self.insert, "executable":self.executable, "remove":self.remove})
    }
    fn parse(v: &Json) -> Result<Self, LabError> {
        only(
            v,
            &["path", "after", "delete", "insert", "executable", "remove"],
        )?;
        let after = match v.get("after") {
            Some(Json::Null) => None,
            Some(Json::String(s)) => Some(AtomId::parse(s)?),
            _ => return Err(invalid("after must be a character id or null")),
        };
        let spans = v["delete"]
            .as_array()
            .ok_or_else(|| invalid("delete must contain spans"))?;
        if spans.len() > MAX_ATOMS {
            return Err(invalid("too many deletion spans"));
        }
        let mut delete = Vec::new();
        let mut total = 0usize;
        for s in spans {
            only(s, &["first", "count"])?;
            let first = AtomId::parse(&text(s, "first")?)?;
            let count = number(s, "count")?;
            total = total
                .checked_add(count)
                .ok_or_else(|| invalid("deletion overflow"))?;
            if count == 0
                || total > MAX_ATOMS
                || (first.offset as usize)
                    .checked_add(count)
                    .is_none_or(|end| end > u32::MAX as usize)
            {
                return Err(invalid("invalid deletion span length"));
            }
            delete.push(Span {
                first,
                count: count as u32,
            });
        }
        let executable = match v.get("executable") {
            Some(Json::Null) => None,
            Some(Json::Bool(v)) => Some(*v),
            _ => return Err(invalid("executable must be boolean or null")),
        };
        let remove = v["remove"]
            .as_bool()
            .ok_or_else(|| invalid("remove must be boolean"))?;
        let insert = text(v, "insert")?;
        if insert.len() > MAX_TEXT_BYTES
            || (remove
                && (!insert.is_empty()
                    || after.is_some()
                    || !delete.is_empty()
                    || executable.is_some()))
        {
            return Err(invalid("invalid removal or oversized insertion"));
        }
        Ok(Self {
            path: path(&text(v, "path")?)?,
            after,
            delete,
            insert,
            executable,
            remove,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Change {
    pub id: String,
    pub author: String,
    pub request: String,
    pub workspace: Option<String>,
    pub title: Option<String>,
    pub parents: BTreeSet<String>,
    pub edits: Vec<Splice>,
}

impl Change {
    pub fn value(&self) -> Json {
        json!({"type":"cairn.collab.change", "version":1, "author":self.author,
            "kind":if self.workspace.is_none() {"workspace"} else if self.edits.is_empty() {"integrate"} else {"edit"},
            "request":self.request, "workspace":self.workspace, "title":self.title,
            "parents":self.parents, "edits":self.edits.iter().map(Splice::to_json).collect::<Vec<_>>()})
    }
    pub fn workspace(&self) -> &str {
        self.workspace.as_deref().unwrap_or(&self.id)
    }
    pub fn seal(mut self) -> Result<Self, LabError> {
        self.id = digest(&self.value())?;
        Ok(self)
    }
    pub fn parse(v: &Json, author: &str) -> Result<Self, LabError> {
        only(
            v,
            &[
                "type",
                "version",
                "kind",
                "author",
                "request",
                "workspace",
                "title",
                "parents",
                "edits",
            ],
        )?;
        if v["type"] != "cairn.collab.change" || v["version"] != 1 || text(v, "author")? != author {
            return Err(invalid(
                "unsupported collaboration format or mismatched author",
            ));
        }
        let workspace = match v.get("workspace") {
            Some(Json::Null) => None,
            Some(Json::String(s)) => Some(address(s)?),
            _ => return Err(invalid("workspace must be an address or null")),
        };
        let title = match v.get("title") {
            Some(Json::Null) => None,
            Some(Json::String(s))
                if !s.trim().is_empty() && s.len() <= 256 && !s.contains('\0') =>
            {
                Some(s.clone())
            }
            _ => return Err(invalid("title must be 1..=256 bytes or null")),
        };
        let edits = v["edits"]
            .as_array()
            .ok_or_else(|| invalid("edits must be an array"))?;
        let kind = if workspace.is_none() {
            "workspace"
        } else if edits.is_empty() {
            "integrate"
        } else {
            "edit"
        };
        if edits.len() > MAX_EDITS
            || workspace.is_none() != title.is_some()
            || (workspace.is_none() && !edits.is_empty())
            || v["kind"] != kind
        {
            return Err(invalid(
                "workspace, edit or integration kind does not match its content",
            ));
        }
        let edits = edits
            .iter()
            .map(Splice::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let unique = edits.iter().map(|e| &e.path).collect::<BTreeSet<_>>();
        if unique.len() != edits.len() {
            return Err(invalid("one splice per path in an atomic change"));
        }
        let parents = heads(&v["parents"])?;
        if parents.len() > MAX_PARENTS {
            return Err(invalid("a change can observe at most 64 causal parents; integrate a wide frontier in batches"));
        }
        Self {
            id: String::new(),
            author: author.into(),
            request: request(&text(v, "request")?)?,
            workspace,
            title,
            parents,
            edits,
        }
        .seal()
    }
}
