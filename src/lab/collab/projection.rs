use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde_json::{json, Value as Json};

use super::model::{self, AtomId, Change, DOCUMENT, MAX_ATOMS, MAX_CHANGES, MAX_TEXT_BYTES};
use crate::lab::{op::Body, state::State, store::Lab, LabError};

#[derive(Clone, Default)]
pub(super) struct Bits(Vec<u64>);
impl Bits {
    fn set(&mut self, n: usize) {
        self.0.resize(self.0.len().max(n / 64 + 1), 0);
        self.0[n / 64] |= 1 << (n % 64);
    }
    pub fn has(&self, n: usize) -> bool {
        self.0.get(n / 64).is_some_and(|v| v & (1 << (n % 64)) != 0)
    }
    fn union(&mut self, other: &Self) {
        self.0.resize(self.0.len().max(other.0.len()), 0);
        for (a, b) in self.0.iter_mut().zip(&other.0) {
            *a |= b;
        }
    }
}

pub(super) struct Node {
    pub change: Change,
    pub clock: u64,
    pub ancestors: Bits,
    pub sources: Vec<usize>,
}

/// A disposable index over authenticated lab operations. Malformed protocol
/// values remain inspectable issues, never partially executed edits.
pub struct Graph {
    pub(super) space: String,
    pub(super) nodes: Vec<Node>,
    pub(super) index: BTreeMap<String, usize>,
    requests: BTreeMap<(String, String), Vec<String>>,
    pub issues: Vec<String>,
}

impl Graph {
    pub fn load(lab: &Lab) -> Result<Self, LabError> {
        let state = State::of(lab);
        let excluded: HashSet<_> = state
            .excluded
            .iter()
            .filter(|e| e.entry.is_none())
            .map(|e| e.op.as_str())
            .collect();
        let mut graph = Self {
            space: lab.space().into(),
            nodes: Vec::new(),
            index: BTreeMap::new(),
            requests: BTreeMap::new(),
            issues: Vec::new(),
        };
        let mut raw: BTreeMap<String, (Change, Vec<usize>)> = BTreeMap::new();
        for (source, op) in lab.ops().iter().enumerate() {
            if excluded.contains(op.id.as_str()) {
                continue;
            }
            let Body::Doc { doc, fields } = &op.body else {
                continue;
            };
            if doc != DOCUMENT {
                continue;
            }
            if fields.len() != 1 || !fields[0].pred.is_empty() {
                graph.issues.push(format!(
                    "{}: collaboration changes are immutable single fields",
                    op.id
                ));
                continue;
            }
            let parsed = (|| {
                let json: Json = serde_json::from_str(&fields[0].value.canonical_string())
                    .map_err(|e| model::invalid(e.to_string()))?;
                let change = Change::parse(&json, &op.author)?;
                if change.id != fields[0].key {
                    return Err(model::invalid("change key does not match payload hash"));
                }
                Ok(change)
            })();
            match parsed {
                Ok(change) => {
                    raw.entry(change.id.clone())
                        .or_insert((change, Vec::new()))
                        .1
                        .push(source);
                }
                Err(e) => graph.issues.push(format!("{}: {e}", op.id)),
            }
        }
        if raw.len() > MAX_CHANGES {
            return Err(LabError::Unavailable(format!(
                "collaboration history exceeds {MAX_CHANGES} changes"
            )));
        }
        // An author cannot give the same request id two meanings. Reject both
        // meanings so arrival order cannot choose an equivocation's winner.
        let mut requests: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for (id, (c, _)) in &raw {
            requests
                .entry((c.author.clone(), c.request.clone()))
                .or_default()
                .push(id.clone());
        }
        for ids in requests.values().filter(|ids| ids.len() > 1) {
            for id in ids {
                raw.remove(id);
                graph.issues.push(format!(
                    "{id}: author reused a request id with different content"
                ));
            }
        }
        graph.requests = requests;
        // A long causal chain used to rescan every remaining change until
        // its parent happened to precede it in hash order. A ready set visits
        // each edge once and keeps the same deterministic causal semantics.
        let mut waiting = BTreeMap::new();
        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut ready = BTreeSet::new();
        for (id, (change, _)) in &raw {
            let mut count = 0;
            for parent in &change.parents {
                if raw.contains_key(parent) {
                    count += 1;
                    children.entry(parent.clone()).or_default().push(id.clone());
                }
            }
            waiting.insert(id.clone(), count);
            if count == 0 {
                ready.insert(id.clone());
            }
        }
        while let Some(id) = ready.pop_first() {
            let (change, sources) = raw.remove(&id).expect("ready change exists");
            if let Err(error) = graph.admit(lab, change, sources) {
                graph.issues.push(format!("{id}: {error}"));
            }
            if let Some(children) = children.remove(&id) {
                for child in children {
                    let count = waiting.get_mut(&child).expect("child exists");
                    *count -= 1;
                    if *count == 0 {
                        ready.insert(child);
                    }
                }
            }
        }
        for id in raw.keys() {
            graph
                .issues
                .push(format!("{id}: cyclic collaboration parents"));
        }
        graph.issues.sort();
        Ok(graph)
    }

    pub(super) fn retry(&self, change: &Change) -> Result<bool, LabError> {
        if let Some(ids) = self
            .requests
            .get(&(change.author.clone(), change.request.clone()))
        {
            if ids.len() != 1 || ids[0] != change.id {
                return Err(LabError::Refused("request id already has different or equivocated content; read again and use a fresh id".into()));
            }
            return Ok(self.index.contains_key(&change.id));
        }
        Ok(false)
    }

    fn admit(&mut self, lab: &Lab, change: Change, sources: Vec<usize>) -> Result<(), LabError> {
        let mut ancestors = Bits::default();
        let mut clock = 1;
        for p in &change.parents {
            let i = *self
                .index
                .get(p)
                .ok_or_else(|| LabError::Unavailable(format!("missing or excluded parent {p}")))?;
            ancestors.union(&self.nodes[i].ancestors);
            ancestors.set(i);
            clock = clock.max(
                self.nodes[i]
                    .clock
                    .checked_add(1)
                    .ok_or_else(|| model::invalid("logical clock exhausted"))?,
            );
        }
        let mut valid_sources = Vec::new();
        for source in sources {
            let past = lab.ancestors_of(source);
            if change
                .parents
                .iter()
                .all(|p| self.nodes[self.index[p]].sources.iter().any(|&s| past[s]))
            {
                valid_sources.push(source);
            }
        }
        if valid_sources.is_empty() {
            return Err(model::invalid(
                "change parents are outside its signed causal past",
            ));
        }
        self.validate(&change, &ancestors)?;
        let i = self.nodes.len();
        self.index.insert(change.id.clone(), i);
        self.nodes.push(Node {
            change,
            clock,
            ancestors,
            sources: valid_sources,
        });
        Ok(())
    }

    pub(super) fn validate(&self, change: &Change, ancestors: &Bits) -> Result<(), LabError> {
        let mut atoms = 0usize;
        let mut bytes = BTreeMap::<&str, usize>::new();
        for edit in self
            .nodes
            .iter()
            .enumerate()
            .filter(|(i, _)| ancestors.has(*i))
            .flat_map(|(_, n)| n.change.edits.iter())
            .chain(change.edits.iter())
        {
            atoms = atoms
                .checked_add(edit.insert.chars().count())
                .ok_or_else(|| model::invalid("character count overflow"))?;
            let size = bytes.entry(&edit.path).or_default();
            *size = size
                .checked_add(edit.insert.len())
                .ok_or_else(|| model::invalid("source size overflow"))?;
            if atoms > MAX_ATOMS || *size > MAX_TEXT_BYTES {
                return Err(model::invalid("workspace history exceeds character or source-byte limits; start a new space from a clear checkpoint"));
            }
        }
        if let Some(workspace) = &change.workspace {
            let root = self.node(workspace)?;
            if root.change.workspace.is_some() || change.parents.is_empty() {
                return Err(model::invalid(
                    "edit must descend from a workspace creation",
                ));
            }
            if change.edits.is_empty() {
                if !change
                    .parents
                    .iter()
                    .any(|p| self.nodes[self.index[p]].change.workspace() == workspace)
                {
                    return Err(model::invalid(
                        "integration must observe its target workspace",
                    ));
                }
                let family = self.family(workspace)?;
                for parent in &change.parents {
                    if self.family(self.node(parent)?.change.workspace())? != family {
                        return Err(model::invalid(
                            "integrate only related workspaces; fork a shared base first",
                        ));
                    }
                }
            } else if change
                .parents
                .iter()
                .any(|p| self.nodes[self.index[p]].change.workspace() != workspace)
            {
                return Err(model::invalid(
                    "an edit cannot mix workspaces; integrate exact heads first",
                ));
            }
            for edit in &change.edits {
                for atom in edit
                    .after
                    .into_iter()
                    .chain(edit.delete.iter().map(|s| s.first))
                {
                    let i = *self
                        .index
                        .get(&atom.change_id())
                        .ok_or_else(|| model::invalid("character belongs to unknown change"))?;
                    let source = &self.nodes[i].change;
                    let piece = source
                        .edits
                        .get(atom.edit as usize)
                        .ok_or_else(|| model::invalid("character edit index out of range"))?;
                    if !ancestors.has(i)
                        || piece.path != edit.path
                        || atom.offset as usize >= piece.insert.chars().count()
                    {
                        return Err(model::invalid(
                            "character is not in this file's observed causal history",
                        ));
                    }
                }
                for span in &edit.delete {
                    let piece =
                        &self.node(&span.first.change_id())?.change.edits[span.first.edit as usize];
                    if span.first.offset as usize + span.count as usize
                        > piece.insert.chars().count()
                    {
                        return Err(model::invalid("deletion span exceeds insertion"));
                    }
                }
            }
        } else if !change.parents.is_empty() {
            let workspaces = change
                .parents
                .iter()
                .map(|p| self.nodes[self.index[p]].change.workspace())
                .collect::<BTreeSet<_>>();
            if workspaces.len() != 1 {
                return Err(model::invalid(
                    "a fork must name one workspace's causal frontier",
                ));
            }
        }
        Ok(())
    }

    pub(super) fn node(&self, id: &str) -> Result<&Node, LabError> {
        self.index.get(id).map(|&i| &self.nodes[i]).ok_or_else(|| {
            LabError::Unavailable(format!(
                "unknown, excluded or unavailable change {id}; refresh/reset the cursor"
            ))
        })
    }

    fn family(&self, workspace: &str) -> Result<&str, LabError> {
        let root = self.node(workspace)?;
        if root.change.parents.is_empty() {
            return Ok(&root.change.id);
        }
        self.nodes
            .iter()
            .enumerate()
            .find(|(i, n)| {
                root.ancestors.has(*i)
                    && n.change.workspace.is_none()
                    && n.change.parents.is_empty()
            })
            .map(|(_, n)| n.change.id.as_str())
            .ok_or_else(|| model::invalid("workspace has no shared origin"))
    }

    pub(super) fn closure(&self, heads: &BTreeSet<String>) -> Result<Bits, LabError> {
        let mut result = Bits::default();
        for head in heads {
            let n = self.node(head)?;
            result.union(&n.ancestors);
            result.set(self.index[head]);
        }
        Ok(result)
    }

    pub fn heads(&self, workspace: &str) -> Result<BTreeSet<String>, LabError> {
        let root = self.node(workspace)?;
        if root.change.workspace.is_some() {
            return Err(model::invalid("workspace id must name its creation"));
        }
        let mut heads = self
            .nodes
            .iter()
            .filter(|n| n.change.workspace() == workspace)
            .map(|n| n.change.id.clone())
            .collect::<BTreeSet<_>>();
        for n in &self.nodes {
            if n.change.workspace() == workspace {
                for p in &n.change.parents {
                    heads.remove(p);
                }
            }
        }
        Ok(heads)
    }

    pub fn workspaces(&self) -> Json {
        Json::Array(
            self.nodes
                .iter()
                .filter(|n| n.change.workspace.is_none())
                .map(|n| {
                    json!({"id":n.change.id,
            "title":n.change.title,"author":n.change.author,"base":n.change.parents,
            "heads":self.heads(&n.change.id).unwrap_or_default()})
                })
                .collect(),
        )
    }

    pub fn snapshot(
        &self,
        workspace: &str,
        at: Option<&BTreeSet<String>>,
    ) -> Result<Snapshot, LabError> {
        let heads = match at {
            Some(heads) => heads.clone(),
            None => self.heads(workspace)?,
        };
        if heads.is_empty() {
            return Err(model::invalid(
                "snapshot heads must belong to the requested workspace",
            ));
        }
        for head in &heads {
            if self.node(head)?.change.workspace() != workspace {
                return Err(model::invalid(
                    "snapshot heads must belong to the requested workspace",
                ));
            }
        }
        let visible = self.closure(&heads)?;
        let mut drafts: BTreeMap<String, Draft> = BTreeMap::new();
        let mut count = 0usize;
        let mut order = (0..self.nodes.len())
            .filter(|&i| visible.has(i))
            .collect::<Vec<_>>();
        order.sort_by_key(|&i| (self.nodes[i].clock, self.nodes[i].change.id.as_str()));
        for i in order {
            let node = &self.nodes[i];
            for (part, edit) in node.change.edits.iter().enumerate() {
                let draft = drafts.entry(edit.path.clone()).or_default();
                // A later edit on only one branch cannot silently resolve an
                // earlier clash. A resolving file write must observe both.
                draft
                    .overlaps
                    .retain(|&(a, b)| !(node.ancestors.has(a) && node.ancestors.has(b)));
                for &(previous, _) in &draft.writes {
                    if !node.ancestors.has(previous) {
                        let other = self.nodes[previous]
                            .change
                            .edits
                            .iter()
                            .find(|e| e.path == edit.path)
                            .expect("file writer");
                        if overlapping_replacements(edit, other) {
                            draft.overlaps.push((previous, i));
                        }
                    }
                }
                if draft.overlaps.len() > 4096 {
                    return Err(LabError::Unavailable(
                        "too many unresolved overlapping replacements".into(),
                    ));
                }
                draft.writes.push((i, !edit.remove));
                if let Some(exec) = edit.executable {
                    draft.modes.push((i, exec));
                }
                if edit.remove {
                    for atom in &draft.atoms {
                        if node.ancestors.has(atom.origin) {
                            draft.deleted.insert(atom.id);
                        }
                    }
                }
                for span in &edit.delete {
                    for offset in span.first.offset..span.first.offset + span.count {
                        draft.deleted.insert(AtomId {
                            offset,
                            ..span.first
                        });
                    }
                }
                count = count
                    .checked_add(edit.insert.chars().count())
                    .ok_or_else(|| model::invalid("character count overflow"))?;
                if count > MAX_ATOMS {
                    return Err(LabError::Unavailable(format!(
                        "snapshot exceeds {MAX_ATOMS} historical characters"
                    )));
                }
                let mut after = edit.after;
                let first = AtomId::new(&node.change.id, part, 0)?;
                for (offset, value) in edit.insert.chars().enumerate() {
                    let id = AtomId {
                        offset: offset
                            .try_into()
                            .map_err(|_| model::invalid("character offset overflow"))?,
                        ..first
                    };
                    draft.atoms.push(Atom {
                        id,
                        after,
                        value,
                        clock: node.clock,
                        origin: i,
                    });
                    after = Some(id);
                }
            }
        }
        let mut files = BTreeMap::new();
        let mut conflicts = Vec::new();
        let mut atoms = BTreeMap::new();
        for (path, draft) in drafts {
            let presence = self.maximal(&draft.writes);
            let modes = self.maximal(&draft.modes);
            if !draft.overlaps.is_empty() {
                conflicts.push(format!("{path}: concurrent overlapping replacements; read all heads and resolve explicitly"));
            }
            if presence.len() > 1 {
                conflicts.push(format!("{path}: concurrent deletion and edit"));
            }
            if !presence.contains(&true) {
                continue;
            }
            if modes.len() > 1 {
                conflicts.push(format!("{path}: concurrent executable modes"));
            }
            let (text, ids) = draft.render()?;
            if text.len() > MAX_TEXT_BYTES {
                return Err(LabError::Unavailable(format!(
                    "{path}: source exceeds {MAX_TEXT_BYTES} bytes"
                )));
            }
            files.insert(
                path.clone(),
                File {
                    blob: crate::canonical::digest_bytes(text.as_bytes()),
                    text,
                    executable: modes.contains(&true),
                },
            );
            atoms.insert(path, ids);
        }
        let mut portable = BTreeMap::new();
        for path in files.keys() {
            if let Some(previous) = portable.insert(path.to_lowercase(), path) {
                conflicts.push(format!(
                    "{previous}, {path}: filenames collide on a case-insensitive filesystem"
                ));
            }
        }
        for path in files.keys() {
            let mut prefix = path.as_str();
            while let Some((parent, _)) = prefix.rsplit_once('/') {
                if portable.contains_key(&parent.to_lowercase()) {
                    conflicts.push(format!("{parent}: both a file and a directory"));
                }
                prefix = parent;
            }
        }
        conflicts.sort();
        conflicts.dedup();
        let mut result = Snapshot {
            space: self.space.clone(),
            workspace: workspace.into(),
            heads,
            files,
            conflicts,
            revision: String::new(),
            atoms,
        };
        result.revision = model::digest(&result.manifest())?;
        Ok(result)
    }

    fn maximal(&self, values: &[(usize, bool)]) -> BTreeSet<bool> {
        values
            .iter()
            .filter(|(i, _)| !values.iter().any(|(j, _)| self.nodes[*j].ancestors.has(*i)))
            .map(|(_, v)| *v)
            .collect()
    }

    /// A causal frontier cursor survives late delivery of older concurrent
    /// work. Pagination advances through delivered changes only.
    pub fn feed(
        &self,
        workspace: &str,
        cursor: &BTreeSet<String>,
        limit: usize,
    ) -> Result<Json, LabError> {
        if limit == 0 || limit > 256 {
            return Err(model::invalid("feed limit must be 1..=256"));
        }
        let wanted = self.closure(&self.heads(workspace)?)?;
        let mut known = self.closure(cursor)?;
        for head in cursor {
            if !wanted.has(self.index[head]) {
                return Err(model::invalid("cursor is outside this workspace history"));
            }
        }
        let mut missing = (0..self.nodes.len())
            .filter(|&i| wanted.has(i) && !known.has(i))
            .collect::<Vec<_>>();
        missing.sort_by_key(|&i| (self.nodes[i].clock, self.nodes[i].change.id.as_str()));
        let more = missing.len() > limit;
        missing.truncate(limit);
        let changes=missing.iter().map(|&i| {known.set(i);json!({"id":self.nodes[i].change.id,"clock":self.nodes[i].clock,"change":self.nodes[i].change.value()})}).collect::<Vec<_>>();
        let mut next = (0..self.nodes.len())
            .filter(|&i| known.has(i))
            .map(|i| self.nodes[i].change.id.clone())
            .collect::<BTreeSet<_>>();
        for (i, node) in self.nodes.iter().enumerate() {
            if known.has(i) {
                for p in &node.change.parents {
                    next.remove(p);
                }
            }
        }
        Ok(
            json!({"workspace":workspace,"changes":changes,"cursor":next,"more":more,"issues":self.issues}),
        )
    }
}

fn overlapping_replacements(a: &super::model::Splice, b: &super::model::Splice) -> bool {
    if a.insert.is_empty() && b.insert.is_empty() {
        return false;
    }
    let mut left = a.delete.iter().collect::<Vec<_>>();
    let mut right = b.delete.iter().collect::<Vec<_>>();
    left.sort_by_key(|s| s.first);
    right.sort_by_key(|s| s.first);
    let (mut i, mut j) = (0, 0);
    while i < left.len() && j < right.len() {
        let (x, y) = (left[i], right[j]);
        let key_x = (x.first.change, x.first.edit);
        let key_y = (y.first.change, y.first.edit);
        if key_x == key_y
            && x.first.offset < y.first.offset + y.count
            && y.first.offset < x.first.offset + x.count
        {
            return true;
        }
        if (key_x, x.first.offset + x.count) <= (key_y, y.first.offset + y.count) {
            i += 1;
        } else {
            j += 1;
        }
    }
    false
}

#[derive(Clone)]
struct Atom {
    id: AtomId,
    after: Option<AtomId>,
    value: char,
    clock: u64,
    origin: usize,
}
#[derive(Default)]
struct Draft {
    atoms: Vec<Atom>,
    deleted: HashSet<AtomId>,
    writes: Vec<(usize, bool)>,
    modes: Vec<(usize, bool)>,
    overlaps: Vec<(usize, usize)>,
}
impl Draft {
    fn render(&self) -> Result<(String, Vec<AtomId>), LabError> {
        let mut children: HashMap<Option<AtomId>, Vec<&Atom>> = HashMap::new();
        for atom in &self.atoms {
            children.entry(atom.after).or_default().push(atom);
        }
        for siblings in children.values_mut() {
            siblings.sort_by_key(|a| (a.clock, a.id));
        }
        let mut stack = children.get(&None).cloned().unwrap_or_default();
        let mut text = String::new();
        let mut ids = Vec::new();
        let mut visited = 0;
        // Iterative traversal handles a million-character insertion without a
        // million recursive frames. Newer children precede the old successor.
        while let Some(atom) = stack.pop() {
            visited += 1;
            if !self.deleted.contains(&atom.id) {
                text.push(atom.value);
                ids.push(atom.id);
            }
            if let Some(next) = children.get(&Some(atom.id)) {
                stack.extend(next.iter().copied());
            }
        }
        if visited != self.atoms.len() {
            return Err(model::invalid("unreachable collaboration character"));
        }
        Ok((text, ids))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub text: String,
    pub executable: bool,
    pub blob: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub space: String,
    pub workspace: String,
    pub heads: BTreeSet<String>,
    pub revision: String,
    pub files: BTreeMap<String, File>,
    pub conflicts: Vec<String>,
    pub(super) atoms: BTreeMap<String, Vec<AtomId>>,
}
impl Snapshot {
    pub fn manifest(&self) -> Json {
        json!({"type":"cairn.collab.snapshot","version":1,"space":self.space,"workspace":self.workspace,"heads":self.heads,
            "files":self.files.iter().map(|(p,f)|json!({"path":p,"blob":f.blob,"size":f.text.len(),"executable":f.executable})).collect::<Vec<_>>(),"conflicts":self.conflicts})
    }
    pub fn to_json(&self, include_text: bool) -> Json {
        let mut v = self.manifest();
        v["revision"] = json!(self.revision);
        if include_text {
            v["contents"] = json!(self
                .files
                .iter()
                .map(|(p, f)| (p.clone(), f.text.clone()))
                .collect::<BTreeMap<_, _>>());
        }
        v
    }
    pub fn require_clear(&self) -> Result<(), LabError> {
        if !self.conflicts.is_empty() {
            return Err(LabError::Refused(format!(
                "resolve workspace conflicts before consuming it: {}",
                self.conflicts.join("; ")
            )));
        }
        Ok(())
    }
}
