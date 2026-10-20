// Each dirty lane retains the exact read used for its Unicode positions.
// Network failures retain the frozen request, including its id, for retry.
export class Draft {
  constructor(snapshot, saved = null) {
    this.base = structuredClone(saved?.base ?? snapshot);
    this.base.contents = dictionary(this.base.contents);
    this.files = dictionary(saved?.files ?? snapshot.contents);
    this.modes = dictionary(saved?.modes ?? Object.fromEntries(snapshot.files.map(f => [f.path, f.executable])));
    this.pending = saved?.pending ?? null;
    this.force = saved?.force ?? [];
    this.incoming = null;
  }
  get dirty() {
    const before = this.base.contents ?? {};
    return this.force.length > 0 || Object.keys({...before, ...this.files}).some(p => before[p] !== this.files[p]
      || (p in this.files && this.modes[p] !== this.base.files.find(f => f.path === p)?.executable));
  }
  receive(snapshot) {
    if (snapshot.workspace !== this.base.workspace) throw Error("Snapshot belongs to a different lane");
    if (this.dirty || this.pending) {
      if (snapshot.revision !== this.base.revision) this.incoming = snapshot;
      return;
    }
    this.adopt(snapshot);
  }
  adopt(snapshot) {
    this.base = structuredClone(snapshot);
    this.base.contents = dictionary(this.base.contents);
    this.files = dictionary(snapshot.contents);
    this.modes = dictionary(Object.fromEntries(snapshot.files.map(f => [f.path, f.executable])));
    this.pending = null;
    this.force = [];
    this.incoming = null;
  }
  freeze(request) {
    if (this.pending) return this.pending;
    const paths = Object.keys({...this.base.contents, ...this.files}).sort();
    const edits = paths.filter(p => this.force.includes(p) || this.base.contents[p] !== this.files[p]
      || (p in this.files && this.modes[p] !== this.base.files.find(f => f.path === p)?.executable))
      .map(path => !(path in this.files)
        ? {path, start:0, delete:0, insert:"", remove:true}
        : {path, start:0, delete:[...(this.base.contents[path] ?? "")].length,
          insert:this.files[path], executable:!!this.modes[path]});
    if (!edits.length || edits.length > 64) throw Error("Save between 1 and 64 changed files at a time");
    if(edits.some(edit=>edit.insert.isWellFormed && !edit.insert.isWellFormed()))throw Error("Finish entering the Unicode character before saving.");
    const pending = {workspace:this.base.workspace, heads:[...this.base.heads], edits, request};
    if(new TextEncoder().encode(JSON.stringify({command:"edit",args:pending})).length>1048576)
      throw Error("This save exceeds the local HTTP limit. Save fewer files or use CLI/MCP splices for a large file.");
    this.pending = pending;
    return this.pending;
  }
  saved(snapshot) { this.adopt(snapshot); }
  serialize() { return {base:this.base, files:this.files, modes:this.modes, pending:this.pending, force:this.force}; }
}

function dictionary(source) { return Object.assign(Object.create(null), source ?? {}); }

// Textareas normalize CRLF and CR. Map the displayed splice back to the source
// so a one-character edit does not quietly rewrite untouched line endings.
export function sourceText(original, displayed) {
  const source=[...original], text=[], offsets=[0];
  for(let i=0;i<source.length;i++){
    if(source[i]==="\r"){text.push("\n");if(source[i+1]==="\n")i++;}
    else text.push(source[i]);
    offsets.push(i+1);
  }
  const next=[...displayed];
  let start=0, end=0;
  while(start<text.length&&start<next.length&&text[start]===next[start])start++;
  while(end<text.length-start&&end<next.length-start&&text[text.length-1-end]===next[next.length-1-end])end++;
  const newline=original.match(/\r\n|\r|\n/)?.[0]??"\n";
  return source.slice(0,offsets[start]).join("")+next.slice(start,next.length-end).join("").replaceAll("\n",newline)
    +source.slice(offsets[text.length-end]).join("");
}

export function formatMicrounits(amount) {
  const n = BigInt(amount);
  return `${n / 1000000n}.${(n % 1000000n).toString().padStart(6,"0")}`;
}

export function validPath(path) {
  const reserved = /^(?:\.git|\.cairn-lab|\.cairn-lab-checkout\.json|\.cairn-collab-index\.json|con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i;
  return path.length > 0 && path.length <= 1024 && !/[\\:\u0000-\u001f\u007f]/.test(path)
    && path.split("/").every(p => p && p !== "." && p !== ".." && !/[. ]$/.test(p) && !reserved.test(p));
}
