import { Draft, formatMicrounits, validPath, sourceText } from "/model.js";

const $ = id => document.getElementById(id);
const short = id => id?.replace(/^sha256:/, "").slice(0, 12) ?? "—";
const shell = value => `'${String(value).replaceAll("'", "'\\''")}'`;
const el = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
};
const button = (label, action, className) => {
  const b = el("button", label, className);
  b.type = "button";
  b.addEventListener("click", () => safely(action));
  return b;
};
let token = new URLSearchParams(location.hash.slice(1)).get("token");
try {
  if (token) sessionStorage.setItem("cairn-workbench-token", token);
  else token = sessionStorage.getItem("cairn-workbench-token");
} catch { /* The printed link works even if browser storage is disabled. */ }
history.replaceState(null, "", location.pathname);
let lanes = [], selected = null, file = null, status = null, saving = false, currentJob = null;
const drafts = new Map();
const feeds = new Map();
const current = () => drafts.get(selected);
const id = () => crypto.randomUUID();
let connected = false;
let navigation = 0;
let pendingJob = null, jobsRestored = false, recipeOf = null;

function notice(message = "") { $("notice").textContent = message; $("notice").hidden = !message; }
async function safely(action) { try { await action(); } catch (error) { notice(error.message); } }
async function api(command, args = {}) {
  if (!token) throw Error("Open the private link printed by cairn lab web to connect. Your signing key stays in the local process.");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch("/api", {method:"POST", headers:{"Content-Type":"application/json", Authorization:`Bearer ${token}`},
      body:JSON.stringify({command,args}), cache:"no-store", credentials:"omit", redirect:"error", signal:controller.signal});
    const result = await response.json();
    if (!response.ok) {
      const error = Error(result.error ?? `Request failed (${response.status})`);
      error.kind = result.kind;
      error.confirmed = true;
      error.status = response.status;
      throw error;
    }
    connected = true;
    $("connection").textContent = "● Connected locally";
    return result;
  } catch (error) {
    if (!error.confirmed) {
      connected = false;
      $("connection").textContent = "○ Reconnecting · drafts retained";
      throw Error("Connection interrupted. Your draft and request are retained. Retry the same save when connected.");
    }
    throw error;
  } finally { clearTimeout(timeout); }
}
function persist(d) {
  try { sessionStorage.setItem(`cairn-draft:${d.base.space}:${d.base.workspace}`, JSON.stringify(d.serialize())); }
  catch { notice("Browser draft recovery is unavailable. Export your draft before closing this tab."); }
}
function stored(snapshot) {
  try {
    const saved = JSON.parse(sessionStorage.getItem(`cairn-draft:${snapshot.space}:${snapshot.workspace}`) ?? "null");
    if (saved?.base?.workspace === snapshot.workspace && saved.base.space === snapshot.space) return saved;
  } catch { notice("A recovery draft could not be read. The signed workspace is unchanged."); }
  return null;
}
function renderLanes() {
  $("lanes").replaceChildren(...lanes.map(lane => {
    const d = drafts.get(lane.id);
    const b = button(`${lane.title}${d?.dirty || d?.pending ? " •" : ""}`, () => selectLane(lane.id), "lane");
    b.setAttribute("aria-current", String(lane.id === selected));
    b.append(el("small", `${lane.heads.length} head${lane.heads.length === 1 ? "" : "s"} · ${short(lane.author)}`));
    return b;
  }));
}
function renderFiles() {
  const d = current();
  const paths = Object.keys(d?.files ?? {}).sort();
  if (!paths.includes(file)) file = paths[0] ?? null;
  const filter = $("file-search").value.toLowerCase();
  $("files").replaceChildren(...paths.filter(p => p.toLowerCase().includes(filter)).map(path => {
    const changed = d.files[path] !== d.base.contents[path] || d.force.includes(path);
    const b = button(`${path}${changed ? " •" : ""}`, () => { file=path; renderFiles(); renderEditor(); }, "file");
    b.setAttribute("aria-current", String(path === file));
    return b;
  }));
  $("empty-files").hidden = paths.length > 0;
}
function renderEditor() {
  const d = current();
  const blocked = !d || !file || saving || !!d.pending;
  $("file-path").textContent = file ?? "No file selected";
  $("editor").disabled = blocked;
  $("executable").disabled = blocked;
  $("delete-file").disabled = blocked;
  $("editor").value = d?.files[file] ?? "";
  $("executable").checked = !!d?.modes[file];
  renderState();
}
function renderState() {
  const d = current();
  const dirty = !!d?.dirty, pending = !!d?.pending;
  const conflicts = d?.base.conflicts ?? [];
  $("save").disabled = !d || saving || (!dirty && !pending);
  $("save").textContent = saving ? "Saving…" : pending ? "Retry same save" : "Save changes";
  $("discard").disabled = !dirty || pending || saving;
  $("add-file").disabled = !d || pending || saving;
  $("fork").disabled = !d || dirty || pending || saving;
  $("integrate").disabled = !d || dirty || pending || saving;
  $("checkpoint").disabled = !d || dirty || pending || !!conflicts.length || saving;
  $("compact").disabled = !d || dirty || pending || !!conflicts.length || saving;
  $("run").disabled = !d || dirty || pending || !!conflicts.length || saving || !status?.environments.length || !!pendingJob;
  $("dirty-count").textContent = dirty || pending ? "•" : "";
  $("draft-state").textContent = pending ? "Request retained for retry" : dirty ? "Draft protected in this tab" : "All changes saved";
  $("save-description").textContent = pending ? "This save keeps its original request id." : dirty ? "Your idea, with its context intact." : d ? "You’re up to date with this read." : "A clear place to think.";
  $("save-hint").textContent = pending ? "Retry before editing further. Export preserves the draft and the request." : dirty ? "Saved drafts recover on reload. Export a copy before closing the tab." : "Every save retains its author and causal parents. Text merges still need tests.";
  $("incoming").hidden = !d?.incoming;
  $("revision").textContent = d ? `Revision ${short(d.base.revision)} · ${d.base.heads.length} causal head${d.base.heads.length===1?"":"s"}` : "No revision";
  $("conflicts").hidden = !conflicts.length;
  const list = el("ul");
  conflicts.forEach(c => list.append(el("li", c)));
  $("conflicts").replaceChildren(el("strong", "Resolve before pinning or running."), list,
    el("p", "Read all incoming work, choose the text or delete a conflicting path, then save your explicit resolution."));
  if (file && conflicts.some(c => c.startsWith(`${file}:`)) && !pending) {
    $("conflicts").append(button("Use current file as resolution", () => {
      if (d.incoming) throw Error("Discard or save your draft, then read incoming work before resolving.");
      if (!d.force.includes(file)) d.force.push(file);
      persist(d); renderState();
    }));
  }
  renderLanes();
}
async function selectLane(next) {
  // Switching lanes retains independent drafts rather than discarding or
  // silently rebasing them. Each lane keeps its own read and frozen request.
  const turn = ++navigation;
  const snapshot = await api("read", {workspace:next});
  if (turn !== navigation) return;
  if (!drafts.has(next)) drafts.set(next, new Draft(snapshot, stored(snapshot)));
  drafts.get(next).receive(snapshot);
  selected = next;
  file = null;
  $("title").textContent = lanes.find(l => l.id === next)?.title ?? "Workspace";
  $("subtitle").textContent = "Live source, independent task lanes and experiments you can replay.";
  renderFiles(); renderEditor();
  await refreshHistory(next);
}
async function refresh() {
  const listing = await api("list");
  lanes = listing.workspaces;
  if (listing.issues.length) notice(`Some signed changes were excluded: ${listing.issues.join("; ")}`);
  renderLanes();
  if (!selected && lanes.length) await selectLane(lanes[0].id);
  else if (selected) {
    const workspace = selected;
    const d = current();
    const next = lanes.find(l => l.id === workspace);
    if (next && JSON.stringify([...next.heads].sort()) !== JSON.stringify([...d.base.heads].sort())) {
      const snapshot = await api("read", {workspace});
      const revision = d.base.revision;
      d.receive(snapshot);
      if (selected === workspace) {
        if (d.base.revision !== revision) { renderFiles(); renderEditor(); }
        renderState();
      }
    }
    await refreshHistory(workspace);
  }
}
async function refreshHistory(workspace) {
  const history = feeds.get(workspace) ?? {cursor:[],changes:[],more:false};
  const page = await api("feed", {workspace, cursor:history.cursor, limit:128});
  const known = new Set(history.changes.map(c => c.id));
  history.changes.push(...page.changes.filter(c => !known.has(c.id)));
  history.cursor = page.cursor;
  history.more = page.more;
  feeds.set(workspace, history);
  if (selected !== workspace) return;
  $("activity").replaceChildren(...[...history.changes].reverse().slice(0,500).map(row => {
    const li = el("li");
    const c = row.change;
    li.append(el("strong", c.kind === "workspace" ? `Created ${c.title}` : c.kind === "integrate" ? "Integrated pinned work" : `Edited ${c.edits.map(e => e.path).join(", ")}`),
      el("p", `Author ${short(c.author)} · causal step ${row.clock} · ${c.parents.length} parent${c.parents.length===1?"":"s"}`), el("code", row.id));
    li.append(button("Read this revision", async () => {
      const snapshot = await api("read",{workspace:c.workspace ?? row.id, heads:[row.id]});
      await show("Historical read", [el("p", "Read only. Restoring a revision creates a new signed edit against your current read."), el("pre", JSON.stringify(snapshot.contents,null,2))], "Export snapshot", () => download("cairn-snapshot.json", snapshot));
    }, "quiet"));
    return li;
  }));
  $("more-activity").hidden = !history.more;
}
async function save() {
  const d = current();
  if (!d || saving) return;
  const retained=!!d.pending;
  const request = d.freeze(id());
  let acknowledged=false;
  persist(d);
  saving=true; renderEditor(); notice();
  try {
    await api("edit", request);
    acknowledged=true;
    // The write acknowledgement is enough to release a frozen request. If
    // the subsequent read fails, retain the draft without inventing a new id.
    const snapshot = await api("read",{workspace:d.base.workspace});
    d.saved(snapshot); persist(d); renderFiles();
    notice(snapshot.conflicts.length ? "Changes saved. Concurrent choices need an explicit resolution before running." : "Changes saved and signed.");
    await refresh();
  } catch (error) {
    if(!retained&&!acknowledged&&[400,409,415].includes(error.status)){d.pending=null;persist(d);}
    notice(error.message);
  }
  finally { saving=false; renderEditor(); }
}
function download(name, value) {
  const blob = new Blob([typeof value==="string"?value:JSON.stringify(value,null,2)], {type:"application/json"});
  const link = document.createElement("a");
  link.href=URL.createObjectURL(blob); link.download=name; link.click();
  setTimeout(()=>URL.revokeObjectURL(link.href),1000);
}
let dialogResolve = null;
function show(title, content, confirm, action) {
  const dialog = $("dialog");
  if (dialog.open) throw Error("Finish the open dialog first.");
  const opener = document.activeElement;
  const heading=el("h2",title);heading.id="dialog-title";
  $("dialog-content").replaceChildren(heading,...content);
  $("dialog-submit").textContent=confirm;
  $("dialog-error").textContent="";
  $("dialog-form").onsubmit=async event => {
    event.preventDefault(); $("dialog-submit").disabled=true;
    try { await action(); dialog.close("confirmed"); }
    catch(error) { $("dialog-error").textContent=error.message; }
    finally { $("dialog-submit").disabled=false; }
  };
  dialog.showModal();
  return new Promise(resolve => { dialogResolve=() => { opener?.focus(); resolve(); }; });
}
$("dialog").addEventListener("close",()=>{dialogResolve?.();dialogResolve=null;});
$("dialog-cancel").onclick=()=>$("dialog").close();
function field(label, value="") {
  const wrap=el("label",label), input=el("input");
  input.value=value; input.required=true; wrap.append(input);
  return [wrap,input];
}
$("create").onclick=()=>safely(async()=>{
  const [wrap,input]=field("Workspace name");
  const request=id();
  await show("A lane for your next idea",[el("p","Work independently, then integrate exact revisions when they’re ready."),wrap],"Create workspace",async()=>{
    const created=await api("create",{title:input.value,request});
    lanes=(await api("list")).workspaces; await selectLane(created.workspace);
  });
});
$("fork").onclick=()=>safely(async()=>{
  const d=current(), base=[...d.base.heads], request=id();
  const [wrap,input]=field("Lane name", `${lanes.find(l=>l.id===selected)?.title ?? "Workspace"} · experiment`);
  await show("Explore a different direction",[el("p",`Fork exactly revision ${short(d.base.revision)}. Later changes in the source stay separate.`),wrap],"Create fork",async()=>{
    const result=await api("create",{title:input.value,base,request});
    lanes=(await api("list")).workspaces; await selectLane(result.workspace);
  });
});
$("integrate").onclick=()=>safely(async()=>{
  const d=current(), target=d.base.workspace, heads=[...d.base.heads], request=id();
  const label=el("label","Source lane"), select=el("select");
  for(const lane of lanes.filter(l=>l.id!==target)) { const option=el("option",lane.title); option.value=lane.id;select.append(option); }
  label.append(select);
  const preview=el("pre");
  let pinned=null;
  const read=async()=>{ pinned=await api("read",{workspace:select.value}); preview.textContent=`Pinned revision ${pinned.revision}\n${pinned.files.map(f=>f.path).join("\n")}`; };
  select.onchange=()=>safely(read);
  if(!select.options.length) throw Error("Create a fork before integrating. Only lanes sharing history can be integrated.");
  await read();
  await show("Integrate a pinned contribution",[el("p","Authors and causal parents are retained. Review and test the result; integration is not a proof."),label,preview],"Integrate this read",async()=>{
    if(!pinned || pinned.workspace!==select.value) throw Error("Wait for the selected lane to load.");
    await api("integrate",{workspace:target,heads,source:pinned.heads,request});
    await refresh();
  });
});
$("add-file").onclick=()=>safely(async()=>{
  const d=current(),[wrap,input]=field("Relative file path","experiment.py");
  await show("Add a source file",[wrap],"Add file",async()=>{
    const path=input.value;
    if(!validPath(path)) throw Error("Use a relative source path without traversal, reserved names or control characters.");
    if(path in d.files) throw Error("That file already exists.");
    d.files[path]="";d.modes[path]=false;file=path;persist(d);renderFiles();renderEditor();
  });
  $("editor").focus();
});
$("delete-file").onclick=()=>safely(async()=>{
  const d=current(), path=file;
  await show("Delete this file?",[el("p",`${path} will be removed when you save. Signed history stays available.`)],"Mark for deletion",async()=>{
    delete d.files[path];delete d.modes[path];persist(d);renderFiles();renderEditor();
  });
});
$("editor").addEventListener("input",()=>{
  const d=current(); if(!d || !file || d.pending)return;
  d.files[file]=sourceText(d.files[file],$("editor").value);persist(d);renderState();
});
$("executable").onchange=()=>{const d=current();d.modes[file]=$("executable").checked;persist(d);renderState();};
$("file-search").oninput=renderFiles;
$("save").onclick=()=>safely(save);
$("export").onclick=()=>{if(current())download("cairn-draft.json",current().serialize());};
$("import").onclick=()=>$("import-file").click();
$("import-file").onchange=()=>safely(async()=>{
  const picked=$("import-file").files[0];$("import-file").value="";
  if(!picked)return;
  if(picked.size>8*1024*1024)throw Error("Draft export exceeds the 8 MiB recovery limit.");
  const saved=JSON.parse(await picked.text());
  if(saved.base?.space!==status?.space || !lanes.some(l=>l.id===saved.base?.workspace))throw Error("This draft belongs to another lab. Open that lab's workbench to recover it.");
  if(!saved.files || Object.entries(saved.files).some(([p,text])=>!validPath(p)||typeof text!=="string"||new TextEncoder().encode(text).length>1048576))throw Error("Invalid source files in recovery draft.");
  const snapshot=await api("read",{workspace:saved.base.workspace,heads:saved.base.heads});
  if(snapshot.revision!==saved.base.revision)throw Error("The exported base does not match the signed historical read.");
  saved.base=snapshot;
  const candidate=new Draft(snapshot,saved);
  if(candidate.pending){
    const actual=candidate.pending;candidate.pending=null;
    const expected=candidate.freeze(actual.request);
    const stable=value=>JSON.stringify(value,(_,v)=>v&&typeof v==="object"&&!Array.isArray(v)?Object.fromEntries(Object.entries(v).sort(([a],[b])=>a.localeCompare(b))):v);
    if(stable(actual)!==stable(expected))throw Error("The retained request differs from the displayed recovery draft. Review the export before importing it.");
  }
  await show("Recover this draft?",[el("p","Import retains its original read and retry id. Any draft already open in this lane will be replaced; export it first."),el("pre",Object.keys(candidate.files).join("\n"))],"Recover draft",async()=>{
    drafts.set(snapshot.workspace,candidate);persist(candidate);await selectLane(snapshot.workspace);
  });
});
$("compact").onclick=()=>safely(async()=>{
  const d=current(), snapshot=d.base;
  await show("Keep history. Start a fresh generation.",[
    el("p","An administrator can roll this exact read into a new lab. The old signed history is retained as a verifiable archive. Offline agents stay in the old space until deliberately moved. Other old lanes and execution receipts remain available through archive recovery."),
    el("p","Export this read as base.json, then choose a new directory and run:"),
    el("pre",`cairn lab --lab ${shell(status.directory)} collab compact ${snapshot.workspace} NEW_LAB --base base.json --identity YOUR_KEY\n\ncairn lab --lab NEW_LAB collab recover RECOVERED_OLD_LAB`),
    el("p","Keep the source lab until late offline work has been received and reviewed. This does not reclaim its disk space or silently merge old-space work into the new generation.")
  ],"Export pinned base",()=>download("base.json",snapshot));
});
$("discard").onclick=()=>safely(async()=>{
  const d=current();
  await show("Discard this lane’s draft?",[el("p","This removes unsaved edits in this tab. Export a recovery copy first if you need them.")],"Discard draft",async()=>{
    d.adopt(await api("read",{workspace:d.base.workspace}));persist(d);renderFiles();renderEditor();
  });
});
$("inspect-incoming").onclick=()=>safely(async()=>{
  const d=current();
  await show("Incoming work · your draft is retained",[el("p",`Incoming revision ${short(d.incoming.revision)}. The left draft is never overwritten automatically.`),el("pre",JSON.stringify({draft:d.files,incoming:d.incoming.contents},null,2))],"Keep editing",async()=>{});
});
$("checkpoint").onclick=()=>safely(async()=>{
  const d=current(), heads=[...d.base.heads];
  const result=await api("checkpoint",{workspace:d.base.workspace,heads});
  await show("Inputs pinned for replay",[el("p",`Revision ${result.revision}. Mount only the exact files listed in the exported checkpoint; no mutable directories.`),el("pre",JSON.stringify(result.inputs,null,2))],"Export checkpoint",()=>download("cairn-checkpoint.json",result));
});
$("more-activity").onclick=()=>safely(()=>refreshHistory(selected));
document.querySelectorAll("[data-tab]").forEach(tab=>{
  const activate=()=>{
    notice();
    document.querySelectorAll("[data-tab]").forEach(t=>{const on=t===tab;t.setAttribute("aria-selected",String(on));t.tabIndex=on?0:-1;$(`${t.dataset.tab}-panel`).hidden=!on;});
  };
  tab.onclick=activate;
  tab.onkeydown=event=>{
    const tabs=[...document.querySelectorAll("[data-tab]")], i=tabs.indexOf(tab);
    const next=event.key==="ArrowRight"?tabs[(i+1)%tabs.length]:event.key==="ArrowLeft"?tabs[(i+tabs.length-1)%tabs.length]:event.key==="Home"?tabs[0]:event.key==="End"?tabs.at(-1):null;
    if(next){event.preventDefault();next.click();next.focus();}
  };
});
window.addEventListener("beforeunload",event=>{if([...drafts.values()].some(d=>d.dirty||d.pending)){event.preventDefault();event.returnValue="";}});
window.addEventListener("keydown",event=>{if((event.ctrlKey||event.metaKey)&&event.key==="s"){event.preventDefault();if(!$("save").disabled)void safely(save);}});

function renderStatus(value) {
  status=value;$("lab-name").textContent=value.name;$("author").textContent=`Identity ${short(value.author)}`;
  if(!jobsRestored){
    jobsRestored=true;
    try{pendingJob=JSON.parse(sessionStorage.getItem(`cairn-job:${value.space}`)??"null");}catch{}
    if(pendingJob){currentJob=pendingJob.session===value.session?pendingJob.job:null;renderPendingJob();}
  }
  const chosen=$("run-env").value;
  $("run-env").replaceChildren(...value.environment_profiles.map(env=>{const option=el("option",`${env.name} · ${short(env.tree)}`);option.value=env.tree;return option;}));
  if(value.environment_profiles.some(env=>env.tree===chosen))$("run-env").value=chosen;
  $("env-help").textContent=value.environments.length?"The local runner requires gVisor or bubblewrap. Runtime failure is unavailable, never a program verdict.":"Import an execution environment with cairn lab env import, then refresh this page. Host processes cannot run through this editor.";
  const cpu=value.hardware.cpu ?? {}, hw=value.hardware, offer=value.resources;
  const dl=el("dl");
  const row=(name,text)=>dl.append(el("dt",name),el("dd",text));
  row("Processor",cpu.model ?? "Model unavailable");row("Architecture",`${cpu.arch ?? "Unknown"} · ${cpu.vendor ?? "vendor unreported"}`);
  row("Capacity",`${hw.cpus ?? "?"} logical CPUs · ${hw.memory_mb ?? "?"} MiB RAM`);
  row("CPU quota",`${offer?.cpu_millis ?? hw.cpu_millis ?? "Unknown"} CPU milliseconds per second`);
  row("Clock",`Base ${cpu.base_khz?`${cpu.base_khz/1000} MHz`:"unknown"} · Max ${cpu.max_khz?`${cpu.max_khz/1000} MHz`:"unknown"}`);
  row("Usable ISA",cpu.features?.join(", ")||"None detected");
  row("Sample",`${cpu.observed_at ?? "Unknown"} · ${cpu.source ?? "no source"}`);
  row("Rate card",offer?.pricing?`${offer.pricing.unit} · ${offer.pricing.rates.length} workload rate(s)`:"Not configured. Set CAIRN_AGENT_RATE_CARD to an operator-reviewed JSON card before launching.");
  $("machine").replaceChildren(el("h3","This machine"),dl,el("p","Clock readings vary with power and load. ISA flags describe usable instructions, not measured workload speed or attested hardware."));
  $("runs").replaceChildren(...value.runs.map(run=>{
    const card=el("details",null,"run-card"), receipt=run.receipt;
    const state=receipt.error?"Runtime unavailable":`Exit ${receipt.exit_status ?? "unknown"}`;
    card.append(el("summary",`${state} · ${short(run.id)} · ${(receipt.argv ?? []).join(" ")}`),el("p",`Author ${short(run.author)}. A receipt is not a prescribed-execution proof.`),el("pre",JSON.stringify(receipt,null,2)),button("Export receipt",()=>download(`cairn-run-${short(run.id)}.json`,run)));
    card.append(button("Replay pinned inputs",async()=>{
      if(pendingJob)throw Error("Inspect the active or retained experiment first.");
      const args={run:run.id,request:id()};
      await show("Replay the recorded experiment?",[el("p","The original command, environment and exact recorded input bytes are replayed. The local GUI still requires a working sandbox and bounded resources. Current workspace edits are not included."),el("pre",JSON.stringify(receipt.argv,null,2))],"Replay pinned inputs",()=>submitJob("replay",args));
    }));
    card.append(button("Use recipe on current source",()=>{
      if(!current())throw Error("Select a workspace first.");
      if(receipt.network)throw Error("This recipe used network access. Review its arguments before preparing a local experiment.");
      if(!value.environment_profiles.some(env=>env.tree===receipt.env?.tree))throw Error("Import the exact recorded environment tree before using this recipe.");
      $("run-env").value=receipt.env.tree;$("program").value=receipt.argv?.[0]??"";
      $("arguments").value=(receipt.argv??[]).slice(1).join("\n");
      $("run-time").value=String(Math.min(receipt.limits?.timeout_s||60,600));
      $("run-cpus").value=String(Math.min(receipt.limits?.cpus||1,64));
      $("run-memory").value=String(Math.min(receipt.limits?.memory_mb||1024,262144));
      recipeOf=run.id;
      notice(`Recipe prepared from ${short(run.id)}. Review it, then run against the selected workspace's saved source.`);
      $("program").focus();
    }));
    return card;
  }));
  if(!value.runs.length)$("runs").append(el("p","No experiments recorded yet. Your first run will appear here.","hint"));
  renderState();
}
let quoteSequence=0;
$("quote-form").addEventListener("input",()=>{quoteSequence++;$("quote").replaceChildren(el("p","Allocation changed. Calculate a fresh estimate.","hint"));});
$("quote-form").onsubmit=event=>{event.preventDefault();void (async()=>{
  const turn=++quoteSequence;
  $("quote").replaceChildren(el("p","Calculating this allocation…"));
  try {
  const args={workload:$("workload").value,cpus:Number($("quote-cpus").value),memory_mb:Number($("quote-memory").value),duration_ms:Number($("quote-time").value)*1000,
    cpu:{features:$("isa").value.split(/[\s,]+/).filter(Boolean).map(f=>f.toLowerCase())}};
  if(![args.cpus,args.memory_mb,args.duration_ms].every(Number.isSafeInteger))throw Error("Use whole allocation values within the browser's exact integer range.");
  const quote=await api("quote",args);
  if(turn!==quoteSequence)return;
  $("quote").replaceChildren(el("strong",`${formatMicrounits(quote.amount_microunits_exact)} ${quote.unit}`),el("p",`Rate ${quote.rate_id} · card ${short(quote.rate_card_id)} · CPU profile ${short(quote.cpu_profile_id)}`),el("p",quote.note),button("Export estimate",()=>download("cairn-compute-estimate.json",quote.canonical_quote)));
  } catch(error) {if(turn===quoteSequence)$("quote").replaceChildren(el("p",error.message,"warning"));}
})();};
$("run-form").onsubmit=event=>{event.preventDefault();void safely(async()=>{
  const d=current(); if($("run").disabled)return;
  const args={workspace:d.base.workspace,heads:[...d.base.heads],env:$("run-env").value,
    argv:[$("program").value,...$("arguments").value.split("\n").filter(s=>s.length)], request:id(),
    timeout_seconds:Number($("run-time").value),cpus:Number($("run-cpus").value),memory_mb:Number($("run-memory").value),
    cpu:{features:$("run-isa").value.split(/[\s,]+/).filter(Boolean).map(f=>f.toLowerCase())}};
  if($("run-workload").value)args.workload=$("run-workload").value;
  if(recipeOf)args.recipe_of=recipeOf;
  let estimate=null;
  if(args.workload)estimate=await api("quote",{workload:args.workload,cpus:args.cpus,memory_mb:args.memory_mb,duration_ms:args.timeout_seconds*1000,cpu:args.cpu});
  const content=[el("p",`Revision ${short(d.base.revision)} · environment ${args.env}. The process is isolated, has no network, and can write only its output and temporary directories.`),el("pre",JSON.stringify(args.argv,null,2))];
  if(estimate)content.push(el("p",`Estimated allocation: ${formatMicrounits(estimate.amount_microunits_exact)} ${estimate.unit} at rate ${estimate.rate_id}. Advisory; no charge or reservation.`));
  await show("Run these exact inputs?",content,"Pin inputs & run",async()=>{
    // Freeze the request through a lost acknowledgement; never auto-start a
    // second experiment after a connection error.
    await submitJob("run",args);
  });
});};
async function pollJob() {
  if(!currentJob)return;
  const result=await api("job",{id:currentJob});
  if(result.state==="running")return;
  currentJob=null;pendingJob=null;persistJob();$("job").replaceChildren(el("strong",result.state==="unavailable"?"Runtime unavailable":`Experiment recorded · ${short(result.run)}`),el("pre",result.error??`${result.stdout}\n${result.stderr}`));
  renderStatus(await api("status"));
}
function persistJob(){
  try{const key=`cairn-job:${status.space}`;if(pendingJob)sessionStorage.setItem(key,JSON.stringify(pendingJob));else sessionStorage.removeItem(key);}
  catch{notice("Experiment recovery storage is unavailable. Inspect recorded receipts before starting another after reload.");}
}
function renderPendingJob(){
  $("job").hidden=false;
  if(currentJob){$("job").replaceChildren(el("strong","Experiment running with pinned inputs…"));return;}
  const same=pendingJob.session===status.session;
  $("job").replaceChildren(el("strong",same?"Experiment request retained":"The workbench process restarted"),el("p",same?"The acknowledgement was interrupted. Retry the exact request; no second request id is generated.":"Inspect recorded receipts before starting another experiment. The old process may have completed the program."));
  if(same)$("job").append(button("Retry same experiment request",()=>submitJob(pendingJob.command,pendingJob.args)));
  else $("job").append(button("Clear after inspecting receipts",async()=>{
    await show("Clear the unresolved experiment?",[el("p","First check the recorded receipts and any retained runner work. Clearing this notice cannot prove that the old process did not run."),el("pre",JSON.stringify(pendingJob.args,null,2))],"I inspected the receipts",async()=>{pendingJob=null;currentJob=null;persistJob();$("job").hidden=true;renderState();});
  }));
}
async function submitJob(command,args){
  if(pendingJob && (pendingJob.command!==command || JSON.stringify(pendingJob.args)!==JSON.stringify(args)))throw Error("Resolve the retained experiment request first.");
  const retained=!!pendingJob;
  pendingJob={session:status.session,command,args,job:null};persistJob();renderState();
  try{const result=await api(command,args);currentJob=result.job;pendingJob.job=currentJob;persistJob();renderPendingJob();}
  catch(error){if(error.confirmed&&!retained){pendingJob=null;persistJob();renderState();}else renderPendingJob();throw error;}
}
async function boot() {
  try { renderStatus(await api("status")); await refresh(); }
  catch(error){notice(error.message);}
  let tick=0;
  const poll=async()=>{
    if(document.hidden){setTimeout(poll,1500);return;}
    try { await refresh();await pollJob();if(++tick%10===0)renderStatus(await api("status")); }
    catch(error){if(connected)notice(error.message);}
    setTimeout(poll,1500);
  };
  setTimeout(poll,1500);
}
void boot();
