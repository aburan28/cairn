// Real local editor acceptance. The fixture runner owns this disposable lab;
// no public node, third-party account or external service receives a write.
import assert from "node:assert/strict";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { chromium } from "playwright";

const url=new URL(process.env.CAIRN_WORKBENCH_URL);
assert(["127.0.0.1","[::1]"].includes(url.hostname));
const token=new URLSearchParams(url.hash.slice(1)).get("token");
const lab=process.env.CAIRN_WORKBENCH_LAB, key=process.env.CAIRN_WORKBENCH_KEY;
assert(lab&&key&&token,"Use scripts/workbench-demo.py with CAIRN_WORKBENCH_BROWSER=1");
const browser=await chromium.launch({executablePath:process.env.CAIRN_BROWSER_PATH||undefined,
  args:process.env.CAIRN_UX_NO_SANDBOX==="1"?["--no-sandbox"]:[]});
const context=await browser.newContext();
const page=await context.newPage();page.setDefaultTimeout(12000);
const errors=[];page.on("pageerror",e=>errors.push(e.message));
const api=async(command,args={})=>{
  const response=await page.request.post(`${url.origin}/api`,{data:{command,args},headers:{Authorization:`Bearer ${token}`,Origin:url.origin}});
  assert.equal(response.status(),200,await response.text());return response.json();
};
const click=async(name)=>page.getByRole("button",{name,exact:true}).click();
const modal=()=>page.getByRole("dialog");
try {
  await page.goto(url.href);
  await page.getByText("● Connected locally",{exact:true}).waitFor();
  assert.equal(new URL(page.url()).hash,"");
  for(const width of [320,360,1280]) {
    await page.setViewportSize({width,height:900});
    for(const name of ["Source","Activity","Experiments","Compute & pricing"]) {
      await page.getByRole("tab",{name,exact:true}).click();
      assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${name} overflows at ${width}`);
    }
  }
  await page.getByRole("tab",{name:"Source",exact:true}).click();
  await page.getByRole("button",{name:"Create workspace",exact:true}).click();
  await modal().getByLabel("Workspace name").fill("Boundary experiment");
  await modal().getByRole("button",{name:"Create workspace",exact:true}).click();
  await modal().waitFor({state:"hidden"});
  await page.getByRole("heading",{name:"Boundary experiment",exact:true}).waitFor();
  await page.getByRole("button",{name:"Add file",exact:true}).click();
  await modal().getByLabel("Relative file path").fill("algorithm.py");
  await modal().getByRole("button",{name:"Add file",exact:true}).click();
  const editor=page.getByRole("textbox",{name:"Source editor",exact:true});
  await editor.fill("a🦀éz\n");
  await page.reload();
  // Select the recovered lane; the other fixture lane was created first.
  await page.getByRole("button",{name:/Boundary experiment/}).click();
  await page.waitForFunction(()=>document.getElementById("editor").value==="a🦀éz\n");
  assert.equal(await editor.inputValue(),"a🦀éz\n");
  await click("Save changes");
  await page.getByText("All changes saved",{exact:true}).waitFor();
  const workspace=(await api("list")).workspaces.find(w=>w.title==="Boundary experiment").id;
  const base=await api("read",{workspace});
  await editor.fill("aλz\n");
  // Another process writes against its original read while the browser is dirty.
  const basePath=join(lab,"browser-test-base.json"), editsPath=join(lab,"browser-test-edits.json");
  await writeFile(basePath,JSON.stringify(base));
  await writeFile(editsPath,JSON.stringify([{path:"algorithm.py",start:5,delete:0,insert:"# remote\n"}]));
  execFileSync(process.env.RUST_BIN,["lab","--lab",lab,"collab","edit",workspace,"--base",basePath,"--edits",editsPath,"--request","browser-remote","--identity",key]);
  await page.getByText("New work arrived.",{exact:true}).waitFor();
  assert.equal(await editor.inputValue(),"aλz\n");
  await click("Save changes");
  await page.getByText("All changes saved",{exact:true}).waitFor();
  assert.equal(await editor.inputValue(),"aλz\n# remote\n");

  // Lose the response after the server accepted the edit; retry the EXACT
  // envelope and require just one signed change. No weakened server fixture.
  let lost=false, frozen=null;
  await page.route("**/api",async route=>{
    const body=route.request().postDataJSON();
    if(body.command==="edit"&&!lost){lost=true;frozen=body;await route.fetch();await route.abort("failed");}
    else await route.continue();
  });
  await editor.fill("aλz\n# remote\n# retained\n");await click("Save changes");
  await page.getByRole("button",{name:"Retry same save",exact:true}).waitFor();
  const countBefore=(await api("feed",{workspace})).changes.length;
  await click("Retry same save");
  await page.getByText("All changes saved",{exact:true}).waitFor();
  assert.equal((await api("feed",{workspace})).changes.length,countBefore);
  assert(frozen.args.request);
  await page.unroute("**/api");

  // Two observed-overlap replacements remain visible until the user signs a
  // resolution against BOTH heads, even when the chosen text stays unchanged.
  const overlap=await api("read",{workspace});
  for(const [request,insert] of [["overlap-a","X"],["overlap-b","Y"]])
    await api("edit",{workspace,heads:overlap.heads,request,edits:[{path:"algorithm.py",start:0,delete:1,insert}]});
  await page.getByText("Resolve before pinning or running.",{exact:true}).waitFor();
  assert(await page.getByRole("button",{name:"Pin checkpoint",exact:true}).isDisabled());
  await click("Use current file as resolution");await click("Save changes");
  await page.getByText("All changes saved",{exact:true}).waitFor();
  assert.deepEqual((await api("read",{workspace})).conflicts,[]);
  await editor.fill(`${await editor.inputValue()}# recovery export\n`);
  const downloading=page.waitForEvent("download");await click("Export draft");
  const exported=await downloading;
  const recovery=await readFile(await exported.path());
  await click("Discard draft");await modal().getByRole("button",{name:"Discard draft",exact:true}).click();
  await modal().waitFor({state:"hidden"});
  assert(!(await editor.inputValue()).includes("# recovery export"));
  await page.locator("#import-file").setInputFiles({name:"cairn-draft.json",mimeType:"application/json",buffer:recovery});
  await modal().getByRole("button",{name:"Recover draft",exact:true}).click();await modal().waitFor({state:"hidden"});
  assert((await editor.inputValue()).includes("# recovery export"));
  await click("Save changes");await page.getByText("All changes saved",{exact:true}).waitFor();

  await click("Fork lane");await modal().getByLabel("Lane name").fill("Independent lane");
  await modal().getByRole("button",{name:"Create fork",exact:true}).click();await modal().waitFor({state:"hidden"});
  await editor.fill(`${await editor.inputValue()}# integrated contribution\n`);
  await click("Save changes");await page.getByText("All changes saved",{exact:true}).waitFor();
  const fork=(await api("list")).workspaces.find(w=>w.title==="Independent lane").id;
  const forkRead=await api("read",{workspace:fork});
  await page.getByRole("button",{name:/^Boundary experiment/}).click();
  await page.getByRole("heading",{name:"Boundary experiment",exact:true}).waitFor();
  assert(!(await editor.inputValue()).includes("# integrated contribution"));
  await click("Integrate…");await modal().getByLabel("Source lane").selectOption(fork);
  await page.waitForFunction(revision=>document.querySelector("#dialog pre")?.textContent.includes(revision),forkRead.revision);
  await api("edit",{workspace:fork,heads:forkRead.heads,request:"fork-after-preview",edits:[{
    path:"algorithm.py",start:[...forkRead.contents["algorithm.py"]].length,delete:0,insert:"# arrived after preview\n"}]});
  await modal().getByRole("button",{name:"Integrate this read",exact:true}).click();await modal().waitFor({state:"hidden"});
  assert((await editor.inputValue()).includes("# integrated contribution"));
  assert(!(await editor.inputValue()).includes("# arrived after preview"),"Integration must retain the reviewed source heads");
  await click("Pin checkpoint");await modal().getByRole("heading",{name:"Inputs pinned for replay"}).waitFor();
  await page.keyboard.press("Escape");
  assert(await page.getByRole("button",{name:"Pin checkpoint",exact:true}).evaluate(b=>b===document.activeElement));

  await page.getByRole("tab",{name:"Compute & pricing",exact:true}).click();
  await page.getByLabel("Workload",{exact:true}).fill("boomer-v1");
  await page.getByRole("button",{name:"Calculate estimate",exact:true}).click();
  await page.locator("#quote strong").waitFor();
  assert((await page.locator("#quote strong").textContent()).includes("USD"));
  await page.locator("#quote-form").getByLabel("Required ISA flags",{exact:true}).fill("madeupinstruction");
  await page.getByRole("button",{name:"Calculate estimate",exact:true}).click();
  await page.locator("#quote").filter({hasText:"usable CPU features"}).waitFor();
  assert.equal(await page.locator("#quote strong").count(),0,"A failed allocation must not retain a stale estimate");
  await page.locator("#quote-form").getByLabel("Required ISA flags",{exact:true}).fill("");
  await page.getByLabel("Workload",{exact:true}).fill("precision-v1");
  await page.locator("#quote-memory").fill("0");await page.locator("#quote-time").fill("1");
  await page.getByRole("button",{name:"Calculate estimate",exact:true}).click();
  await page.getByText("18446744073709.551615 USD",{exact:true}).waitFor();
  const quoteDownload=page.waitForEvent("download");await click("Export estimate");
  assert((await readFile(await (await quoteDownload).path(),"utf8")).includes('"amount_microunits":18446744073709551615'));
  await page.getByRole("tab",{name:"Source",exact:true}).click();
  const shot=process.env.CAIRN_UX_SCREENSHOTS;
  if(shot){await mkdir(shot,{recursive:true});for(const width of [360,1280]){await page.setViewportSize({width,height:900});await page.screenshot({path:join(shot,`workbench-${width}.png`),fullPage:true});}}
  assert.deepEqual(errors,[]);
  console.log("PASS browser layouts at 320/360/1280, draft reload/export/import, concurrent edit protection, lost-response retry, conflicts, isolated forks, pinned integration, checkpoints, focus restoration, ISA rejection and exact u64 estimates");
} finally {await browser.close();}
