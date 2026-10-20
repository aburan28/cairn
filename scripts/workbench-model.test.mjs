import test from "node:test";
import assert from "node:assert/strict";
import { Draft, formatMicrounits, validPath, sourceText } from "../src/serve/workbench/model.mjs";

const snapshot = (revision="one", text="a🦀éz", heads=["h1"]) => ({space:"s",workspace:"w",revision,heads,
  files:[{path:"experiment.py",executable:false}],contents:{"experiment.py":text},conflicts:[]});

test("incoming work never changes the positions or base of a dirty Unicode draft",()=>{
  const d=new Draft(snapshot());d.files["experiment.py"]="aλz";
  d.receive(snapshot("two","a🦀éz remote",["h2"]));
  assert.equal(d.base.revision,"one");assert.equal(d.files["experiment.py"],"aλz");
  assert.equal(d.incoming.revision,"two");
  assert.deepEqual(d.freeze("retry").edits,[{path:"experiment.py",start:0,delete:4,insert:"aλz",executable:false}]);
  assert.deepEqual(d.pending.heads,["h1"]);
});
test("retry and reload preserve an identical request instead of inventing another edit",()=>{
  const d=new Draft(snapshot());d.files["experiment.py"]="changed";
  const pending=structuredClone(d.freeze("one-request"));
  const recovered=new Draft(snapshot("remote","other",["new"]),JSON.parse(JSON.stringify(d.serialize())));
  assert.deepEqual(recovered.freeze("do-not-use"),pending);
  recovered.receive(snapshot("remote","other",["new"]));
  assert.equal(recovered.base.revision,"one");assert.equal(recovered.incoming.revision,"remote");
  recovered.saved(snapshot("ack","changed",["ack"]));
  assert.equal(recovered.dirty,false);assert.equal(recovered.pending,null);
});
test("clean reads advance; mode changes, empty new files and removals are actual edits",()=>{
  const d=new Draft(snapshot());d.receive(snapshot("new","updated",["new"]));
  assert.equal(d.base.revision,"new");assert.equal(d.dirty,false);
  d.modes["experiment.py"]=true;
  assert.equal(d.freeze("mode").edits[0].executable,true);
  d.adopt(snapshot());delete d.files["experiment.py"];
  assert.deepEqual(d.freeze("remove").edits,[{path:"experiment.py",start:0,delete:0,insert:"",remove:true}]);
  d.adopt(snapshot());d.files["empty.txt"]="";d.modes["empty.txt"]=false;
  assert.equal(d.freeze("empty").edits[0].path,"empty.txt");
});
test("explicit conflict resolution can sign the chosen text even if no character changes",()=>{
  const d=new Draft(snapshot());d.force.push("experiment.py");
  assert.equal(d.dirty,true);assert.equal(d.freeze("resolve").edits.length,1);
});
test("amounts above Number precision display exactly and path checks reject traversal",()=>{
  assert.equal(formatMicrounits("18446744073709551615"),"18446744073709.551615");
  for(const path of ["../x","/x","a//b",".git/config","CON.py","x\\y","x:y","x\u0000y","trailing.","a/../b"])
    assert.equal(validPath(path),false,path);
  for(const path of ["src/algorithm.rs",".gitignore","λ/experiment.py"])assert.equal(validPath(path),true,path);
});
test("source paths that are JavaScript prototype names stay ordinary source data",()=>{
  const d=new Draft(snapshot());
  d.files["__proto__"]="source";d.modes["__proto__"]=false;
  d.files["constructor"]="other source";d.modes["constructor"]=false;
  assert.equal(Object.getPrototypeOf(d.files),null);
  assert.deepEqual(d.freeze("prototype-names").edits.map(e=>[e.path,e.delete,e.insert]),[
    ["__proto__",0,"source"],["constructor",0,"other source"]]);
});
test("editing a textarea preserves untouched CRLF, CR, mixed endings and Unicode",()=>{
  assert.equal(sourceText("a🦀\r\nbé\r\n","aλ\nbé\n"),"aλ\r\nbé\r\n");
  assert.equal(sourceText("one\rtwo\nthree\r\n","one\rtwo\nthree!\n".replaceAll("\r","\n")),"one\rtwo\nthree!\r\n");
  assert.equal(sourceText("one\r\ntwo\r\n","one\nnew\ntwo\n"),"one\r\nnew\r\ntwo\r\n");
});
test("oversized saves fail before freezing a request so the draft remains editable",()=>{
  const d=new Draft(snapshot());d.files["experiment.py"]="x".repeat(1048576);
  assert.throws(()=>d.freeze("large"),/HTTP limit/);assert.equal(d.pending,null);
});
