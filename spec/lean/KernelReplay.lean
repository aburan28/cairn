import Lean
open Lean

-- `Environment.replay` is deprecated in favour of `Kernel.Environment.replay`
-- on recent toolchains, and is the only spelling older ones have. This file
-- has to run on whatever Lean a node operator installed.
set_option linter.deprecated false

/-!
# Kernel replay of a compiled Lean claim

Run by both implementations' `lean` verifiers, after the claim compiles, as

    lean --run KernelReplay.lean CLAIM.olean STATEMENT.olean THEOREM MARKER

`CLAIM.olean` is the objective's preamble, statement and the submitted proof,
compiled. `STATEMENT.olean` is the preamble and statement compiled with the
proof replaced by `sorry`: text no submitter wrote. `THEOREM` is the name the
statement declares, or `-` when it declares none (an `example`).

Compiling the claim runs the submitter's code: Lean elaboration executes
macros, tactics and elaborators. A metaprogram can therefore put a
declaration into the environment *without* the kernel checking it
(`Environment.addDeclCore … (doCheck := false)` is public), prove the
objective from it, and leave a clean exit and an empty `#print axioms`
behind. Nothing the claim's own compile reports can rule that out.

This process never runs the submitter's code. It reads the claim's module as
data, imports only what that module imported, and sends every declaration the
module added back through the kernel. Then it holds the claim to the
statement's own compile:

* every declaration the statement made -- the preamble's definitions and
  axioms -- is in the claim unchanged, values included;
* the theorem is a theorem, with exactly the statement's type;
* the claim adds no axiom of its own.

and reports, from the replayed declarations, the axioms the theorem rests on.

Every line the verifier reads starts with `MARKER`, which is random per run.
Exactly one of `ok`, `fail …` or `unavailable …` ends the report: `fail` is a
fact about the claim, `unavailable` is a fact about this node (the kernel ran
out of time, stack or memory), and no terminal line at all means this file did
not run here, which is also a fact about the node.

This file is part of the protocol's definition of an accepted Lean proof, and
both implementations embed it unchanged. Edit it in one place, here.
-/

/-- The constants a module added, by name. -/
def constantsOf (mod : ModuleData) : Std.HashMap Name ConstantInfo := Id.run do
  let mut out : Std.HashMap Name ConstantInfo := {}
  for name in mod.constNames, info in mod.constants do
    out := out.insert name info
  return out

def kindOf : ConstantInfo → String
  | .axiomInfo _ => "axiom"
  | .defnInfo _ => "def"
  | .thmInfo _ => "theorem"
  | .opaqueInfo _ => "opaque"
  | .quotInfo _ => "quot"
  | .inductInfo _ => "inductive"
  | .ctorInfo _ => "constructor"
  | .recInfo _ => "recursor"

/-- Is `claimed` the same declaration as `pinned`, value included? -/
def sameDeclaration (pinned claimed : ConstantInfo) : Bool :=
  kindOf pinned == kindOf claimed
    && pinned.levelParams == claimed.levelParams
    && pinned.type == claimed.type
    && pinned.value? (allowOpaque := true) == claimed.value? (allowOpaque := true)

/-- Every axiom `root` depends on, transitively. `added` -- what the replay
checked -- is consulted first, then the imports. Not looked up in the
environment `replay` returns, whose `find?` does not see replayed constants on
every Lean. -/
partial def axiomsOf (env : Environment) (added : Std.HashMap Name ConstantInfo)
    (root : Name) : Array Name := Id.run do
  let mut seen : NameSet := {}
  let mut stack : Array Name := #[root]
  let mut found : Array Name := #[]
  while !stack.isEmpty do
    let name := stack.back!
    stack := stack.pop
    if seen.contains name then continue
    seen := seen.insert name
    match added.get? name <|> env.find? name with
    | some (.axiomInfo _) => found := found.push name
    | some info =>
      for used in info.type.getUsedConstants do
        stack := stack.push used
      if let some value := info.value? (allowOpaque := true) then
        for used in value.getUsedConstants do
          stack := stack.push used
      match info with
      | .inductInfo val =>
        for ctor in val.ctors do stack := stack.push ctor
      | .ctorInfo val => stack := stack.push val.induct
      | .recInfo val =>
        for rule in val.rules do
          for used in rule.rhs.getUsedConstants do stack := stack.push used
      | _ => pure ()
    | none => pure ()
  return found

/-- A kernel refusal that is about this node's resources, not the claim. -/
def exhausted (message : String) : Bool :=
  ["deterministic timeout", "deep recursion", "excessive memory", "interrupted",
   "reduceBool"].any fun phrase => (message.splitOn phrase).length > 1

/-- The first line of a message, bounded: a refusal can pretty-print a whole
term, and the verifier keeps the line, not the term. -/
def firstLine (message : String) : String :=
  let line := (message.splitOn "\n").headD ""
  if line.length > 200 then (line.take 200).toString ++ "…" else line

def main (args : List String) : IO UInt32 := do
  let [claimPath, statementPath, theoremArg, marker] := args
    | IO.eprintln "usage: KernelReplay CLAIM.olean STATEMENT.olean THEOREM MARKER"
      return 2
  let say (line : String) : IO Unit := IO.println s!"{marker} {line}"
  -- Not `findSysroot`: it runs `lean --print-prefix` through `PATH`, and the
  -- verifier's jail scrubs `PATH`. The toolchain is the one running this
  -- file, so its prefix is the directory above this executable.
  let sysroot ← match ← IO.getEnv "LEAN_SYSROOT" with
    | some root => pure (System.FilePath.mk root)
    | none => pure ((← IO.appDir).parent.getD ".")
  initSearchPath sysroot
  let (claim, _) ← readModuleData claimPath
  let (statement, _) ← readModuleData statementPath
  if claim.imports != statement.imports then
    say "fail the claim imports differently from the statement"
    return 1
  let env ← importModules claim.imports {}
  let added := constantsOf claim
  let pinned := constantsOf statement
  try
    discard <| env.replay added
  catch error =>
    let message := toString error
    if exhausted message then
      say s!"unavailable kernel replay: {firstLine message}"
    else
      say s!"fail kernel replay: {firstLine message}"
    return 1
  say s!"replayed {added.size}"
  let theoremName? := if theoremArg == "-" then none else some theoremArg.toName
  for (name, expected) in pinned do
    let some claimed := added.get? name
      | say s!"fail the claim does not declare {name}"
        return 1
    if some name == theoremName? then
      unless kindOf claimed == "theorem" do
        say s!"fail {name} is a {kindOf claimed}, not a theorem"
        return 1
      unless claimed.type == expected.type && claimed.levelParams == expected.levelParams do
        say s!"fail {name} does not have the statement's type"
        return 1
    else if !sameDeclaration expected claimed then
      say s!"fail {name} differs from the statement's declaration"
      return 1
    if kindOf expected == "axiom" then
      say s!"pinned {name}"
  for (name, info) in added do
    if kindOf info == "axiom" && !pinned.contains name then
      say s!"added-axiom {name}"
  if let some theoremName := theoremName? then
    unless pinned.contains theoremName do
      say s!"fail the statement does not declare {theoremName}"
      return 1
    for axiomName in axiomsOf env added theoremName do
      say s!"axiom {axiomName}"
  say "ok"
  return 0
