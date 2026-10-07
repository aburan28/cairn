/**
 * From a sentence to a divided search's draft: the helper behind the
 * "Start a coordinated task" box on `/coordination`.
 *
 * Deliberately a parser, not a model. It reads a prompt for the four things
 * a piecework objective needs — a goal handle, a unit count, a per-unit
 * price, and a verifier kind — and produces the JSON block and the commands
 * to review. Everything it cannot find gets a marked placeholder, never a
 * guess presented as a reading: a draft that invents a verifier kind would
 * post work under rules nobody chose.
 */

export type CoordinatedDraft = {
  /** `GOAL-<key>[/<angle>]`, from an explicit handle or the first words. */
  goalHandle: string;
  /** Whether the handle came from the prompt's own words or a `GOAL-` token. */
  goalFrom: "explicit" | "words";
  /** Total units to divide, when the prompt named a count. */
  units: number | null;
  /** Price per novel unit, when the prompt named one. */
  unitPrice: number | null;
  /** The verifier kind the prompt's vocabulary points at. */
  verifierKind: string;
  /** `units × unitPrice`, when both are known. */
  pool: number | null;
};

const STOP = new Set([
  "a", "an", "the", "to", "for", "of", "on", "in", "and", "or", "with", "using",
  "that", "this", "we", "need", "want", "please", "search", "solve", "find", "all",
]);

/** `GOAL-foo/bar` spelled anywhere in the text, angle included. */
function explicitHandle(prompt: string): string | null {
  const match = prompt.match(/GOAL-[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*/);
  return match ? match[0] : null;
}

function slugWords(prompt: string): string {
  const words = prompt
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, " ")
    .split(/[\s-]+/)
    .filter((w) => w && !STOP.has(w) && w.length > 1);
  return words.slice(0, 4).join("-") || "divided-search";
}

/** `2M units`, `500k orbits`, `1,000,000 seeds` — the count beside a unit noun. */
function unitCount(prompt: string): number | null {
  const match = prompt.match(/([\d,]+(?:\.\d+)?)\s*([kKmM])?\s*(units?|orbits?|seeds?|tasks?|keys?|points?)\b/);
  if (!match) return null;
  const base = Number.parseFloat(match[1].replace(/,/g, ""));
  if (!Number.isFinite(base)) return null;
  const scale = match[2]?.toLowerCase() === "m" ? 1_000_000 : match[2]?.toLowerCase() === "k" ? 1_000 : 1;
  const total = Math.round(base * scale);
  return total > 0 ? total : null;
}

/** `10 per unit`, `5 each`, `price 25` — the price beside a price noun. */
function unitPrice(prompt: string): number | null {
  const match = prompt.match(/(\d[\d,]*)\s*(per[ -]?unit|each|per[ -]?orbit|per[ -]?seed)\b/i)
    ?? prompt.match(/(?:price|pay(?:ing|s)?|bounty)\s*(?:of\s*)?(\d[\d,]*)/i);
  if (!match) return null;
  const price = Number.parseInt((match[1] ?? match[2] ?? "").replace(/,/g, ""), 10);
  return Number.isFinite(price) && price > 0 ? price : null;
}

function verifierKind(prompt: string): string {
  const text = prompt.toLowerCase();
  if (/\blean\b|\bproof\b|\btheorem\b|\bproves?\b/.test(text)) return "lean";
  if (/\bwitness\b|\bcertificate\b|\bcounterexample\b|\bnp\b/.test(text)) return "certificate";
  if (/\bstatistic\b|\bp-value\b|\bhypothesis\b|\bsignificance\b/.test(text)) return "statistical";
  if (/\breplay\b|\bre-?run\b|\bdeterministic\b|\breproduc/.test(text)) return "replay";
  return "evaluator";
}

export function draftCoordinatedTask(prompt: string): CoordinatedDraft {
  const explicit = explicitHandle(prompt);
  const goalHandle = explicit ?? `GOAL-${slugWords(prompt)}`;
  const units = unitCount(prompt);
  const price = unitPrice(prompt);
  return {
    goalHandle,
    goalFrom: explicit ? "explicit" : "words",
    units,
    unitPrice: price,
    verifierKind: verifierKind(prompt),
    pool: units !== null && price !== null ? units * price : null,
  };
}

/** The `piecework` block as it goes into the objective JSON. Placeholders stay loud. */
export function pieceworkJson(draft: CoordinatedDraft): string {
  const units = draft.units === null ? '"<units>"' : draft.units.toLocaleString("en-US").replace(/,/g, "");
  const price = draft.unitPrice === null ? '"<unit-price>"' : String(draft.unitPrice);
  return (
    `"goal": "${draft.goalHandle}",\n` +
    `"verifier": { "kind": "${draft.verifierKind}" },\n` +
    `"piecework": { "units": ${units}, "unit_price": ${price} }`
  );
}

/** Scaffold the objective directory this draft describes. */
export function scaffoldCommand(draft: CoordinatedDraft): string {
  const name = draft.goalHandle.replace(/^GOAL-/i, "").split("/")[0].toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return `cairn scaffold ${name || "my-search"} --kind ${draft.verifierKind}`;
}
