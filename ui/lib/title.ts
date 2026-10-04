/**
 * What to call an objective on a page a person reads.
 *
 * The record has no title field. `goal` is a slug -- `GOAL-ecc2k-130` -- that
 * reads as an identifier, because it is one, and rendering it as a page's
 * headline put a shouting prefix and a lowercase tail at the top of every
 * challenge. The statement's opening clause is what the funder wrote to say
 * what they want, and it is almost always the sentence a person would have
 * used as the title: "Find the private key for the ECC2K-130 challenge curve".
 *
 * Both are the funder's text and neither is checked. Taking the title from the
 * statement does not change that, which is why the challenge page still labels
 * the statement "written by the funder, not checked".
 *
 * Nothing here is consensus: the id, the goal and the statement are untouched,
 * and a title is only ever a display string.
 */

/** The longest headline before it is cut at a word and given an ellipsis. */
const MAX = 96;

/** Past this, a sentence loses its first parenthetical or colon clause: a
 *  title says what is wanted, and the aside is where it starts qualifying. */
const ASIDE = 56;

/** `GOAL-ecc2k-130` → `ecc2k-130`: the slug without the prefix every goal carries. */
export function goalSlug(goal: string | null | undefined): string {
  if (!goal) return "";
  return goal.replace(/^GOAL[-_:]/i, "");
}

/**
 * The statement's first sentence, trimmed to a headline.
 *
 * A sentence ends at `. ` / `? ` / `! ` or a newline -- not at every full
 * stop, because `F_3^4.` and `10^7).` are inside sentences here. A long
 * sentence is cut at its first parenthetical or colon, which is where the
 * statements in this repository start explaining themselves, and then at a
 * word boundary.
 */
export function headline(statement: string | null | undefined): string {
  const text = (statement ?? "").replace(/\s+/g, " ").trim();
  if (!text) return "";
  const end = text.search(/[.?!](\s|$)/);
  let first = end === -1 ? text : text.slice(0, end);
  if (first.length > ASIDE) {
    const aside = first.search(/\s\(|:\s|;\s|,\s(?:with|where|which|such)\s/);
    if (aside > 24) first = first.slice(0, aside);
  }
  if (first.length > MAX) {
    const cut = first.lastIndexOf(" ", MAX - 1);
    first = `${first.slice(0, cut > 40 ? cut : MAX - 1).replace(/[,;:\s]+$/, "")}…`;
  }
  return first;
}

/**
 * A title for an objective: the statement's headline, else the goal slug made
 * readable, else the short id.
 */
export function objectiveTitle(objective: {
  goal?: string | null;
  statement?: string | null;
  id: string;
}): string {
  const fromStatement = headline(objective.statement);
  if (fromStatement) return fromStatement;
  const slug = goalSlug(objective.goal);
  if (slug) return slug.replace(/[-_]+/g, " ");
  const bare = objective.id.replace(/^sha256:/, "");
  return bare.length <= 12 ? bare : `${bare.slice(0, 8)}…${bare.slice(-4)}`;
}
