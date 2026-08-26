/**
 * The one runtime check every fetcher here makes on what a node answered.
 *
 * Each `lib/*.ts` file mirrors an endpoint's shape as a TypeScript type and
 * then `as`-casts the parsed JSON into it. A cast is a promise, not a check:
 * a field the server renames passes `tsc`, passes `next build`, and renders as
 * "—" in a cell. That is not hypothetical -- `units` in `site.ts` grew its
 * `undefined` tolerance because the page read `remaining` for a while and the
 * node calls it `pool_remaining`, and CI was green throughout.
 *
 * This is deliberately *not* a schema validator. It asserts that the fields a
 * page is about to read are present, and nothing about their types beyond
 * "not undefined": the point is to fail loudly at the seam rather than to
 * re-describe every endpoint a second time in a form that would drift from
 * the first.
 */

/** What a node answered does not have the fields this page reads. */
export class ShapeMismatch extends Error {}

/**
 * Throw unless `value` is an object carrying every one of `fields`.
 *
 * `what` names the endpoint in the message, because a reader seeing "missing
 * `height`" needs to know which of five requests said so.
 */
export function expectFields<T extends object>(
  value: unknown,
  fields: readonly string[],
  what: string,
): T {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ShapeMismatch(
      `${what} answered ${describe(value)}, not an object with ` +
        `${fields.map((f) => `\`${f}\``).join(", ")}.`,
    );
  }
  const missing = fields.filter((f) => (value as Record<string, unknown>)[f] === undefined);
  if (missing.length > 0) {
    throw new ShapeMismatch(
      `${what} answered without ${missing.map((f) => `\`${f}\``).join(", ")}. ` +
        `Either the node is older or newer than this page, or a field was renamed ` +
        `on one side and not the other.`,
    );
  }
  return value as T;
}

function describe(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  return `a ${typeof value}`;
}
