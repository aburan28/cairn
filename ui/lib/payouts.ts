/** Read-only attribution for one objective, supplied by the node's log fold. */
export type PayoutPreview = {
  objective_id: string;
  ledger: { height: number; head: string };
  reward_units: string;
  settled_units: string;
  payees: { identity: string; units: string }[];
  attribution: {
    delta_num: number;
    delta_den: number;
    max_depth: number;
    reserved_num: number;
    reserved_den: number;
  };
  note: string;
};

export async function fetchPayoutPreview(base: string, objective: string): Promise<PayoutPreview> {
  const response = await fetch(`${base}/payouts/${encodeURIComponent(objective)}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`The node answered ${response.status} for payout attribution.`);
  const preview = (await response.json()) as PayoutPreview;
  if (!preview || preview.objective_id !== objective || !Array.isArray(preview.payees)
    || typeof preview.ledger?.head !== "string" || !Number.isSafeInteger(preview.ledger?.height)
    || preview.ledger.height < 0 || !preview.ledger.head) {
    throw new Error("The node returned attribution for a different objective or log head.");
  }
  parseUnits(preview.reward_units);
  parseUnits(preview.settled_units);
  if (preview.payees.some((payee) => !payee || typeof payee.identity !== "string" || !payee.identity)) {
    throw new Error("The node returned a payee without an identity.");
  }
  preview.payees.forEach((payee) => parseUnits(payee.units));
  quotePayouts(preview, "0");
  return preview;
}

/** An unsigned draft for an external wallet, tied to the observed log head. */
export function draftReceipt(
  preview: PayoutPreview,
  asset: string,
  amountText: string,
): string {
  const quote = quotePayouts(preview, amountText);
  return JSON.stringify({
    schema: "cairn.external-payout-preview.v1",
    status: "draft-unverified",
    objective_id: preview.objective_id,
    ledger: preview.ledger,
    asset,
    amount_base_units: amountText,
    funded_cairn_units: preview.reward_units,
    settled_cairn_units: preview.settled_units,
    attribution: preview.attribution,
    payees: quote.rows.map((row) => ({
      identity: row.identity,
      units: row.units.toString(),
      amount_base_units: row.amount.toString(),
      address: null,
    })),
    unallocated_base_units: quote.unallocated.toString(),
    note: "Preview only. Verify the log, payout addresses, terms, and per-settlement rounding before sending any funds.",
  }, null, 2);
}

/** An outside-asset illustration. Integer division always rounds down. */
export function quotePayouts(preview: PayoutPreview, amountText: string): {
  rows: { identity: string; units: bigint; amount: bigint }[];
  unallocated: bigint;
} {
  if (!/^[0-9]{1,32}$/.test(amountText)) throw new Error("Enter an integer amount in the asset's smallest units (up to 32 digits).");
  const amount = BigInt(amountText);
  const reward = parseUnits(preview.reward_units);
  const settled = parseUnits(preview.settled_units);
  if (reward === 0n || settled > reward) throw new Error("The objective's funded unit count is invalid.");
  const seen = new Set<string>();
  let attributed = 0n;
  const rows = preview.payees.map((payee) => {
    if (seen.has(payee.identity)) throw new Error("The node repeated a payee.");
    seen.add(payee.identity);
    const units = parseUnits(payee.units);
    attributed += units;
    return { identity: payee.identity, units, amount: (amount * units) / reward };
  });
  if (attributed !== settled) throw new Error("Attributed units do not equal settled units.");
  const paid = rows.reduce((sum, row) => sum + row.amount, 0n);
  return { rows, unallocated: amount - paid };
}

function parseUnits(text: string): bigint {
  if (typeof text !== "string" || !/^[0-9]+$/.test(text)) throw new Error("The node returned a non-integer unit count.");
  return BigInt(text);
}
